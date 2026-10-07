package recorder

import (
	"context"
	"fmt"
	"time"

	"orbitlink/internal/audit"
)

func (m *Manager) Drain(ctx context.Context, segmentID string) (int, error) {
	m.mu.Lock()
	current, found := m.sessions[segmentID]
	if !found {
		m.mu.Unlock()
		return 0, fmt.Errorf("recording segment %s not found", segmentID)
	}
	if current.segment.Status != Open && current.segment.Status != Draining {
		m.mu.Unlock()
		return 0, fmt.Errorf("recording segment %s cannot drain from %s", segmentID, current.segment.Status)
	}
	current.segment.Status = Draining
	frames := append([]Frame(nil), current.buffer...)
	m.mu.Unlock()

	written := 0
	entries := make([]IndexEntry, 0, len(frames))
	for _, frame := range frames {
		select {
		case <-ctx.Done():
			return written, fmt.Errorf("recorder drain canceled after %d frames: %w", written, ctx.Err())
		default:
		}
		appended, err := m.writer.Append(segmentID, frame)
		if err != nil {
			return written, err
		}
		entries = append(entries, IndexEntry{
			Sequence: frame.Sequence, Epoch: frame.Epoch, CRC32: appended.CRC32,
			Offset: appended.Offset, Length: appended.Length,
		})
		written++
	}

	m.mu.Lock()
	current = m.sessions[segmentID]
	current.buffer = current.buffer[written:]
	current.segment.FramesWritten += written
	current.segment.FramesBuffered = len(current.buffer)
	err := m.flushLocked()
	if err == nil && written > 0 {
		var index *SegmentIndex
		index, err = m.indexLocked(segmentID)
		if err == nil {
			index.replaceEntries(append(index.Entries, entries...))
			err = m.persistIndexLocked(index)
		}
	}
	m.mu.Unlock()
	if err == nil {
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "drained", Subject: segmentID, Fields: map[string]any{"frames": written}})
	}
	return written, err
}

// Seal closes a segment only after the on-disk recording passes integrity
// verification. The index is bound to the seal: a failed check means the
// segment stays unsealed and the index is never marked complete.
func (m *Manager) Seal(segmentID, reason string) (SealResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, found := m.sessions[segmentID]
	if !found {
		return SealResult{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	if len(current.buffer) != 0 {
		return SealResult{Segment: current.segment, Complete: false, Error: "frames remain buffered"}, fmt.Errorf("recording still has %d buffered frames", len(current.buffer))
	}
	verification, err := m.verifySegmentLocked(segmentID, false)
	if err != nil {
		return SealResult{}, err
	}
	if !verification.Passed() {
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "index.seal_rejected", Subject: segmentID, Severity: audit.Warning, Fields: map[string]any{"truncated": verification.Truncated, "corrupt": verification.Corrupt, "detail": verification.Detail}})
		return SealResult{Segment: current.segment, Complete: false, Error: "integrity verification failed: " + verification.Detail, Verification: &verification},
			fmt.Errorf("recording segment %s failed integrity verification: %s", segmentID, verification.Detail)
	}
	if verification.Frames != current.segment.FramesWritten {
		detail := fmt.Sprintf("frame count mismatch: %d written but %d verified on disk", current.segment.FramesWritten, verification.Frames)
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "index.seal_rejected", Subject: segmentID, Severity: audit.Warning, Fields: map[string]any{"detail": detail}})
		return SealResult{Segment: current.segment, Complete: false, Error: detail, Verification: &verification},
			fmt.Errorf("recording segment %s: %s", segmentID, detail)
	}
	current.segment.Status = Sealed
	current.segment.SealReason = reason
	current.segment.SealedAt = time.Now().UTC()
	index, err := m.indexLocked(segmentID)
	if err != nil {
		return SealResult{}, err
	}
	index.Sealed = true
	index.Complete = true
	index.SealedAt = current.segment.SealedAt
	if err := m.persistIndexLocked(index); err != nil {
		return SealResult{}, err
	}
	if err := m.flushLocked(); err != nil {
		return SealResult{}, err
	}
	_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "sealed", Subject: segmentID, Fields: map[string]any{"frames": current.segment.FramesWritten, "reason": reason, "complete": true, "gaps": len(index.Gaps)}})
	return SealResult{Segment: current.segment, Complete: true, Verification: &verification}, nil
}
