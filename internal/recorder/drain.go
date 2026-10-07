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
	for _, frame := range frames {
		select {
		case <-ctx.Done():
			return written, fmt.Errorf("recorder drain canceled after %d frames: %w", written, ctx.Err())
		default:
		}
		if err := m.writer.Append(segmentID, frame); err != nil {
			return written, err
		}
		written++
	}

	m.mu.Lock()
	current = m.sessions[segmentID]
	current.buffer = current.buffer[written:]
	current.segment.FramesWritten += written
	current.segment.FramesBuffered = len(current.buffer)
	err := m.flushLocked()
	m.mu.Unlock()
	if err == nil {
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "drained", Subject: segmentID, Fields: map[string]any{"frames": written}})
	}
	return written, err
}

// Seal binds the integrity index to the sealed state: the recording is
// rescanned and verified first, and only a passing verification lets the
// segment be marked complete. A failed verification leaves the segment
// unsealed so the damage cannot be papered over.
func (m *Manager) Seal(segmentID, reason string) (SealResult, error) {
	report, err := m.Verify(segmentID)
	if err != nil {
		return SealResult{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, found := m.sessions[segmentID]
	if !found {
		return SealResult{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	if len(current.buffer) != 0 {
		return SealResult{Segment: current.segment, Complete: false, Error: "frames remain buffered"}, fmt.Errorf("recording still has %d buffered frames", len(current.buffer))
	}
	if !report.OK {
		_, _ = m.audit.Record(audit.Event{
			Component: "recorder", Action: "seal.rejected", Subject: segmentID, Severity: audit.Critical,
			Fields: map[string]any{"corrupt": len(report.Corrupt), "truncated_tail": report.TruncatedTail, "index_diverged": report.IndexDiverged},
		})
		return SealResult{Segment: current.segment, Complete: false, Error: "integrity verification failed", Verification: &report},
			fmt.Errorf("recording segment %s failed integrity verification", segmentID)
	}
	if current.segment.Status == Sealed {
		// Already in the terminal state; a repeated seal after a verified
		// rescan is idempotent so retries stay safe.
		return SealResult{Segment: current.segment, Complete: true, Verification: &report}, nil
	}
	if report.Frames != current.segment.FramesWritten {
		return SealResult{Segment: current.segment, Complete: false, Error: "recording changed during seal", Verification: &report},
			fmt.Errorf("recording segment %s changed during seal, retry", segmentID)
	}
	sealedAt := time.Now().UTC()
	seal := SealRecord{
		Frames: report.Frames, Bytes: report.Bytes, Gaps: len(report.Gaps),
		Digest: report.Digest, SealedAt: sealedAt,
	}
	if err := m.index.Seal(segmentID, seal); err != nil {
		return SealResult{}, err
	}
	current.segment.Status = Sealed
	current.segment.SealReason = reason
	current.segment.SealedAt = sealedAt
	current.segment.Integrity = IntegritySummary{
		Verified: true, CheckedAt: report.CheckedAt,
		Frames: report.Frames, Gaps: len(report.Gaps), Digest: report.Digest,
	}
	if err := m.flushLocked(); err != nil {
		return SealResult{}, err
	}
	_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "sealed", Subject: segmentID, Fields: map[string]any{"frames": current.segment.FramesWritten, "reason": reason, "gaps": len(report.Gaps), "digest": report.Digest}})
	return SealResult{Segment: current.segment, Complete: true, Verification: &report}, nil
}
