package recorder

import (
	"fmt"
	"time"

	"orbitlink/internal/audit"
)

func (m *Manager) Transfer(segmentID, from, to string, expectedGeneration int64) (Segment, error) {
	if from == "" || to == "" || from == to {
		return Segment{}, fmt.Errorf("distinct source and destination owners are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, found := m.sessions[segmentID]
	if !found {
		return Segment{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	if current.segment.OwnerStation != from || current.segment.OwnerGeneration != expectedGeneration {
		return Segment{}, fmt.Errorf("recording owner generation changed")
	}
	current.segment.OwnerStation = to
	current.segment.OwnerGeneration++
	if err := m.flushLocked(); err != nil {
		return Segment{}, err
	}
	_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "ownership.transferred", Subject: segmentID, Fields: map[string]any{"from": from, "to": to, "generation": current.segment.OwnerGeneration}})
	return current.segment, nil
}

func (m *Manager) CloseForOwner(segmentID, station string, expectedGeneration int64, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, found := m.sessions[segmentID]
	if !found {
		return fmt.Errorf("recording segment %s not found", segmentID)
	}
	if current.segment.OwnerStation != station || current.segment.OwnerGeneration != expectedGeneration {
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "stale-close.ignored", Subject: segmentID, Severity: audit.Warning, Fields: map[string]any{"station": station, "expected_generation": expectedGeneration, "current_generation": current.segment.OwnerGeneration}})
		return nil
	}
	if len(current.buffer) > 0 {
		return fmt.Errorf("owner close rejected while %d frames remain buffered", len(current.buffer))
	}
	verification, err := m.verifySegmentLocked(segmentID, false)
	if err != nil {
		return err
	}
	if !verification.Passed() {
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "index.seal_rejected", Subject: segmentID, Severity: audit.Warning, Fields: map[string]any{"station": station, "truncated": verification.Truncated, "corrupt": verification.Corrupt, "detail": verification.Detail}})
		return fmt.Errorf("owner close rejected: integrity verification failed: %s", verification.Detail)
	}
	current.segment.Status = Sealed
	current.segment.SealReason = reason
	index, err := m.indexLocked(segmentID)
	if err != nil {
		return err
	}
	index.Sealed = true
	index.Complete = true
	index.SealedAt = time.Now().UTC()
	if err := m.persistIndexLocked(index); err != nil {
		return err
	}
	return m.flushLocked()
}
