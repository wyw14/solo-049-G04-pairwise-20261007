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
	m.mu.RLock()
	current, found := m.sessions[segmentID]
	m.mu.RUnlock()
	if !found {
		return fmt.Errorf("recording segment %s not found", segmentID)
	}
	if current.segment.OwnerStation != station || current.segment.OwnerGeneration != expectedGeneration {
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "stale-close.ignored", Subject: segmentID, Severity: audit.Warning, Fields: map[string]any{"station": station, "expected_generation": expectedGeneration, "current_generation": current.segment.OwnerGeneration}})
		return nil
	}
	report, err := m.Verify(segmentID)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current = m.sessions[segmentID]
	if current.segment.OwnerStation != station || current.segment.OwnerGeneration != expectedGeneration {
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "stale-close.ignored", Subject: segmentID, Severity: audit.Warning, Fields: map[string]any{"station": station, "expected_generation": expectedGeneration, "current_generation": current.segment.OwnerGeneration}})
		return nil
	}
	if len(current.buffer) > 0 {
		return fmt.Errorf("owner close rejected while %d frames remain buffered", len(current.buffer))
	}
	if current.segment.Status == Sealed {
		// Already in the terminal state; owner close stays idempotent.
		return nil
	}
	if !report.OK {
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "seal.rejected", Subject: segmentID, Severity: audit.Critical, Fields: map[string]any{"corrupt": len(report.Corrupt), "truncated_tail": report.TruncatedTail, "index_diverged": report.IndexDiverged}})
		return fmt.Errorf("recording segment %s failed integrity verification", segmentID)
	}
	sealedAt := time.Now().UTC()
	seal := SealRecord{Frames: report.Frames, Bytes: report.Bytes, Gaps: len(report.Gaps), Digest: report.Digest, SealedAt: sealedAt}
	if err := m.index.Seal(segmentID, seal); err != nil {
		return err
	}
	current.segment.Status = Sealed
	current.segment.SealReason = reason
	current.segment.SealedAt = sealedAt
	current.segment.Integrity = IntegritySummary{Verified: true, CheckedAt: report.CheckedAt, Frames: report.Frames, Gaps: len(report.Gaps), Digest: report.Digest}
	return m.flushLocked()
}
