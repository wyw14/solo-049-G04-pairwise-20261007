package recorder

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"time"

	"orbitlink/internal/audit"
)

const (
	frameHeaderSize   = 28
	maxPayloadLength  = 1 << 20
	recoveryComponent = "recorder"
)

// CorruptFrame pinpoints one frame that failed verification.
type CorruptFrame struct {
	Offset   int64  `json:"offset"`
	Sequence uint64 `json:"sequence,omitempty"`
	Reason   string `json:"reason"`
}

// VerificationReport is the outcome of checking a segment recording against
// its integrity index. OK is false when frames are corrupt, the file has a
// torn tail, or the persisted index diverges from the recording.
type VerificationReport struct {
	SegmentID     string         `json:"segment_id"`
	CheckedAt     time.Time      `json:"checked_at"`
	Frames        int            `json:"frames"`
	Bytes         int64          `json:"bytes"`
	FirstSequence uint64         `json:"first_sequence,omitempty"`
	LastSequence  uint64         `json:"last_sequence,omitempty"`
	Gaps          []Gap          `json:"gaps"`
	Corrupt       []CorruptFrame `json:"corrupt"`
	TruncatedTail bool           `json:"truncated_tail"`
	TailBytes     int64          `json:"tail_bytes,omitempty"`
	IndexDiverged bool           `json:"index_diverged"`
	Digest        string         `json:"digest"`
	OK            bool           `json:"ok"`
}

// scanFrames parses the recording file without mutating it, returning the
// verified entries, every corrupt frame, and whether the file ends in a
// torn (partially written) record — the signature of a power loss.
func scanFrames(path string) (entries []IndexEntry, corrupt []CorruptFrame, truncated bool, tailBytes int64, err error) {
	entries = []IndexEntry{}
	corrupt = []CorruptFrame{}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return entries, corrupt, false, 0, nil
	}
	if err != nil {
		return nil, nil, false, 0, fmt.Errorf("open recording: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, false, 0, fmt.Errorf("stat recording: %w", err)
	}
	size := info.Size()
	offset := int64(0)
	header := make([]byte, frameHeaderSize)
	for {
		if _, readErr := io.ReadFull(file, header); readErr != nil {
			if readErr == io.EOF {
				break
			}
			if readErr == io.ErrUnexpectedEOF {
				return entries, corrupt, true, size - offset, nil
			}
			return nil, nil, false, 0, fmt.Errorf("read frame header: %w", readErr)
		}
		sequence := binary.BigEndian.Uint64(header[0:8])
		epoch := int64(binary.BigEndian.Uint64(header[8:16]))
		length := binary.BigEndian.Uint64(header[16:24])
		crc := binary.BigEndian.Uint32(header[24:28])
		if length > maxPayloadLength {
			corrupt = append(corrupt, CorruptFrame{Offset: offset, Sequence: sequence, Reason: "invalid frame length"})
			return entries, corrupt, true, size - offset, nil
		}
		payload := make([]byte, length)
		if _, readErr := io.ReadFull(file, payload); readErr != nil {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				return entries, corrupt, true, size - offset, nil
			}
			return nil, nil, false, 0, fmt.Errorf("read frame payload: %w", readErr)
		}
		next := offset + frameHeaderSize + int64(length)
		switch {
		case crc32.ChecksumIEEE(payload) != crc:
			corrupt = append(corrupt, CorruptFrame{Offset: offset, Sequence: sequence, Reason: "crc mismatch"})
		case len(entries) > 0 && sequence <= entries[len(entries)-1].Sequence:
			corrupt = append(corrupt, CorruptFrame{Offset: offset, Sequence: sequence, Reason: "sequence out of order"})
		default:
			entries = append(entries, IndexEntry{
				Sequence: sequence, Epoch: epoch, CRC32: crc, Offset: offset, Length: int(length),
			})
		}
		offset = next
	}
	return entries, corrupt, false, 0, nil
}

// Verify rescans the recording, recomputes every CRC, and compares the
// result against the persisted index and its seal record. It never mutates
// either file; recovery is the only mutating path.
func (m *Manager) Verify(segmentID string) (VerificationReport, error) {
	report := VerificationReport{
		SegmentID: segmentID, CheckedAt: time.Now().UTC(),
		Gaps: []Gap{}, Corrupt: []CorruptFrame{},
	}
	entries, corrupt, truncated, tailBytes, err := scanFrames(m.paths.Recording(segmentID))
	if err != nil {
		return report, err
	}
	report.Corrupt = corrupt
	report.TruncatedTail = truncated
	report.TailBytes = tailBytes
	report.Frames = len(entries)
	for _, entry := range entries {
		report.Bytes += frameHeaderSize + int64(entry.Length)
	}
	if len(entries) > 0 {
		report.FirstSequence = entries[0].Sequence
		report.LastSequence = entries[len(entries)-1].Sequence
	}
	report.Gaps = computeGaps(entries)
	report.Digest = indexDigest(entries)
	index, err := m.index.Read(segmentID)
	if err != nil {
		return report, err
	}
	report.IndexDiverged = !entriesEqual(index.Entries, entries)
	if index.Seal != nil {
		seal := index.Seal
		if seal.Digest != report.Digest || seal.Frames != report.Frames || seal.Bytes != report.Bytes {
			report.IndexDiverged = true
		}
	}
	report.OK = !report.TruncatedTail && len(report.Corrupt) == 0 && !report.IndexDiverged
	return report, nil
}

// Index returns the persisted integrity view of a segment, including the
// located gaps, for read-only inspection.
func (m *Manager) Index(segmentID string) (SegmentIndex, error) {
	m.mu.RLock()
	_, found := m.sessions[segmentID]
	m.mu.RUnlock()
	if !found {
		return SegmentIndex{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	return m.index.Read(segmentID)
}

// recoverSegments runs after a restart. Open and draining segments may carry
// a torn tail or an index that lags the recording (power loss between the
// frame fsync and the index fsync); both are repaired here. Sealed segments
// are re-verified and any loss of integrity is surfaced through the audit
// trail and the persisted segment summary.
func (m *Manager) recoverSegments() error {
	for id, current := range m.sessions {
		switch current.segment.Status {
		case Sealed, Aborted:
			report, err := m.Verify(id)
			if err != nil {
				return fmt.Errorf("verify sealed segment %s: %w", id, err)
			}
			if !report.OK {
				current.segment.Integrity = IntegritySummary{
					Verified: false, CheckedAt: report.CheckedAt, Frames: report.Frames, Gaps: len(report.Gaps),
				}
				if err := m.flushLocked(); err != nil {
					return err
				}
				_, _ = m.audit.Record(audit.Event{
					Component: recoveryComponent, Action: "integrity.lost", Subject: id, Severity: audit.Critical,
					Fields: map[string]any{"corrupt": len(report.Corrupt), "truncated_tail": report.TruncatedTail, "index_diverged": report.IndexDiverged},
				})
			}
		default:
			entries, corrupt, truncated, tailBytes, err := scanFrames(m.paths.Recording(id))
			if err != nil {
				return fmt.Errorf("recover segment %s: %w", id, err)
			}
			if truncated {
				good := int64(0)
				for _, entry := range entries {
					if end := entry.Offset + frameHeaderSize + int64(entry.Length); end > good {
						good = end
					}
				}
				if err := os.Truncate(m.paths.Recording(id), good); err != nil {
					return fmt.Errorf("truncate torn tail of segment %s: %w", id, err)
				}
			}
			if err := m.index.Rewrite(id, entries); err != nil {
				return fmt.Errorf("rebuild index of segment %s: %w", id, err)
			}
			_, _ = m.audit.Record(audit.Event{
				Component: recoveryComponent, Action: "recovered", Subject: id,
				Fields: map[string]any{
					"frames": len(entries), "corrupt": len(corrupt),
					"truncated_tail": truncated, "tail_bytes": tailBytes,
				},
			})
		}
	}
	return nil
}
