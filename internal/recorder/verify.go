package recorder

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"time"

	"orbitlink/internal/audit"
)

// maxFramePayload bounds a plausible frame so a corrupt length field cannot
// send recovery into an unbounded allocation.
const maxFramePayload = 16 << 20

type scanResult struct {
	entries   []IndexEntry
	bytes     int64
	truncated bool
	corrupt   bool
	detail    string
}

// scanFramesFile parses the recording record by record. The scan never
// modifies the file; a torn tail or corruption is reported, not repaired here.
func scanFramesFile(path string) (scanResult, error) {
	result := scanResult{entries: make([]IndexEntry, 0, 256)}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, fmt.Errorf("open recording for verification: %w", err)
	}
	defer file.Close()
	header := make([]byte, frameHeaderSize)
	for {
		offset := result.bytes
		if _, err := io.ReadFull(file, header); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				result.truncated = true
				result.detail = fmt.Sprintf("partial frame header at offset %d", offset)
				break
			}
			return result, fmt.Errorf("read frame header at offset %d: %w", offset, err)
		}
		sequence := binary.BigEndian.Uint64(header[0:8])
		epoch := int64(binary.BigEndian.Uint64(header[8:16]))
		length := binary.BigEndian.Uint64(header[16:24])
		checksum := binary.BigEndian.Uint32(header[24:28])
		if length > maxFramePayload {
			result.corrupt = true
			result.detail = fmt.Sprintf("implausible payload length %d at offset %d", length, offset)
			break
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(file, payload); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				result.truncated = true
				result.detail = fmt.Sprintf("partial payload for frame %d at offset %d", sequence, offset)
				break
			}
			return result, fmt.Errorf("read payload at offset %d: %w", offset, err)
		}
		if crc32.ChecksumIEEE(payload) != checksum {
			result.corrupt = true
			result.detail = fmt.Sprintf("crc mismatch for frame %d at offset %d", sequence, offset)
			break
		}
		result.entries = append(result.entries, IndexEntry{
			Sequence: sequence, Epoch: epoch, CRC32: checksum,
			Offset: offset, Length: int64(frameHeaderSize) + int64(length),
		})
		result.bytes += int64(frameHeaderSize) + int64(length)
	}
	return result, nil
}

// verifySegmentLocked scans the recording file, reconciles the durable index
// with what is actually on disk, and enforces the seal binding: an index is
// only complete while the segment is sealed and the last scan passed. When
// repair is set and the segment is not sealed, a torn tail left by a power
// loss is truncated so future appends stay aligned.
func (m *Manager) verifySegmentLocked(segmentID string, repair bool) (Verification, error) {
	current, found := m.sessions[segmentID]
	if !found {
		return Verification{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	index, err := m.indexLocked(segmentID)
	if err != nil {
		return Verification{}, err
	}
	path := m.paths.Recording(segmentID)
	m.writer.mu.Lock()
	scan, err := scanFramesFile(path)
	m.writer.mu.Unlock()
	if err != nil {
		return Verification{}, err
	}
	verification := Verification{
		CheckedAt: time.Now().UTC(), Frames: len(scan.entries), Bytes: scan.bytes,
		Truncated: scan.truncated, Corrupt: scan.corrupt, Detail: scan.detail,
	}
	if repair && scan.truncated && current.segment.Status != Sealed {
		if err := os.Truncate(path, scan.bytes); err != nil {
			return verification, fmt.Errorf("repair torn tail of recording %s: %w", segmentID, err)
		}
		verification.Detail += " (torn tail truncated during recovery)"
	}
	index.replaceEntries(scan.entries)
	index.LastVerify = &verification
	index.Complete = index.Sealed && verification.Passed()
	if err := m.persistIndexLocked(index); err != nil {
		return verification, err
	}
	return verification, nil
}

// VerifyIndex rescans the recording file and reconciles the index. It is the
// on-demand form of the power-loss recovery check and never modifies the
// recording itself.
func (m *Manager) VerifyIndex(segmentID string) (Verification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	verification, err := m.verifySegmentLocked(segmentID, false)
	if err != nil {
		return Verification{}, err
	}
	severity := audit.Info
	action := "index.verified"
	if !verification.Passed() {
		severity = audit.Warning
		action = "index.verify_failed"
	}
	_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: action, Subject: segmentID, Severity: severity, Fields: map[string]any{"frames": verification.Frames, "bytes": verification.Bytes, "truncated": verification.Truncated, "corrupt": verification.Corrupt, "detail": verification.Detail}})
	return verification, nil
}

// recoverIndexesLocked reconciles every known segment with its recording file
// after a restart: frames that reached disk before a power loss are indexed,
// torn tails on unsealed segments are truncated, and the frame counter is
// realigned with what the file actually holds.
func (m *Manager) recoverIndexesLocked() error {
	for segmentID, current := range m.sessions {
		verification, err := m.verifySegmentLocked(segmentID, true)
		if err != nil {
			return err
		}
		drift := current.segment.FramesWritten != verification.Frames
		if drift {
			current.segment.FramesWritten = verification.Frames
			current.segment.FramesBuffered = 0
		}
		if verification.Frames == 0 && verification.Passed() && !drift {
			continue
		}
		severity := audit.Info
		if !verification.Passed() {
			severity = audit.Warning
		}
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "index.recovered", Subject: segmentID, Severity: severity, Fields: map[string]any{"frames": verification.Frames, "truncated": verification.Truncated, "corrupt": verification.Corrupt, "counter_drift": drift, "detail": verification.Detail}})
	}
	return m.flushLocked()
}
