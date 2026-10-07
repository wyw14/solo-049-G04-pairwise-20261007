package recorder

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"
	"time"

	"orbitlink/internal/audit"
	"orbitlink/internal/store"
)

// IndexExport is an immutable, self-checksummed snapshot of a segment index
// for off-station archival or review.
type IndexExport struct {
	SegmentID  string        `json:"segment_id"`
	ExportedAt time.Time     `json:"exported_at"`
	Status     SegmentStatus `json:"status"`
	Sealed     bool          `json:"sealed"`
	Complete   bool          `json:"complete"`
	Frames     int           `json:"frames"`
	Bytes      int64         `json:"bytes"`
	Gaps       []Gap         `json:"gaps,omitempty"`
	Entries    []IndexEntry  `json:"entries"`
	LastVerify *Verification `json:"last_verify,omitempty"`
	Checksum   uint32        `json:"checksum"`
}

// ComputeChecksum computes the CRC32 of the export with the checksum field zeroed.
func (e IndexExport) ComputeChecksum() uint32 {
	e.Checksum = 0
	encoded, err := json.Marshal(e)
	if err != nil {
		return 0
	}
	return crc32.ChecksumIEEE(encoded)
}

// ExportIndex writes the segment index to a read-only file next to the
// recording and returns its path. The live index is not modified.
func (m *Manager) ExportIndex(segmentID string) (string, error) {
	m.mu.RLock()
	current, found := m.sessions[segmentID]
	if !found {
		m.mu.RUnlock()
		return "", fmt.Errorf("recording segment %s not found", segmentID)
	}
	index, found := m.indexes[segmentID]
	if !found {
		index = newSegmentIndex(segmentID)
	}
	snapshot := index.snapshot()
	export := IndexExport{
		SegmentID: segmentID, ExportedAt: time.Now().UTC(), Status: current.segment.Status,
		Sealed: snapshot.Sealed, Complete: snapshot.Complete, Frames: snapshot.FramesIndexed,
		Bytes: snapshot.BytesIndexed, Gaps: snapshot.Gaps, Entries: snapshot.Entries, LastVerify: snapshot.LastVerify,
	}
	m.mu.RUnlock()
	export.Checksum = export.ComputeChecksum()
	path := m.paths.RecordingExport(segmentID)
	if err := store.WriteJSON(path, export); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0o444); err != nil {
		return "", fmt.Errorf("make export read-only: %w", err)
	}
	_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "index.exported", Subject: segmentID, Fields: map[string]any{"path": path, "checksum": export.Checksum, "complete": export.Complete}})
	return path, nil
}
