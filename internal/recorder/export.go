package recorder

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"orbitlink/internal/audit"
	"orbitlink/internal/store"
)

// ExportResult describes one read-only export of a sealed segment.
type ExportResult struct {
	SegmentID   string             `json:"segment_id"`
	Destination string             `json:"destination"`
	FramesFile  string             `json:"frames_file"`
	IndexFile   string             `json:"index_file"`
	Manifest    string             `json:"manifest"`
	Report      VerificationReport `json:"report"`
}

type exportManifest struct {
	Segment    Segment            `json:"segment"`
	Report     VerificationReport `json:"verification"`
	ExportedAt time.Time          `json:"exported_at"`
	ReadOnly   bool               `json:"read_only"`
}

// Export copies the recording and its integrity index into a read-only
// bundle. Export is refused unless the segment is in a terminal state and
// passes a fresh verification, so a damaged recording can never leave the
// station looking complete.
func (m *Manager) Export(segmentID, destination string) (ExportResult, error) {
	m.mu.RLock()
	current, found := m.sessions[segmentID]
	m.mu.RUnlock()
	if !found {
		return ExportResult{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	if current.segment.Status != Sealed && current.segment.Status != Aborted {
		return ExportResult{}, fmt.Errorf("recording segment %s must be sealed before export", segmentID)
	}
	report, err := m.Verify(segmentID)
	if err != nil {
		return ExportResult{}, err
	}
	if !report.OK {
		return ExportResult{}, fmt.Errorf("recording segment %s failed integrity verification; export refused", segmentID)
	}
	if destination == "" {
		destination = m.paths.ExportDir(segmentID)
	}
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return ExportResult{}, fmt.Errorf("create export directory: %w", err)
	}
	result := ExportResult{
		SegmentID: segmentID, Destination: destination,
		FramesFile: filepath.Join(destination, segmentID+".frames"),
		IndexFile:  filepath.Join(destination, segmentID+".index.jsonl"),
		Manifest:   filepath.Join(destination, segmentID+".manifest.json"),
		Report:     report,
	}
	if err := copyReadOnly(m.paths.Recording(segmentID), result.FramesFile); err != nil {
		return ExportResult{}, err
	}
	if err := copyReadOnly(m.paths.RecordingIndex(segmentID), result.IndexFile); err != nil {
		return ExportResult{}, err
	}
	manifest := exportManifest{
		Segment: current.segment, Report: report, ExportedAt: time.Now().UTC(), ReadOnly: true,
	}
	if err := store.WriteJSON(result.Manifest, manifest); err != nil {
		return ExportResult{}, err
	}
	if err := os.Chmod(result.Manifest, 0o444); err != nil {
		return ExportResult{}, fmt.Errorf("seal export manifest: %w", err)
	}
	_, _ = m.audit.Record(audit.Event{
		Component: "recorder", Action: "exported", Subject: segmentID,
		Fields: map[string]any{"destination": destination, "frames": report.Frames, "digest": report.Digest},
	})
	return result, nil
}

// copyReadOnly copies one file and drops every write permission on the
// destination. A missing source is exported as an empty file so a segment
// that legitimately recorded zero frames still produces a complete bundle.
func copyReadOnly(source, destination string) error {
	input, err := os.Open(source)
	if os.IsNotExist(err) {
		input = nil
	} else if err != nil {
		return fmt.Errorf("open export source: %w", err)
	}
	if input != nil {
		defer input.Close()
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create export file: %w", err)
	}
	if input != nil {
		if _, err := io.Copy(output, input); err != nil {
			_ = output.Close()
			return fmt.Errorf("copy export file: %w", err)
		}
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return fmt.Errorf("sync export file: %w", err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close export file: %w", err)
	}
	if err := os.Chmod(destination, 0o444); err != nil {
		return fmt.Errorf("make export read-only: %w", err)
	}
	return nil
}
