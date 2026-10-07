package recorder

import (
	"context"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"orbitlink/internal/audit"
	"orbitlink/internal/store"
)

func testPayload(sequence uint64, size int) []byte {
	payload := make([]byte, size)
	binary.BigEndian.PutUint64(payload, sequence)
	for index := 8; index < len(payload); index++ {
		payload[index] = byte((int(sequence) + index) % 251)
	}
	return payload
}

func newTestManager(t *testing.T, root string) *Manager {
	t.Helper()
	paths := store.NewPaths(root)
	manager, err := NewManager(paths, audit.NewTrail(store.NewAppendLog(paths)))
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func startSegment(t *testing.T, manager *Manager) Segment {
	t.Helper()
	segment, err := manager.Start("pass-1", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	return segment
}

func bufferAndDrain(t *testing.T, manager *Manager, segmentID string, sequences ...uint64) {
	t.Helper()
	for _, sequence := range sequences {
		payload := testPayload(sequence, 64)
		frame := Frame{Sequence: sequence, Epoch: 7, Payload: payload, CRC32: crc32.ChecksumIEEE(payload)}
		if err := manager.Buffer(segmentID, frame); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := manager.Drain(context.Background(), segmentID); err != nil {
		t.Fatal(err)
	}
}

func corruptPayloadByte(t *testing.T, root, segmentID string, offset int64) {
	t.Helper()
	path := store.NewPaths(root).Recording(segmentID)
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xFF}, offset); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestIndexRecordsFrameOffsetsAndChecksums(t *testing.T) {
	root := t.TempDir()
	manager := newTestManager(t, root)
	segment := startSegment(t, manager)
	bufferAndDrain(t, manager, segment.ID, 1, 2, 3)

	index, err := manager.Index(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Entries) != 3 {
		t.Fatalf("expected 3 index entries, got %d", len(index.Entries))
	}
	record := int64(frameHeaderSize + 64)
	for i, entry := range index.Entries {
		if entry.Sequence != uint64(i+1) || entry.Epoch != 7 {
			t.Fatalf("entry %d has sequence %d epoch %d", i, entry.Sequence, entry.Epoch)
		}
		if entry.Offset != int64(i)*record || entry.Length != 64 {
			t.Fatalf("entry %d has offset %d length %d", i, entry.Offset, entry.Length)
		}
		if entry.CRC32 != crc32.ChecksumIEEE(testPayload(entry.Sequence, 64)) {
			t.Fatalf("entry %d CRC does not match payload", i)
		}
	}
	if len(index.Gaps) != 0 {
		t.Fatalf("unexpected gaps: %#v", index.Gaps)
	}
}

func TestVerifyLocatesMissingFrames(t *testing.T) {
	root := t.TempDir()
	manager := newTestManager(t, root)
	segment := startSegment(t, manager)
	bufferAndDrain(t, manager, segment.ID, 1, 2, 5, 6, 10)

	report, err := manager.Verify(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK {
		t.Fatalf("gaps alone must not fail verification: %#v", report)
	}
	if len(report.Gaps) != 2 {
		t.Fatalf("expected 2 gaps, got %#v", report.Gaps)
	}
	if report.Gaps[0] != (Gap{From: 3, To: 4, Count: 2}) {
		t.Fatalf("first gap mislocated: %#v", report.Gaps[0])
	}
	if report.Gaps[1] != (Gap{From: 7, To: 9, Count: 3}) {
		t.Fatalf("second gap mislocated: %#v", report.Gaps[1])
	}
	if report.FirstSequence != 1 || report.LastSequence != 10 || report.Frames != 5 {
		t.Fatalf("bad sequence summary: %#v", report)
	}
}

func TestVerifyDetectsCorruption(t *testing.T) {
	root := t.TempDir()
	manager := newTestManager(t, root)
	segment := startSegment(t, manager)
	bufferAndDrain(t, manager, segment.ID, 1, 2, 3)
	// Flip one payload byte inside the second frame.
	secondFramePayload := int64(frameHeaderSize+64) + frameHeaderSize
	corruptPayloadByte(t, root, segment.ID, secondFramePayload+10)

	report, err := manager.Verify(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if report.OK {
		t.Fatal("corrupted frame passed verification")
	}
	if len(report.Corrupt) != 1 || report.Corrupt[0].Sequence != 2 {
		t.Fatalf("corrupt frame not located: %#v", report.Corrupt)
	}
}

func TestSealRejectedWhenVerificationFails(t *testing.T) {
	root := t.TempDir()
	manager := newTestManager(t, root)
	segment := startSegment(t, manager)
	bufferAndDrain(t, manager, segment.ID, 1, 2)
	corruptPayloadByte(t, root, segment.ID, frameHeaderSize+5)

	result, err := manager.Seal(segment.ID, "test seal")
	if err == nil {
		t.Fatal("seal unexpectedly succeeded on a corrupt recording")
	}
	if result.Complete {
		t.Fatal("corrupt segment was marked complete")
	}
	if result.Verification == nil || result.Verification.OK {
		t.Fatalf("seal result is missing the failed verification: %#v", result.Verification)
	}
	for _, listed := range manager.List() {
		if listed.ID == segment.ID {
			if listed.Status == Sealed {
				t.Fatal("segment reached sealed state despite failed verification")
			}
			if listed.Integrity.Verified {
				t.Fatal("segment marked verified despite failed verification")
			}
		}
	}
}

func TestSealBindsIndexToSealedState(t *testing.T) {
	root := t.TempDir()
	manager := newTestManager(t, root)
	segment := startSegment(t, manager)
	bufferAndDrain(t, manager, segment.ID, 1, 2, 3)

	result, err := manager.Seal(segment.ID, "test seal")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete {
		t.Fatalf("clean segment was not marked complete: %#v", result)
	}
	if !result.Segment.Integrity.Verified || result.Segment.Integrity.Frames != 3 {
		t.Fatalf("integrity summary not bound to segment: %#v", result.Segment.Integrity)
	}
	index, err := manager.Index(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if index.Seal == nil || index.Seal.Digest != result.Segment.Integrity.Digest {
		t.Fatalf("index seal record missing or digest mismatch: %#v", index.Seal)
	}

	// Tampering with the recording after the seal must be detected.
	corruptPayloadByte(t, root, segment.ID, frameHeaderSize+3)
	report, err := manager.Verify(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if report.OK {
		t.Fatal("post-seal tampering passed verification")
	}
}

func TestRecoveryRepairsPowerLossDamage(t *testing.T) {
	root := t.TempDir()
	manager := newTestManager(t, root)
	segment := startSegment(t, manager)
	bufferAndDrain(t, manager, segment.ID, 1, 2, 3)

	paths := store.NewPaths(root)
	// Simulate a power loss: a half-written frame at the tail of the
	// recording, and an index missing its last entry.
	framePath := paths.Recording(segment.ID)
	file, err := os.OpenFile(framePath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0x01, 0x02, 0x03}); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	indexPath := paths.RecordingIndex(segment.ID)
	data, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 index lines, got %d", len(lines))
	}
	if err := os.WriteFile(indexPath, []byte(strings.Join(lines[:2], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Restart: recovery must truncate the torn tail and rebuild the index.
	recovering := newTestManager(t, root)
	report, err := recovering.Verify(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK {
		t.Fatalf("recovered segment failed verification: %#v", report)
	}
	if report.Frames != 3 {
		t.Fatalf("expected 3 frames after recovery, got %d", report.Frames)
	}
	info, err := os.Stat(framePath)
	if err != nil {
		t.Fatal(err)
	}
	if want := 3 * int64(frameHeaderSize+64); info.Size() != want {
		t.Fatalf("torn tail not truncated: size %d, want %d", info.Size(), want)
	}
	index, err := recovering.Index(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Entries) != 3 {
		t.Fatalf("index not rebuilt: %d entries", len(index.Entries))
	}
	if _, err := recovering.Seal(segment.ID, "sealed after recovery"); err != nil {
		t.Fatalf("segment recovered from power loss could not be sealed: %v", err)
	}
}

func TestExportProducesVerifiedReadOnlyBundle(t *testing.T) {
	root := t.TempDir()
	manager := newTestManager(t, root)
	segment := startSegment(t, manager)
	bufferAndDrain(t, manager, segment.ID, 1, 2)
	if _, err := manager.Seal(segment.ID, "test seal"); err != nil {
		t.Fatal(err)
	}

	result, err := manager.Export(segment.ID, filepath.Join(t.TempDir(), "export"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{result.FramesFile, result.IndexFile, result.Manifest} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("exported file missing: %v", err)
		}
		if info.Mode().Perm() != 0o444 {
			t.Fatalf("exported file %s is not read-only: %v", path, info.Mode().Perm())
		}
	}
	exported, err := os.ReadFile(result.FramesFile)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(store.NewPaths(root).Recording(segment.ID))
	if err != nil {
		t.Fatal(err)
	}
	if string(exported) != string(original) {
		t.Fatal("exported recording differs from the original")
	}
	if !result.Report.OK || result.Report.Frames != 2 {
		t.Fatalf("export did not carry a passing verification: %#v", result.Report)
	}
}

func TestExportRefusedForUnsealedOrCorruptSegment(t *testing.T) {
	root := t.TempDir()
	manager := newTestManager(t, root)
	segment := startSegment(t, manager)
	bufferAndDrain(t, manager, segment.ID, 1, 2)

	if _, err := manager.Export(segment.ID, filepath.Join(t.TempDir(), "open")); err == nil {
		t.Fatal("export of an unsealed segment unexpectedly succeeded")
	}

	corruptPayloadByte(t, root, segment.ID, frameHeaderSize+20)
	if _, err := manager.Seal(segment.ID, "doomed"); err == nil {
		t.Fatal("seal of a corrupt segment unexpectedly succeeded")
	}
	if _, err := manager.Export(segment.ID, filepath.Join(t.TempDir(), "corrupt")); err == nil {
		t.Fatal("export of a corrupt segment unexpectedly succeeded")
	}
}

func TestVerifyRejectsSealedIndexExtension(t *testing.T) {
	root := t.TempDir()
	manager := newTestManager(t, root)
	segment := startSegment(t, manager)
	bufferAndDrain(t, manager, segment.ID, 1, 2)
	if _, err := manager.Seal(segment.ID, "test seal"); err != nil {
		t.Fatal(err)
	}

	// Appending a frame behind the sealed index must diverge the digest.
	payload := testPayload(3, 64)
	if err := manager.writer.Append(segment.ID, Frame{Sequence: 3, Epoch: 7, Payload: payload, CRC32: crc32.ChecksumIEEE(payload)}); err != nil {
		t.Fatal(err)
	}
	report, err := manager.Verify(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if report.OK || !report.IndexDiverged {
		t.Fatalf("extension behind a sealed index was not detected: %#v", report)
	}
}

func TestRecoveryReportsSealedSegmentTampering(t *testing.T) {
	root := t.TempDir()
	manager := newTestManager(t, root)
	segment := startSegment(t, manager)
	bufferAndDrain(t, manager, segment.ID, 1, 2)
	if _, err := manager.Seal(segment.ID, "test seal"); err != nil {
		t.Fatal(err)
	}

	corruptPayloadByte(t, root, segment.ID, frameHeaderSize+8)
	recovering := newTestManager(t, root)
	for _, listed := range recovering.List() {
		if listed.ID == segment.ID && listed.Integrity.Verified {
			t.Fatal("tampered sealed segment survived recovery as verified")
		}
	}
	report, err := recovering.Verify(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if report.OK {
		t.Fatal("tampered sealed segment passed verification after restart")
	}
}
