package recorder

import (
	"context"
	"encoding/json"
	"hash/crc32"
	"os"
	"testing"

	"orbitlink/internal/audit"
	"orbitlink/internal/store"
)

func newTestManager(t *testing.T) (*Manager, store.Paths) {
	t.Helper()
	paths := store.NewPaths(t.TempDir())
	trail := audit.NewTrail(store.NewAppendLog(paths))
	manager, err := NewManager(paths, trail)
	if err != nil {
		t.Fatal(err)
	}
	return manager, paths
}

func bufferFrame(t *testing.T, manager *Manager, segmentID string, sequence uint64, epoch int64) {
	t.Helper()
	payload := make([]byte, 64)
	for index := range payload {
		payload[index] = byte(sequence + uint64(index))
	}
	if err := manager.Buffer(segmentID, Frame{Sequence: sequence, Epoch: epoch, Payload: payload}); err != nil {
		t.Fatal(err)
	}
}

func TestDrainIndexesFramesWithOffsetsAndGaps(t *testing.T) {
	manager, _ := newTestManager(t)
	segment, err := manager.Start("pass-1", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	bufferFrame(t, manager, segment.ID, 1, 10)
	bufferFrame(t, manager, segment.ID, 2, 10)
	bufferFrame(t, manager, segment.ID, 4, 11)
	if _, err := manager.Drain(context.Background(), segment.ID); err != nil {
		t.Fatal(err)
	}
	index, err := manager.Index(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if index.FramesIndexed != 3 {
		t.Fatalf("expected 3 indexed frames, got %d", index.FramesIndexed)
	}
	record := int64(frameHeaderSize) + 64
	for position, entry := range index.Entries {
		expected := int64(position) * record
		if entry.Offset != expected {
			t.Fatalf("entry %d offset = %d, expected %d", position, entry.Offset, expected)
		}
		if entry.Length != record {
			t.Fatalf("entry %d length = %d, expected %d", position, entry.Length, record)
		}
		if entry.CRC32 == 0 {
			t.Fatalf("entry %d is missing its checksum", position)
		}
	}
	if index.Entries[0].Epoch != 10 || index.Entries[2].Epoch != 11 {
		t.Fatalf("epochs were not indexed: %#v", index.Entries)
	}
	if index.NextOffset != 3*record || index.BytesIndexed != 3*record {
		t.Fatalf("next offset %d and bytes %d should both be %d", index.NextOffset, index.BytesIndexed, 3*record)
	}
	if len(index.Gaps) != 1 || index.Gaps[0] != (Gap{From: 3, To: 3, Count: 1}) {
		t.Fatalf("expected missing frame 3 to be located, got %#v", index.Gaps)
	}
	if index.Complete {
		t.Fatal("an unsealed segment must never be complete")
	}
}

func TestSealMarksCompleteOnlyAfterVerificationPasses(t *testing.T) {
	manager, _ := newTestManager(t)
	segment, err := manager.Start("pass-1", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	bufferFrame(t, manager, segment.ID, 1, 10)
	bufferFrame(t, manager, segment.ID, 2, 10)
	if _, err := manager.Drain(context.Background(), segment.ID); err != nil {
		t.Fatal(err)
	}
	result, err := manager.Seal(segment.ID, "test complete")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.Verification == nil || !result.Verification.Passed() {
		t.Fatalf("seal should report a passed verification: %#v", result)
	}
	index, err := manager.Index(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !index.Sealed || !index.Complete || index.SealedAt.IsZero() {
		t.Fatalf("sealed index should be bound complete: %#v", index)
	}
}

func TestSealRejectedWhenRecordingIsCorrupt(t *testing.T) {
	manager, paths := newTestManager(t)
	segment, err := manager.Start("pass-1", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	bufferFrame(t, manager, segment.ID, 1, 10)
	if _, err := manager.Drain(context.Background(), segment.ID); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(paths.Recording(segment.ID), os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xFF}, int64(frameHeaderSize)+3); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	result, err := manager.Seal(segment.ID, "should fail")
	if err == nil {
		t.Fatal("seal unexpectedly succeeded on a corrupt recording")
	}
	if result.Complete {
		t.Fatal("a failed verification must not be marked complete")
	}
	current, _ := manager.Index(segment.ID)
	if current.Sealed || current.Complete || current.LastVerify == nil || !current.LastVerify.Corrupt {
		t.Fatalf("corrupt seal attempt should leave the index unsealed and incomplete: %#v", current)
	}
	segments := manager.List()
	if segments[0].Status == Sealed {
		t.Fatal("segment must stay unsealed when verification fails")
	}
}

func TestPowerLossRecoveryTruncatesTornFrame(t *testing.T) {
	manager, paths := newTestManager(t)
	segment, err := manager.Start("pass-1", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	bufferFrame(t, manager, segment.ID, 1, 10)
	bufferFrame(t, manager, segment.ID, 2, 10)
	if _, err := manager.Drain(context.Background(), segment.ID); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(paths.Recording(segment.ID), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(make([]byte, 11)); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()

	restarted, err := NewManager(paths, manager.audit)
	if err != nil {
		t.Fatal(err)
	}
	index, err := restarted.Index(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if index.FramesIndexed != 2 {
		t.Fatalf("recovery should index the 2 durable frames, got %d", index.FramesIndexed)
	}
	info, err := os.Stat(paths.Recording(segment.ID))
	if err != nil {
		t.Fatal(err)
	}
	if want := 2 * (int64(frameHeaderSize) + 64); info.Size() != want {
		t.Fatalf("torn tail should be truncated to %d bytes, file is %d", want, info.Size())
	}
	verification, err := restarted.VerifyIndex(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Passed() {
		t.Fatalf("post-recovery verification should pass: %#v", verification)
	}
}

func TestPowerLossRecoveryRebuildsMissingIndex(t *testing.T) {
	manager, paths := newTestManager(t)
	segment, err := manager.Start("pass-1", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(1); sequence <= 3; sequence++ {
		bufferFrame(t, manager, segment.ID, sequence, 20)
	}
	if _, err := manager.Drain(context.Background(), segment.ID); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths.RecordingIndex(segment.ID)); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(paths, manager.audit)
	if err != nil {
		t.Fatal(err)
	}
	index, err := restarted.Index(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	record := int64(frameHeaderSize) + 64
	if index.FramesIndexed != 3 || index.NextOffset != 3*record {
		t.Fatalf("index should be rebuilt from disk: %#v", index)
	}
	for position, entry := range index.Entries {
		if entry.Offset != int64(position)*record || entry.Sequence != uint64(position)+1 {
			t.Fatalf("rebuilt entry %d is wrong: %#v", position, entry)
		}
	}
}

func TestRecoveryClearsCompletenessWhenSealedRecordingIsCorrupt(t *testing.T) {
	manager, paths := newTestManager(t)
	segment, err := manager.Start("pass-1", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	bufferFrame(t, manager, segment.ID, 1, 10)
	if _, err := manager.Drain(context.Background(), segment.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Seal(segment.ID, "done"); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(paths.Recording(segment.ID), os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xAA}, int64(frameHeaderSize)+9); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	restarted, err := NewManager(paths, manager.audit)
	if err != nil {
		t.Fatal(err)
	}
	index, err := restarted.Index(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if index.Complete {
		t.Fatal("corruption found after power loss must clear completeness")
	}
	if index.LastVerify == nil || !index.LastVerify.Corrupt {
		t.Fatalf("recovery should record the corruption: %#v", index.LastVerify)
	}
}

func TestExportIsReadOnlyAndChecksummed(t *testing.T) {
	manager, _ := newTestManager(t)
	segment, err := manager.Start("pass-1", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	bufferFrame(t, manager, segment.ID, 1, 10)
	bufferFrame(t, manager, segment.ID, 3, 10)
	if _, err := manager.Drain(context.Background(), segment.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Seal(segment.ID, "done"); err != nil {
		t.Fatal(err)
	}
	path, err := manager.ExportIndex(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("export must be read-only, mode is %v", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var export IndexExport
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatal(err)
	}
	if export.Checksum != export.ComputeChecksum() {
		t.Fatal("export checksum does not validate")
	}
	if !export.Complete || !export.Sealed || export.Frames != 2 {
		t.Fatalf("export should mirror the sealed index: %#v", export)
	}
	if len(export.Gaps) != 1 || export.Gaps[0].From != 2 {
		t.Fatalf("export should carry the missing-frame locations: %#v", export.Gaps)
	}
	if len(export.Entries) != 2 || export.Entries[1].Offset != int64(frameHeaderSize)+64 {
		t.Fatalf("export entries should carry offsets: %#v", export.Entries)
	}
}

func TestIndexChecksumMatchesWriterChecksum(t *testing.T) {
	manager, _ := newTestManager(t)
	segment, err := manager.Start("pass-1", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("telemetry-frame-payload")
	if err := manager.Buffer(segment.ID, Frame{Sequence: 1, Epoch: 3, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Drain(context.Background(), segment.ID); err != nil {
		t.Fatal(err)
	}
	index, err := manager.Index(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := crc32.ChecksumIEEE(payload); index.Entries[0].CRC32 != want {
		t.Fatalf("indexed crc %d does not match payload crc %d", index.Entries[0].CRC32, want)
	}
}
