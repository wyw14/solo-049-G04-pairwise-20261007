package recorder

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sync"

	"orbitlink/internal/store"
)

type FrameWriter struct {
	mu    sync.Mutex
	paths store.Paths
	index *IndexLog
}

func NewFrameWriter(paths store.Paths, index *IndexLog) *FrameWriter {
	return &FrameWriter{paths: paths, index: index}
}

// Append writes one frame and its index entry. The frame is fsynced before
// the index entry, so after a power loss the index may lag the recording by
// one entry — recovery rebuilds that tail from the recording itself.
func (w *FrameWriter) Append(segmentID string, frame Frame) error {
	if segmentID == "" || len(frame.Payload) == 0 {
		return fmt.Errorf("segment and frame payload are required")
	}
	if frame.CRC32 == 0 {
		frame.CRC32 = crc32.ChecksumIEEE(frame.Payload)
	}
	if crc32.ChecksumIEEE(frame.Payload) != frame.CRC32 {
		return fmt.Errorf("frame %d checksum mismatch", frame.Sequence)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	path := w.paths.Recording(segmentID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create recording directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open recording: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat recording: %w", err)
	}
	offset := info.Size()
	writer := bufio.NewWriter(file)
	header := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint64(header[0:8], frame.Sequence)
	binary.BigEndian.PutUint64(header[8:16], uint64(frame.Epoch))
	binary.BigEndian.PutUint64(header[16:24], uint64(len(frame.Payload)))
	binary.BigEndian.PutUint32(header[24:28], frame.CRC32)
	if _, err := writer.Write(header); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if _, err := writer.Write(frame.Payload); err != nil {
		return fmt.Errorf("write frame payload: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush frame: %w", err)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return w.index.Append(segmentID, IndexEntry{
		Sequence: frame.Sequence, Epoch: frame.Epoch, CRC32: frame.CRC32,
		Offset: offset, Length: len(frame.Payload),
	})
}

func (w *FrameWriter) Size(segmentID string) (int64, error) {
	info, err := os.Stat(w.paths.Recording(segmentID))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
