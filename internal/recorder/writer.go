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

// frameHeaderSize is the on-disk record prefix: sequence, epoch, payload
// length and payload CRC32, all big-endian.
const frameHeaderSize = 28

// AppendResult locates the record that was just durably written.
type AppendResult struct {
	Offset int64
	Length int64
	CRC32  uint32
}

type FrameWriter struct {
	mu    sync.Mutex
	paths store.Paths
}

func NewFrameWriter(paths store.Paths) *FrameWriter {
	return &FrameWriter{paths: paths}
}

func (w *FrameWriter) Append(segmentID string, frame Frame) (AppendResult, error) {
	if segmentID == "" || len(frame.Payload) == 0 {
		return AppendResult{}, fmt.Errorf("segment and frame payload are required")
	}
	if frame.CRC32 == 0 {
		frame.CRC32 = crc32.ChecksumIEEE(frame.Payload)
	}
	if crc32.ChecksumIEEE(frame.Payload) != frame.CRC32 {
		return AppendResult{}, fmt.Errorf("frame %d checksum mismatch", frame.Sequence)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	path := w.paths.Recording(segmentID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return AppendResult{}, fmt.Errorf("create recording directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return AppendResult{}, fmt.Errorf("open recording: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return AppendResult{}, fmt.Errorf("stat recording: %w", err)
	}
	result := AppendResult{Offset: info.Size(), Length: int64(frameHeaderSize) + int64(len(frame.Payload)), CRC32: frame.CRC32}
	writer := bufio.NewWriter(file)
	header := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint64(header[0:8], frame.Sequence)
	binary.BigEndian.PutUint64(header[8:16], uint64(frame.Epoch))
	binary.BigEndian.PutUint64(header[16:24], uint64(len(frame.Payload)))
	binary.BigEndian.PutUint32(header[24:28], frame.CRC32)
	if _, err := writer.Write(header); err != nil {
		return AppendResult{}, fmt.Errorf("write frame header: %w", err)
	}
	if _, err := writer.Write(frame.Payload); err != nil {
		return AppendResult{}, fmt.Errorf("write frame payload: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return AppendResult{}, fmt.Errorf("flush frame: %w", err)
	}
	if err := file.Sync(); err != nil {
		return AppendResult{}, err
	}
	return result, nil
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
