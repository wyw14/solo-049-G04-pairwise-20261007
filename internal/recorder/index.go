package recorder

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"orbitlink/internal/store"
)

// IndexEntry locates one durable frame inside the segment recording file.
type IndexEntry struct {
	Sequence uint64 `json:"sequence"`
	Epoch    int64  `json:"epoch"`
	CRC32    uint32 `json:"crc32"`
	Offset   int64  `json:"offset"`
	Length   int    `json:"length"`
}

// Gap is an inclusive range of frame sequences missing from the recording.
type Gap struct {
	From  uint64 `json:"from"`
	To    uint64 `json:"to"`
	Count uint64 `json:"count"`
}

// SealRecord binds the verified index to the sealed segment state. It is
// appended to the index only after verification passes, so any later
// tampering with either file is detected as a digest divergence.
type SealRecord struct {
	Frames   int       `json:"frames"`
	Bytes    int64     `json:"bytes"`
	Gaps     int       `json:"gaps"`
	Digest   string    `json:"digest"`
	SealedAt time.Time `json:"sealed_at"`
}

// SegmentIndex is the materialized integrity view of one segment.
type SegmentIndex struct {
	SegmentID string       `json:"segment_id"`
	Entries   []IndexEntry `json:"entries"`
	Gaps      []Gap        `json:"gaps"`
	Seal      *SealRecord  `json:"seal,omitempty"`
}

func (idx SegmentIndex) Frames() int { return len(idx.Entries) }

func (idx SegmentIndex) Bytes() int64 {
	total := int64(0)
	for _, entry := range idx.Entries {
		total += frameHeaderSize + int64(entry.Length)
	}
	return total
}

// indexDigest chains every entry into one hash so the seal record commits to
// the exact frame sequence, epochs, CRCs and file offsets.
func indexDigest(entries []IndexEntry) string {
	hasher := sha256.New()
	var block [36]byte
	for _, entry := range entries {
		binary.BigEndian.PutUint64(block[0:8], entry.Sequence)
		binary.BigEndian.PutUint64(block[8:16], uint64(entry.Epoch))
		binary.BigEndian.PutUint32(block[16:20], entry.CRC32)
		binary.BigEndian.PutUint64(block[20:28], uint64(entry.Offset))
		binary.BigEndian.PutUint64(block[28:36], uint64(entry.Length))
		_, _ = hasher.Write(block[:])
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// computeGaps locates missing frame sequences between consecutive entries.
func computeGaps(entries []IndexEntry) []Gap {
	gaps := []Gap{}
	for index := 1; index < len(entries); index++ {
		previous, current := entries[index-1].Sequence, entries[index].Sequence
		if current > previous+1 {
			gaps = append(gaps, Gap{From: previous + 1, To: current - 1, Count: current - previous - 1})
		}
	}
	return gaps
}

func entriesEqual(left, right []IndexEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type indexLine struct {
	Kind     string      `json:"kind"`
	Sequence uint64      `json:"sequence,omitempty"`
	Epoch    int64       `json:"epoch,omitempty"`
	CRC32    uint32      `json:"crc32,omitempty"`
	Offset   int64       `json:"offset,omitempty"`
	Length   int         `json:"length,omitempty"`
	Seal     *SealRecord `json:"seal,omitempty"`
}

// IndexLog persists per-frame index records as an append-only JSONL stream
// that is fsynced with every accepted entry, mirroring the recording writes.
type IndexLog struct {
	mu    sync.Mutex
	paths store.Paths
}

func NewIndexLog(paths store.Paths) *IndexLog {
	return &IndexLog{paths: paths}
}

func (l *IndexLog) Append(segmentID string, entry IndexEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendLineLocked(segmentID, indexLine{
		Kind: "entry", Sequence: entry.Sequence, Epoch: entry.Epoch,
		CRC32: entry.CRC32, Offset: entry.Offset, Length: entry.Length,
	})
}

// Seal appends the terminal seal record. A sealed index rejects further
// appends so the sealed state cannot be silently extended.
func (l *IndexLog) Seal(segmentID string, seal SealRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	index, err := readIndexFile(l.paths.RecordingIndex(segmentID), segmentID)
	if err != nil {
		return err
	}
	if index.Seal != nil {
		return fmt.Errorf("recording segment %s index is already sealed", segmentID)
	}
	return l.appendLineLocked(segmentID, indexLine{Kind: "seal", Seal: &seal})
}

func (l *IndexLog) appendLineLocked(segmentID string, line indexLine) error {
	path := l.paths.RecordingIndex(segmentID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create recording index directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open recording index: %w", err)
	}
	encoded, err := json.Marshal(line)
	if err == nil {
		_, err = file.Write(append(encoded, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("append recording index: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close recording index: %w", closeErr)
	}
	return nil
}

func (l *IndexLog) Read(segmentID string) (SegmentIndex, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return readIndexFile(l.paths.RecordingIndex(segmentID), segmentID)
}

func readIndexFile(path, segmentID string) (SegmentIndex, error) {
	index := SegmentIndex{SegmentID: segmentID, Entries: []IndexEntry{}, Gaps: []Gap{}}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return index, nil
	}
	if err != nil {
		return index, fmt.Errorf("open recording index: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var line indexLine
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			return index, fmt.Errorf("decode recording index: %w", err)
		}
		switch line.Kind {
		case "entry":
			index.Entries = append(index.Entries, IndexEntry{
				Sequence: line.Sequence, Epoch: line.Epoch, CRC32: line.CRC32,
				Offset: line.Offset, Length: line.Length,
			})
		case "seal":
			if line.Seal == nil {
				return index, fmt.Errorf("recording index seal record is empty")
			}
			seal := *line.Seal
			index.Seal = &seal
		default:
			return index, fmt.Errorf("recording index has unknown record kind %q", line.Kind)
		}
	}
	if err := scanner.Err(); err != nil {
		return index, fmt.Errorf("scan recording index: %w", err)
	}
	index.Gaps = computeGaps(index.Entries)
	return index, nil
}

// Rewrite atomically replaces the index with the scanned entries. Recovery
// uses it after a power loss; a torn seal record is dropped so the segment
// can be verified and sealed again.
func (l *IndexLog) Rewrite(segmentID string, entries []IndexEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	for _, entry := range entries {
		if err := encoder.Encode(indexLine{
			Kind: "entry", Sequence: entry.Sequence, Epoch: entry.Epoch,
			CRC32: entry.CRC32, Offset: entry.Offset, Length: entry.Length,
		}); err != nil {
			return fmt.Errorf("encode recording index: %w", err)
		}
	}
	path := l.paths.RecordingIndex(segmentID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create recording index directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary recording index: %w", err)
	}
	name := temporary.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(name)
		}
	}()
	if _, err := temporary.Write(buffer.Bytes()); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write recording index: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync recording index: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close recording index: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace recording index: %w", err)
	}
	keep = true
	return nil
}
