package recorder

import (
	"fmt"
	"sort"
	"time"

	"orbitlink/internal/store"
)

// IndexEntry pins one frame to its exact position inside the recording file.
type IndexEntry struct {
	Sequence uint64 `json:"sequence"`
	Epoch    int64  `json:"epoch"`
	CRC32    uint32 `json:"crc32"`
	Offset   int64  `json:"offset"`
	Length   int64  `json:"length"`
}

// Gap is an inclusive range of frame sequences that never reached the file.
type Gap struct {
	From  uint64 `json:"from"`
	To    uint64 `json:"to"`
	Count uint64 `json:"count"`
}

// Verification is the outcome of scanning the recording file against the index.
type Verification struct {
	CheckedAt time.Time `json:"checked_at"`
	Frames    int       `json:"frames"`
	Bytes     int64     `json:"bytes"`
	Truncated bool      `json:"truncated,omitempty"`
	Corrupt   bool      `json:"corrupt,omitempty"`
	Detail    string    `json:"detail,omitempty"`
}

func (v Verification) Passed() bool {
	return !v.Truncated && !v.Corrupt
}

// SegmentIndex is the durable integrity record for one recording segment.
// Complete is only ever true while the segment is sealed and the last
// verification passed; any failed check clears it again.
type SegmentIndex struct {
	SegmentID     string        `json:"segment_id"`
	Entries       []IndexEntry  `json:"entries"`
	Gaps          []Gap         `json:"gaps,omitempty"`
	FramesIndexed int           `json:"frames_indexed"`
	BytesIndexed  int64         `json:"bytes_indexed"`
	NextOffset    int64         `json:"next_offset"`
	Sealed        bool          `json:"sealed"`
	Complete      bool          `json:"complete"`
	SealedAt      time.Time     `json:"sealed_at,omitempty"`
	LastVerify    *Verification `json:"last_verify,omitempty"`
	UpdatedAt     time.Time     `json:"updated_at"`
}

func newSegmentIndex(segmentID string) *SegmentIndex {
	return &SegmentIndex{SegmentID: segmentID, Entries: make([]IndexEntry, 0, 256), UpdatedAt: time.Now().UTC()}
}

// computeGaps locates missing frame sequences so operators can pinpoint loss.
func computeGaps(entries []IndexEntry) []Gap {
	if len(entries) < 2 {
		return nil
	}
	ordered := make([]IndexEntry, len(entries))
	copy(ordered, entries)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Sequence < ordered[j].Sequence })
	var gaps []Gap
	previous := ordered[0].Sequence
	for _, entry := range ordered[1:] {
		if entry.Sequence > previous+1 {
			gaps = append(gaps, Gap{From: previous + 1, To: entry.Sequence - 1, Count: entry.Sequence - previous - 1})
		}
		if entry.Sequence > previous {
			previous = entry.Sequence
		}
	}
	return gaps
}

// replaceEntries rebuilds the derived fields of the index from scanned entries.
func (index *SegmentIndex) replaceEntries(entries []IndexEntry) {
	index.Entries = entries
	index.FramesIndexed = len(entries)
	index.Gaps = computeGaps(entries)
	index.BytesIndexed = 0
	for _, entry := range entries {
		if end := entry.Offset + entry.Length; end > index.BytesIndexed {
			index.BytesIndexed = end
		}
	}
	index.NextOffset = index.BytesIndexed
	index.UpdatedAt = time.Now().UTC()
}

// indexLocked resolves the in-memory index, loading it from disk once.
// Callers must hold m.mu for writing; the map is mutated here.
func (m *Manager) indexLocked(segmentID string) (*SegmentIndex, error) {
	if index, found := m.indexes[segmentID]; found {
		return index, nil
	}
	var index SegmentIndex
	found, err := store.ReadJSON(m.paths.RecordingIndex(segmentID), &index)
	if err != nil {
		return nil, err
	}
	if !found {
		index = *newSegmentIndex(segmentID)
	}
	m.indexes[segmentID] = &index
	return &index, nil
}

func (m *Manager) persistIndexLocked(index *SegmentIndex) error {
	index.UpdatedAt = time.Now().UTC()
	return store.WriteJSON(m.paths.RecordingIndex(index.SegmentID), index)
}

// snapshot deep-copies the index so callers cannot observe later mutation.
func (index *SegmentIndex) snapshot() SegmentIndex {
	copy := *index
	copy.Entries = append([]IndexEntry(nil), index.Entries...)
	copy.Gaps = append([]Gap(nil), index.Gaps...)
	if index.LastVerify != nil {
		verification := *index.LastVerify
		copy.LastVerify = &verification
	}
	return copy
}

// Index returns a copy of the integrity index for a recording segment.
func (m *Manager) Index(segmentID string) (SegmentIndex, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, found := m.sessions[segmentID]; !found {
		return SegmentIndex{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	index, found := m.indexes[segmentID]
	if !found {
		return *newSegmentIndex(segmentID), nil
	}
	return index.snapshot(), nil
}
