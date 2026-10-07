package store

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Paths keeps every durable document below one station state directory.
type Paths struct {
	Root string
}

func NewPaths(root string) Paths {
	return Paths{Root: filepath.Clean(root)}
}

func (p Paths) Events(stream string) string {
	return filepath.Join(p.Root, "events", safeName(stream)+".jsonl")
}

func (p Paths) Snapshot(component string) string {
	return filepath.Join(p.Root, "snapshots", safeName(component)+".json")
}

func (p Paths) Recording(id string) string {
	return filepath.Join(p.Root, "recordings", safeName(id)+".frames")
}

func (p Paths) RecordingIndex(id string) string {
	return filepath.Join(p.Root, "recordings", safeName(id)+".index.jsonl")
}

func (p Paths) ExportDir(id string) string {
	return filepath.Join(p.Root, "exports", safeName(id))
}

func (p Paths) Validate() error {
	if p.Root == "." || strings.TrimSpace(p.Root) == "" {
		return fmt.Errorf("state root is required")
	}
	return nil
}

func safeName(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "..", "-")
	value = strings.NewReplacer("/", "-", "\\", "-", ":", "-").Replace(value)
	if value == "" {
		return "default"
	}
	return value
}
