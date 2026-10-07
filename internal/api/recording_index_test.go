package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"orbitlink/internal/recorder"
)

func TestRecordingIndexEndpoints(t *testing.T) {
	runtime := newTestRuntime(t)
	router, err := NewRouter(runtime)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(router)
	defer server.Close()

	segment, err := runtime.Recorder.Start("pass-index-api", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Recorder.Buffer(segment.ID, recorder.Frame{Sequence: 1, Epoch: 5, Payload: []byte("frame-one-payload")}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Recorder.Buffer(segment.ID, recorder.Frame{Sequence: 3, Epoch: 5, Payload: []byte("frame-three-payload")}); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Recorder.Drain(context.Background(), segment.ID); err != nil {
		t.Fatal(err)
	}

	response, err := server.Client().Get(server.URL + "/api/recordings/" + segment.ID + "/index")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("index endpoint returned %d", response.StatusCode)
	}
	var index recorder.SegmentIndex
	decodeBody(t, response, &index)
	if index.FramesIndexed != 2 || len(index.Gaps) != 1 || index.Gaps[0].From != 2 {
		t.Fatalf("index endpoint should expose entries and gaps: %#v", index)
	}

	response = requestJSON(t, server.Client(), http.MethodPost, server.URL+"/api/recordings/"+segment.ID+"/index/verify", "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("verify endpoint returned %d", response.StatusCode)
	}
	var verification struct {
		Passed       bool                  `json:"passed"`
		Verification recorder.Verification `json:"verification"`
	}
	decodeBody(t, response, &verification)
	if !verification.Passed || verification.Verification.Frames != 2 {
		t.Fatalf("verification should pass over 2 frames: %#v", verification)
	}

	response = requestJSON(t, server.Client(), http.MethodPost, server.URL+"/api/recordings/"+segment.ID+"/index/export", "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("export endpoint returned %d", response.StatusCode)
	}
	var exported struct {
		Exported bool   `json:"exported"`
		Path     string `json:"path"`
	}
	decodeBody(t, response, &exported)
	if !exported.Exported || exported.Path == "" {
		t.Fatalf("export endpoint should return a path: %#v", exported)
	}

	response, err = server.Client().Get(server.URL + "/api/recordings/does-not-exist/index")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unknown segment should be rejected, got %d", response.StatusCode)
	}
	_ = response.Body.Close()
}

func TestSealFlowBindsIndexCompleteness(t *testing.T) {
	runtime := newTestRuntime(t)
	segment, err := runtime.Recorder.Start("pass-seal-binding", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Recorder.Buffer(segment.ID, recorder.Frame{Sequence: 1, Epoch: 1, Payload: []byte("bound-frame")}); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Recorder.Drain(context.Background(), segment.ID); err != nil {
		t.Fatal(err)
	}
	result, err := runtime.Recorder.Seal(segment.ID, "binding test")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete {
		t.Fatal("verified seal should be complete")
	}
	index, err := runtime.Recorder.Index(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !index.Complete || !index.Sealed {
		t.Fatalf("index completeness must be bound to the seal: %#v", index)
	}
	encoded, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 {
		t.Fatal("index should serialize")
	}
}
