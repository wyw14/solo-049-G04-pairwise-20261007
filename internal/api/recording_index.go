package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (r *Runtime) getRecordingIndex(writer http.ResponseWriter, request *http.Request) {
	index, err := r.Recorder.Index(chi.URLParam(request, "segmentID"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, index)
}

func (r *Runtime) verifyRecordingIndex(writer http.ResponseWriter, request *http.Request) {
	verification, err := r.Recorder.VerifyIndex(chi.URLParam(request, "segmentID"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"passed": verification.Passed(), "verification": verification})
}

func (r *Runtime) exportRecordingIndex(writer http.ResponseWriter, request *http.Request) {
	path, err := r.Recorder.ExportIndex(chi.URLParam(request, "segmentID"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"exported": true, "path": path, "read_only": true})
}
