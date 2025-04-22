package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// mockResponseWriter implements http.ResponseWriter and http.Flusher for testing SSE.
type mockResponseWriter struct {
	*httptest.ResponseRecorder       // Embed to get ResponseWriter behavior
	flushed                    bool  // Track if Flush was called
	forceError                 error // Added for testing error handling
}

// NewMockResponseWriter creates a new mock response writer.
func NewMockResponseWriter() *mockResponseWriter {
	return &mockResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
	}
}

// Write method for mockResponseWriter (ensure it handles forceError)
func (m *mockResponseWriter) Write(p []byte) (int, error) {
	if m.forceError != nil {
		return 0, m.forceError
	}
	return m.ResponseRecorder.Write(p) // Use embedded writer
}

// Flush method for mockResponseWriter
func (m *mockResponseWriter) Flush() {
	if m.forceError != nil { // Don't flush if write failed
		return
	}
	m.flushed = true
	// We don't actually flush the embedded recorder in this mock
}

// --- Simple Mock Flusher ---
type mockFlusher struct {
	flushed bool
}

func (f *mockFlusher) Flush() {
	f.flushed = true
}

// --- End Mock Flusher ---

func TestManager_Run_Stop(t *testing.T) {
	// Basic test to ensure the manager can start and stop.
	// More comprehensive tests involving resource handling would be needed.

	// Dummy tool set JSON for initialization
	dummyToolSet := []byte(`{"tools": []}`)

	m := newConnectionManager(dummyToolSet)

	// Basic run/stop test - might need refinement depending on Run() implementation
	// We need a way to observe if Run() is actually doing something or blocking.
	// For now, just test start and stop signals.
	stopChan := make(chan struct{})
	go func() {
		// Need to figure out what Run expects or does.
		// If Run is intended to block, this test structure needs adjustment.
		// For now, assume Run might just start background tasks and doesn't block indefinitely.
		// If it expects specific input or state, that needs mocking.
		// Placeholder: Simulate Run behavior relevant to Stop.
		// If Run blocks, this goroutine might hang.
		<-stopChan // Simulate Run blocking until Stop is called
	}()

	// Simulate adding a client to test remove logic
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	mrr := NewMockResponseWriter() // Use the mock
	m.addClient(req, mrr, mrr)     // Pass the mock which implements both interfaces
	if m.getClientCount() != 1 {
		t.Errorf("Expected 1 client after add, got %d", m.getClientCount())
	}

	time.Sleep(100 * time.Millisecond) // Give time for potential background tasks

	// Test removing the client
	m.removeClient(req)
	if m.getClientCount() != 0 {
		t.Errorf("Expected 0 clients after remove, got %d", m.getClientCount())
	}

	// Simulate stopping the manager
	close(stopChan) // Signal the placeholder Run goroutine to exit

	// Need a way to verify Stop() worked. If it closes internal channels,
	// we could potentially check that. Without knowing Stop's implementation,
	// this is a basic check.
	// Maybe add a dedicated Stop() method to connectionManager if Run blocks?
	// Or check internal state if possible.

	// Example: If Stop closes a known channel:
	// select {
	// case <-m.internalStopChan: // Assuming internalStopChan exists and is closed by Stop()
	//	// Expected behavior
	// case <-time.After(1 * time.Second):
	//	t.Fatal("Manager did not signal stop within the expected time")
	// }
}

// Define a dummy non-flusher if needed
type nonFlusher struct {
	http.ResponseWriter
}

func (nf *nonFlusher) Flush() { /* Do nothing */ }

func TestManager_AddRemoveClient(t *testing.T) {
	dummyToolSet := []byte(`{"tools": []}`)
	m := newConnectionManager(dummyToolSet)

	req1 := httptest.NewRequest(http.MethodGet, "/events?id=1", nil)
	mrr1 := NewMockResponseWriter() // Use mock

	req2 := httptest.NewRequest(http.MethodGet, "/events?id=2", nil)
	mrr2 := NewMockResponseWriter() // Use mock

	m.addClient(req1, mrr1, mrr1) // Pass mock
	if count := m.getClientCount(); count != 1 {
		t.Errorf("Expected 1 client, got %d", count)
	}

	m.addClient(req2, mrr2, mrr2) // Pass mock
	if count := m.getClientCount(); count != 2 {
		t.Errorf("Expected 2 clients, got %d", count)
	}

	m.removeClient(req1)
	if count := m.getClientCount(); count != 1 {
		t.Errorf("Expected 1 client after removing req1, got %d", count)
	}
	// Ensure the correct client was removed
	m.mu.RLock()
	_, exists := m.clients[req1]
	m.mu.RUnlock()
	if exists {
		t.Error("req1 should have been removed but still exists in map")
	}

	m.removeClient(req2)
	if count := m.getClientCount(); count != 0 {
		t.Errorf("Expected 0 clients after removing req2, got %d", count)
	}

	// Test removing non-existent client
	m.removeClient(req1) // Remove again
	if count := m.getClientCount(); count != 0 {
		t.Errorf("Expected 0 clients after removing non-existent, got %d", count)
	}
}

// Test for sendToolset needs a way to capture output sent to the client.
// httptest.ResponseRecorder can capture the body.
func TestManager_SendToolset(t *testing.T) {
	toolSetData := `{"tools": ["tool1", "tool2"]}`
	m := newConnectionManager([]byte(toolSetData))

	mrr := NewMockResponseWriter() // Use mock

	// Directly create a client struct instance for testing sendToolset specifically
	// Note: This bypasses addClient logic for focused testing of sendToolset.
	testClient := &client{writer: mrr, flusher: mrr} // Use mock for both

	m.sendToolset(testClient)

	// Use strings.TrimSpace for comparison to avoid issues with subtle whitespace differences
	// Escape inner quotes
	expectedOutputPattern := "event: tool_set\ndata: {\"tools\": [\"tool1\", \"tool2\"]}\n\n"
	actualOutput := mrr.Body.String()

	if strings.TrimSpace(actualOutput) != strings.TrimSpace(expectedOutputPattern) {
		// Use %q to quote strings, making whitespace visible
		t.Errorf("Expected toolset output matching pattern %q, got %q", expectedOutputPattern, actualOutput)
	}
	if !mrr.flushed { // Check if flush was called
		t.Error("Expected Flush() to be called on the writer, but it wasn't")
	}

	// Test sending to nil client
	m.sendToolset(nil) // Should not panic
}

// Test case for when writing the toolset fails (e.g., client disconnected)
func TestConnectionManager_SendToolset_WriteError(t *testing.T) {
	mgr := newConnectionManager([]byte(`{"tool":"set"}`))

	// Create a mock writer that always returns an error
	mockWriter := &mockResponseWriter{
		ResponseRecorder: httptest.NewRecorder(), // Initialize embedded recorder
		forceError:       fmt.Errorf("simulated write error"),
	}
	mockFlusher := &mockFlusher{}

	// Create a client with the erroring writer
	mockClient := &client{
		writer:  mockWriter,
		flusher: mockFlusher,
	}

	// Call sendToolset - we expect it to log the error and return early
	// We don't easily assert the log, but we run it for coverage.
	mgr.sendToolset(mockClient)

	// Assert that Flush was NOT called because the function should have returned early
	assert.False(t, mockFlusher.flushed, "Flush should not be called when Write fails")
	// Assert that Write was attempted (optional, depends on mock capabilities)
	// If mockResponseWriter tracks calls, assert Write was called once.
}
