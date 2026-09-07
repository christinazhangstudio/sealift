package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func configureTestAI(t *testing.T, endpoint string) {
	t.Helper()
	settings := []struct {
		target *string
		value  string
	}{
		{&selfHostedEmbeddingURL, endpoint},
		{&selfHostedEmbeddingModel, "test-embeddings"},
		{&useSelfHostedAI, "true"},
		{&selfHostedAIChatCompletionsURL, endpoint},
		{&selfHostedAIChatCompletionsModel, "test-chat"},
		{&openAIAPIKey, ""},
	}
	for _, setting := range settings {
		original := *setting.target
		*setting.target = setting.value
		t.Cleanup(func() { *setting.target = original })
	}
}

func TestAIRequestsCancelUpstream(t *testing.T) {
	for _, operation := range []string{"embedding", "completion", "inbox rules", "stream"} {
		t.Run(operation, func(t *testing.T) {
			started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				close(started)
				select {
				case <-r.Context().Done():
					close(canceled)
				case <-release:
				}
			}))
			defer upstream.Close()
			defer close(release)
			configureTestAI(t, upstream.URL)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			response := httptest.NewRecorder()
			result := make(chan error, 1)
			go func() {
				var err error
				switch operation {
				case "embedding":
					_, err = getEmbedding(ctx, "question")
				case "completion":
					_, _, err = getCompletion(ctx, "question", "", true)
				case "inbox rules":
					_, _, err = getPromptCompletion(ctx, "classify", false, 1200)
				case "stream":
					err = streamCompletion(ctx, response, response, "question", "", true, nil)
				}
				result <- err
			}()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("AI request did not start")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("error = %v, want context.Canceled", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("AI request kept running after cancellation")
			}
			select {
			case <-canceled:
			case <-time.After(2 * time.Second):
				t.Fatal("provider connection was not canceled")
			}
			if strings.Contains(response.Body.String(), `"done":true`) {
				t.Fatal("canceled stream reported success")
			}
		})
	}
}

func TestStreamCompletionDoesNotCompleteBrokenResponses(t *testing.T) {
	for _, failure := range []string{"short body", "oversized event"} {
		t.Run(failure, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if failure == "short body" {
					w.Header().Set("Content-Length", "1000")
					fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"partial answer\"}}]}\n\n")
				} else {
					fmt.Fprint(w, "data: "+strings.Repeat("x", 1024*1024)+"\n\n")
				}
			}))
			defer upstream.Close()
			configureTestAI(t, upstream.URL)
			response := httptest.NewRecorder()
			err := streamCompletion(context.Background(), response, response, "question", "", true, nil)
			if err == nil {
				t.Fatal("broken upstream response was accepted")
			}
			if strings.Contains(response.Body.String(), `"done":true`) {
				t.Fatalf("broken stream reported success: %s", response.Body.String())
			}
		})
	}
}

func TestStreamCompletionStopsAtDoneWithoutWaitingForEOF(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"answer\"}}]}\n\ndata: [DONE]\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer upstream.Close()
	defer close(release)
	configureTestAI(t, upstream.URL)
	response := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := streamCompletion(ctx, response, response, "question", "", true,
		[]KnowledgeChunk{{Source: "help.md"}}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"token":"answer"`, `"done":true`, `"source":"help.md"`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Errorf("stream does not contain %s: %s", want, response.Body.String())
		}
	}
}

type failedAIStreamWriter struct {
	*httptest.ResponseRecorder
	err error
}

func (w failedAIStreamWriter) Write([]byte) (int, error) { return 0, w.err }

func TestStreamCompletionStopsOnBrowserWriteFailure(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"answer\"}}]}\n\n")
	}))
	defer upstream.Close()
	configureTestAI(t, upstream.URL)
	want := errors.New("browser connection closed")
	response := failedAIStreamWriter{httptest.NewRecorder(), want}
	if err := streamCompletion(context.Background(), response, response, "question", "", true, nil); !errors.Is(err, want) {
		t.Fatalf("error = %v, want browser write failure", err)
	}
}

func TestAIHelpersRejectMalformedEndpoint(t *testing.T) {
	configureTestAI(t, "://invalid endpoint")
	if _, err := getEmbedding(context.Background(), "question"); err == nil {
		t.Error("embedding accepted invalid endpoint")
	}
	if _, _, err := getCompletion(context.Background(), "question", "", true); err == nil {
		t.Error("completion accepted invalid endpoint")
	}
	response := httptest.NewRecorder()
	if err := streamCompletion(context.Background(), response, response, "question", "", true, nil); err == nil {
		t.Error("stream accepted invalid endpoint")
	}
}
