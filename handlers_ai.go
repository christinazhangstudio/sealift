package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type KnowledgeChunk struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Source    string             `bson:"source" json:"source"`
	Text      string             `bson:"text" json:"text"`
	Embedding []float32          `bson:"embedding" json:"embedding"`
	CreatedAt time.Time          `bson:"createdAt" json:"createdAt"`
}

// handleAIIngest ingests documentation into the knowledge base (Sequential Step 1).
func (s *Server) handleAIIngest(w http.ResponseWriter, r *http.Request) {
	docsPath := "docs"
	files, err := os.ReadDir(docsPath)
	if err != nil {
		slog.Error("Failed to read docs directory", "err", err)
		http.Error(w, "Could not find docs directory", http.StatusInternalServerError)
		return
	}

	var ingestedCount int
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".md") {
			continue
		}

		content, err := os.ReadFile(fmt.Sprintf("%s/%s", docsPath, f.Name()))
		if err != nil {
			continue
		}

		// Simple chunking: split by paragraphs for POC
		chunks := strings.Split(string(content), "\n\n")
		for _, text := range chunks {
			text = strings.TrimSpace(text)
			if text == "" {
				continue
			}

			embedding, err := getOllamaEmbedding(text)
			if err != nil {
				slog.Warn("Failed to get embedding from Ollama", "err", err)
				continue
			}

			chunk := KnowledgeChunk{
				Source:    f.Name(),
				Text:      text,
				Embedding: embedding,
				CreatedAt: time.Now(),
			}

			_, err = s.knowledgeBaseLocalCol.InsertOne(r.Context(), chunk)
			if err != nil {
				slog.Error("Failed to save chunk to Local Mongo", "err", err)
			}
			if s.knowledgeBaseAtlasCol != nil {
				_, err = s.knowledgeBaseAtlasCol.InsertOne(r.Context(), chunk)
				if err != nil {
					slog.Error("Failed to save chunk to Atlas Mongo", "err", err)
				}
			}
			ingestedCount++
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "chunks_ingested": ingestedCount})
}

// handleAIAsk handles documentation queries (Sequential Step 2 & 3 Combined).
func (s *Server) handleAIAsk(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
		return
	}
	history := r.URL.Query().Get("history") // Conversation history for LLM context only

	simThresholdStr := os.Getenv("AI_SIMILARITY_THRESHOLD")
	var simThreshold float32 = 0.30 // Default threshold
	if simThresholdStr != "" {
		if val, err := strconv.ParseFloat(simThresholdStr, 32); err == nil {
			simThreshold = float32(val)
		}
	}

	// 1. Get embedding for the user question
	queryEmbedding, err := getOllamaEmbedding(query)
	if err != nil {
		slog.Error("Failed to embed query", "err", err)
		http.Error(w, "AI service unavailable", http.StatusInternalServerError)
		return
	}

	// 2. Retrieval: Search MongoDB for the most relevant chunks
	pipeline := mongo.Pipeline{
		{
			{Key: "$vectorSearch", Value: bson.D{
				{Key: "index", Value: "vector_index"}, // Must match the name in MongoDB Atlas
				{Key: "path", Value: "embedding"},
				{Key: "queryVector", Value: queryEmbedding},
				{Key: "numCandidates", Value: 10},
				{Key: "limit", Value: 3},
			}},
		},
	}

	var chunks []KnowledgeChunk

	// Step 2a: Try High-Performance Atlas Vector Search first (Threshold: 0.7 for Vector)
	if s.knowledgeBaseAtlasCol != nil {
		slog.Debug("Attempting Atlas Vector Search...")
		cursor, err := s.knowledgeBaseAtlasCol.Aggregate(r.Context(), pipeline)
		if err == nil {
			defer cursor.Close(r.Context())
			var atlasChunks []KnowledgeChunk
			if err := cursor.All(r.Context(), &atlasChunks); err == nil {
				for _, c := range atlasChunks {
					score := cosineSimilarity(queryEmbedding, c.Embedding)
					slog.Info("Atlas chunk score", "source", c.Source, "score", score, "threshold", simThreshold)
					// Nomic embeddings typically range 0.25 - 0.7 for valid matches
					if score > simThreshold {
						chunks = append(chunks, c)
					}
				}
				if len(chunks) > 0 {
					slog.Info("Vector search succeeded on Atlas", "count", len(chunks))
				} else if len(atlasChunks) > 0 {
					slog.Info("Atlas found chunks but all were below threshold")
				}
			} else {
				slog.Warn("Vector search fetch failed with error", "err", err)
			}
		} else {
			slog.Warn("Vector search aggregate failed with error", "err", err)
		}
	}

	// Step 2b: Fallback to Local Search if Atlas is missing or empty
	if len(chunks) == 0 {
		slog.Debug("Atlas search empty or failed, trying local fallback...")
		allCursor, err := s.knowledgeBaseLocalCol.Find(r.Context(), bson.M{})
		if err != nil {
			slog.Error("Local Knowledge base inaccessible", "err", err)
		} else {
			defer allCursor.Close(r.Context())
			var allChunks []KnowledgeChunk
			if err := allCursor.All(r.Context(), &allChunks); err == nil {
				type ScoredChunk struct {
					Chunk KnowledgeChunk
					Score float32
				}
				var scored []ScoredChunk
				for _, c := range allChunks {
					score := cosineSimilarity(queryEmbedding, c.Embedding)

					// Similarity Threshold: configurable explicitly via AI_SIMILARITY_THRESHOLD
					if score > simThreshold {
						scored = append(scored, ScoredChunk{Chunk: c, Score: score})
					} else if score > (simThreshold - 0.10) {
						// For debugging: see what closely missed the threshold
						slog.Info("Local chunk closely missed threshold", "score", score, "source", c.Source)
					}
				}

				sort.Slice(scored, func(i, j int) bool {
					return scored[i].Score > scored[j].Score
				})

				limit := 3
				if len(scored) < limit {
					limit = len(scored)
				}
				for i := 0; i < limit; i++ {
					chunks = append(chunks, scored[i].Chunk)
				}
				if len(chunks) > 0 {
					slog.Info("Local search fallback successful", "count", len(chunks))
				}
			}
		}
	}

	// 3. Generation: Combine context and ask Llama
	contextText := ""
	isCasualChat := len(chunks) == 0 && history == "" // Only casual if no docs AND no conversation history

	if !isCasualChat {
		for i, chunk := range chunks {
			contextText += fmt.Sprintf("[%d] Source: %s\nContent: %s\n\n", i+1, chunk.Source, chunk.Text)
		}
	}

	slog.Info("Requesting AI Generation", "isCasual", isCasualChat)

	// Inject conversation history into context for LLM (not used in embedding/vector search)
	llmContext := contextText
	if history != "" {
		llmContext = fmt.Sprintf("Previous Conversation:\n%s\n\n%s", history, contextText)
	}

	answer, err := getCompletion(query, llmContext, isCasualChat)
	if err != nil {
		slog.Error("failed to generate answer", "err", err)
		http.Error(w, "Failed to generate answer; AI server temporarily down?", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"query":   query,
		"answer":  answer,
		"sources": chunks,
	})
}

// --- AI Helper Functions ---

func getOllamaEmbedding(text string) ([]float32, error) {
	baseUrl := ollamaURL
	if baseUrl == "" {
		baseUrl = "http://localhost:11434"
	}
	url := fmt.Sprintf("%s/api/embeddings", baseUrl)
	// Nomic Embed Text strictly requires explicit task prefixes to mathematically align vectors for retrieval
	queryText := text
	if !strings.HasPrefix(queryText, "search_query: ") {
		queryText = "search_query: " + queryText
	}

	payload := map[string]interface{}{
		"model":  "nomic-embed-text",
		"prompt": queryText,
	}

	body, _ := json.Marshal(payload)

	// Create client with timeout specifically for Ollama
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	var result struct {
		Embedding []float32 `json:"embedding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Embedding, nil
}

func getCompletion(query string, contextText string, isCasual bool) (string, error) {
	var prompt string
	if isCasual {
		prompt = loadPromptTemplate("prompts/casual.txt", map[string]string{"Query": query})
	} else {
		prompt = loadPromptTemplate("prompts/rag.txt", map[string]string{"Query": query, "Context": contextText})
	}

	cloudKey := os.Getenv("OPENAI_API_KEY")
	useSelfHosted := os.Getenv("USE_SELF_HOSTED_AI") == "true"

	// Either Self-Hosted OpenAI-compatible or Groq Cloud
	if cloudKey != "" || useSelfHosted {
		baseURL := os.Getenv("OPENAI_BASE_URL")
		if baseURL == "" {
			baseURL = "https://api.groq.com/openai/v1/chat/completions" // Groq cloud is extremely fast & has a free tier for Llama 3
		}
		model := os.Getenv("GROQ_AI_MODEL")

		// OVERRIDE for Self-Hosted Endpoint
		if useSelfHosted {
			selfHostedURL := os.Getenv("SELF_HOSTED_AI_URL")
			if selfHostedURL != "" {
				baseURL = selfHostedURL
			} else {
				return "", errors.New("SELF_HOSTED_AI_URL must be provided when USE_SELF_HOSTED_AI is true")
			}

			model = os.Getenv("SELF_HOSTED_AI_MODEL")
			if model == "" {
				return "", errors.New("SELF_HOSTED_AI_MODEL must be provided when USE_SELF_HOSTED_AI is true")
			}
		}

		if model == "" {
			return "", errors.New("GROQ_AI_MODEL must be explicitly provided when using the Cloud API")
		}

		payload := map[string]interface{}{
			"model": model,
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		}
		body, _ := json.Marshal(payload)

		client := &http.Client{Timeout: 300 * time.Second} // Long timeout for heavy self-hosted responses
		req, _ := http.NewRequest("POST", baseURL, strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+cloudKey)
		req.Header.Set("Content-Type", "application/json")

		if useSelfHosted {
			slog.Info("Using self-hosted AI endpoint", "url", baseURL)
		} else {
			slog.Info("Using Groq Cloud AI endpoint", "url", baseURL)
		}

		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyText, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("AI endpoint returned status %d: %s", resp.StatusCode, string(bodyText))
		}

		var result struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return "", err
		}
		if len(result.Choices) > 0 {
			slog.Info("processed AI response", "response", resp, "body", resp.Body)
			return result.Choices[0].Message.Content, nil
		}
		return "", errors.New("invalid response from AI endpoint")
	}

	// Fallback to local Ollama
	baseUrl := ollamaURL
	if baseUrl == "" {
		baseUrl = "http://localhost:11434"
	}
	url := fmt.Sprintf("%s/api/generate", baseUrl)

	payload := map[string]interface{}{
		"model":  "llama3",
		"prompt": prompt,
		"stream": false,
	}

	body, _ := json.Marshal(payload)

	// Custom client with long timeout for generation
	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Response, nil
}

func cosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dotProduct, normA, normB float32
	for i := 0; i < len(a); i++ {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dotProduct / (float32(math.Sqrt(float64(normA))) * float32(math.Sqrt(float64(normB))))
}

// loadPromptTemplate reads a prompt template from a file path, falling back to a hardcoded default.
// Templates use Go text/template syntax: {{.Query}}, {{.Context}}, etc.
func loadPromptTemplate(filePath string, data map[string]string) string {
	tmplText := ""
	if content, err := os.ReadFile(filePath); err == nil {
		tmplText = string(content)
		slog.Debug("Loaded prompt template from file", "path", filePath)
	} else {
		slog.Debug("Using default prompt template", "path", filePath, "reason", err.Error())
	}

	tmpl, err := template.New("prompt").Parse(tmplText)
	if err != nil {
		slog.Warn("Failed to parse prompt template, using raw text", "err", err)
		return tmplText
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		slog.Warn("Failed to execute prompt template, using raw text", "err", err)
		return tmplText
	}
	return buf.String()
}
