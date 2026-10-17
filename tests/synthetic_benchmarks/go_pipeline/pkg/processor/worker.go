package processor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"metis/pipeline/pkg/config"
	"metis/pipeline/pkg/metrics"
)

type Task struct {
	ID      int    `json:"id"`
	Payload string `json:"payload"`
}

type TaskResult struct {
	ID        int    `json:"id"`
	Status    string `json:"status"` // "PROCESSED", "FILTERED", "ERROR"
	Digest    string `json:"digest,omitempty"`
	Output    string `json:"output,omitempty"`
	ErrorText string `json:"error,omitempty"`
}

type PipelinePool struct {
	config  *config.PipelineConfig
	metrics *metrics.MetricsCounter
}

func NewPipelinePool(cfg *config.PipelineConfig, m *metrics.MetricsCounter) *PipelinePool {
	return &PipelinePool{
		config:  cfg,
		metrics: m,
	}
}

func (p *PipelinePool) Run(tasks []Task) []TaskResult {
	if len(tasks) == 0 {
		return []TaskResult{}
	}

	numWorkers := p.config.Workers
	if numWorkers <= 0 {
		numWorkers = 1
	}
	if numWorkers > len(tasks) {
		numWorkers = len(tasks)
	}

	taskChan := make(chan Task, len(tasks))
	resultChan := make(chan TaskResult, len(tasks))
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go p.workerProcess(w, taskChan, resultChan, &wg)
	}

	for _, t := range tasks {
		p.metrics.IncReceived()
		p.metrics.AddBytes(int64(len(t.Payload)))
		taskChan <- t
	}
	close(taskChan)

	wg.Wait()
	close(resultChan)

	results := make([]TaskResult, 0, len(tasks))
	for res := range resultChan {
		results = append(results, res)
	}

	// Sort results by ID deterministically
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].ID > results[j].ID {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	return results
}

func (p *PipelinePool) workerProcess(workerID int, tasks <-chan Task, results chan<- TaskResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for t := range tasks {
		res := p.processSingleTask(workerID, t)
		results <- res
	}
}

func (p *PipelinePool) processSingleTask(workerID int, t Task) TaskResult {
	// Keyword filter check
	if p.config.FilterKeyword != "" && !strings.Contains(t.Payload, p.config.FilterKeyword) {
		p.metrics.IncFiltered()
		return TaskResult{
			ID:     t.ID,
			Status: "FILTERED",
		}
	}

	// Malformed / error trigger
	if strings.HasPrefix(t.Payload, "ERR:") {
		p.metrics.IncErrors()
		return TaskResult{
			ID:        t.ID,
			Status:    "ERROR",
			ErrorText: strings.TrimPrefix(t.Payload, "ERR:"),
		}
	}

	// Process payload
	h := sha256.Sum256([]byte(t.Payload))
	digest := hex.EncodeToString(h[:8]) // First 8 bytes as short hash

	var output string
	switch p.config.Mode {
	case "validate":
		output = fmt.Sprintf("VALID:%d", len(t.Payload))
	case "filter":
		output = t.Payload
	default: // "transform"
		output = strings.ToUpper(t.Payload)
	}

	p.metrics.IncProcessed()
	return TaskResult{
		ID:     t.ID,
		Status: "PROCESSED",
		Digest: digest,
		Output: output,
	}
}
