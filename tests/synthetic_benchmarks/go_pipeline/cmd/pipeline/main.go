package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"metis/pipeline/pkg/config"
	"metis/pipeline/pkg/metrics"
	"metis/pipeline/pkg/processor"
)

func main() {
	cfg, exitEarly, err := config.ParseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Flag parse failed: %v\n", err)
		os.Exit(2)
	}
	if exitEarly {
		os.Exit(0)
	}

	stats := metrics.NewMetricsCounter()
	pool := processor.NewPipelinePool(cfg, stats)

	// Read tasks from stdin line-by-line
	scanner := bufio.NewScanner(os.Stdin)
	var tasks []processor.Task
	taskID := 1

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if len(line) == 0 {
			continue
		}
		tasks = append(tasks, processor.Task{
			ID:      taskID,
			Payload: line,
		})
		taskID++
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Scanner error: %v\n", err)
		os.Exit(1)
	}

	if len(tasks) == 0 {
		if cfg.ShowMetrics {
			fmt.Println(stats.ToJSON())
		}
		os.Exit(0)
	}

	results := pool.Run(tasks)

	// Emit results
	for _, r := range results {
		b, _ := json.Marshal(r)
		fmt.Println(string(b))
	}

	if cfg.ShowMetrics {
		fmt.Println(stats.ToJSON())
	}
}
