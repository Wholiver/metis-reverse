package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

type PipelineConfig struct {
	Workers       int           `json:"workers"`
	BatchSize     int           `json:"batch_size"`
	Timeout       time.Duration `json:"timeout"`
	FilterKeyword string        `json:"filter_keyword"`
	ShowMetrics   bool          `json:"show_metrics"`
	Mode          string        `json:"mode"`
}

func DefaultConfig() *PipelineConfig {
	return &PipelineConfig{
		Workers:       4,
		BatchSize:     50,
		Timeout:       2 * time.Second,
		FilterKeyword: "",
		ShowMetrics:   false,
		Mode:          "transform",
	}
}

func ParseFlags() (*PipelineConfig, bool, error) {
	cfg := DefaultConfig()

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of go_pipeline:\n")
		flag.PrintDefaults()
	}

	workers := flag.Int("workers", cfg.Workers, "Number of concurrent worker goroutines")
	batchSize := flag.Int("batch", cfg.BatchSize, "Batch processing size")
	filter := flag.String("filter", "", "Filter tasks by keyword substring")
	showMetrics := flag.Bool("metrics", false, "Output JSON metrics summary on exit")
	mode := flag.String("mode", "transform", "Processing mode: transform, filter, or validate")
	showHelp := flag.Bool("help", false, "Show command usage")
	showVersion := flag.Bool("version", false, "Show pipeline version")

	flag.Parse()

	if *showHelp {
		flag.Usage()
		return nil, true, nil
	}
	if *showVersion {
		fmt.Println("go_pipeline v1.2.0 (go/darwin)")
		return nil, true, nil
	}

	cfg.Workers = *workers
	cfg.BatchSize = *batchSize
	cfg.FilterKeyword = *filter
	cfg.ShowMetrics = *showMetrics
	cfg.Mode = *mode

	// Environment variable overrides
	if envW := os.Getenv("PIPELINE_WORKERS"); envW != "" {
		var w int
		if _, err := fmt.Sscanf(envW, "%d", &w); err == nil && w > 0 {
			cfg.Workers = w
		}
	}

	return cfg, false, nil
}

func (c *PipelineConfig) DumpJSON() string {
	b, _ := json.Marshal(c)
	return string(b)
}
