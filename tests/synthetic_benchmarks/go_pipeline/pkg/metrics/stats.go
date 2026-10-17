package metrics

import (
	"encoding/json"
	"sync/atomic"
)

type MetricsCounter struct {
	TotalReceived   int64 `json:"total_received"`
	TotalProcessed  int64 `json:"total_processed"`
	TotalFiltered   int64 `json:"total_filtered"`
	TotalErrors     int64 `json:"total_errors"`
	TotalBytesInput int64 `json:"total_bytes_input"`
}

func NewMetricsCounter() *MetricsCounter {
	return &MetricsCounter{}
}

func (m *MetricsCounter) IncReceived() {
	atomic.AddInt64(&m.TotalReceived, 1)
}

func (m *MetricsCounter) IncProcessed() {
	atomic.AddInt64(&m.TotalProcessed, 1)
}

func (m *MetricsCounter) IncFiltered() {
	atomic.AddInt64(&m.TotalFiltered, 1)
}

func (m *MetricsCounter) IncErrors() {
	atomic.AddInt64(&m.TotalErrors, 1)
}

func (m *MetricsCounter) AddBytes(n int64) {
	atomic.AddInt64(&m.TotalBytesInput, n)
}

func (m *MetricsCounter) ToJSON() string {
	snap := map[string]int64{
		"total_received":    atomic.LoadInt64(&m.TotalReceived),
		"total_processed":   atomic.LoadInt64(&m.TotalProcessed),
		"total_filtered":    atomic.LoadInt64(&m.TotalFiltered),
		"total_errors":      atomic.LoadInt64(&m.TotalErrors),
		"total_bytes_input": atomic.LoadInt64(&m.TotalBytesInput),
	}
	b, _ := json.Marshal(snap)
	return string(b)
}
