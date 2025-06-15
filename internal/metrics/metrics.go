package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	RequestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "api_requests_total",
			Help: "Общее количество запросов к API",
		},
		[]string{"endpoint"},
	)

	RequestHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "api_request_duration_seconds",
			Help:    "Длительность обработки запроса",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"endpoint"},
	)
)

// Инициализация
func Init() {
	prometheus.MustRegister(RequestCounter)
	prometheus.MustRegister(RequestHistogram)
}
