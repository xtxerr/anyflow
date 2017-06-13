// Prometheus Metrics

package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

const metricsNamespace = "anyflow"

var (
	packetsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "packets_total",
			Help:      "Number of received UDP packets",
		},
		[]string{"source_ip"},
	)
)
