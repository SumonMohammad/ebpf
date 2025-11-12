package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf ebpf ./ebpf.c -- -I. -g -O2

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	execCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "execve_calls_total",
			Help: "Number of execve syscalls per program",
		},
		[]string{"path"},
	)
)

// Helper to convert int8 array from BPF to []byte
func int8ToBytes(arr []int8) []byte {
	b := make([]byte, len(arr))
	for i, v := range arr {
		b[i] = byte(v)
	}
	return b
}

func main() {
	// Remove memlock limit for BPF maps
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load compiled BPF objects
	var objs ebpfObjects
	if err := loadEbpfObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Attach tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecveTp, nil)
	if err != nil {
		log.Fatalf("Attaching Tracepoint: %s", err)
	}
	defer tp.Close()

	log.Println("eBPF program attached. Exporting Prometheus metrics at :2112/metrics")

	// Register Prometheus metrics
	prometheus.MustRegister(execCounter)

	// Periodically read eBPF map and update Prometheus counter
	go func() {
		for {
			updateMetrics(&objs)
			time.Sleep(5 * time.Second)
		}
	}()

	// Start HTTP server for Prometheus
	go func() {
		log.Println("Starting HTTP server at :2112")
		if err := http.ListenAndServe(":2112", nil); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()
	http.Handle("/metrics", promhttp.Handler())

	// Wait for SIGINT/SIGTERM to exit
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Println("Received signal, exiting...")
}

// updateMetrics reads BPF map and updates Prometheus counters
func updateMetrics(objs *ebpfObjects) {
	iter := objs.ExecCount.Iterate()
	var key ebpfPathKey
	var val uint64

	for iter.Next(&key, &val) {
		pathBytes := bytes.TrimRight(int8ToBytes(key.Path[:]), "\x00")
		path := string(pathBytes)
		execCounter.WithLabelValues(path).Add(float64(val))
	}
}
