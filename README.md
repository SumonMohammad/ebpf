# eBPF Execve Exporter

This project is an **eBPF-based Prometheus exporter** that tracks every `execve` system call on a Linux system.  
It helps you monitor **which executables are being run**, how often, and exports those metrics to **Prometheus** for visualization and alerting.

---
## Overview 

Every eBPF application usually consists out of at least two parts:

- A user-space program (USP) that declares the kernel space program and attaches it to the relevant tracepoint/probe. -> In this case this is `main.go`.
- A kernel-space program (KSP) is what gets triggered and runs inside the kernel once the tracepoint/probe is met. This is where the actual eBPF logic is implemented. -> In this case this is `ebpf.c`.

## Features

- Trace every process execution (`execve` syscall)
- Export metrics in Prometheus format
- Lightweight and runs in userspace
- Uses eBPF for kernel-level observability

---
## Prerequisites

- Before running this project, make sure you have:

- Linux (with eBPF supported kernel — 5.8+ recommended)

- Docker & Docker Compose installed

- Go 1.21+ (if running locally)

- clang and llvm (for compiling eBPF programs)

- Prometheus installed or running in Docker

## Install dependencies

To install eBPF dependencies, run:
```bash
sudo apt install llvm clang libbpf-dev 
```

To add `ebpf-go` as a dependency to an existing Go module, run this from within the module's directory:
```bash
go get github.com/cilium/ebpf
```

## What is vmlinux.h?

`vmlinux.h` is a kernel header file, providing access to kernel structures and definitions for eBPF programs.

It was generated using:
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

```

## Run these command for creating prometheus and grafana images in Docker 

## For prometheus :

```bash
docker run -d \
--name prometheus \
--network monitoring \
-p 9090:9090 \
-v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
prom/prometheus

```
```text
make sure prometheus docker image is running

Go to http://localhost:2112/metrics for show raw metrices 

GO to http://localhost:9090/targets for check the "ebpf_execve_exporter" job is up

GO to http://localhost:9090/query  for run prometheus metrices query

```


## For grafana 

```bash
docker run -d \
  --name grafana \
  --network monitoring \
  -p 3000:3000 \
  grafana/grafana
```

```text

Go to http://localhost:3000

Default login:

Username: admin

Password: admin

Then:

Connections → Data Sources → Add data source → Prometheus

URL: http://prometheus:9090

“Save & Test”

Now go to

Dashboards → New → New Dashboard → Add Visualization

select `execve_calls_total` in query field and run query
```
## Compile & Run

[bpf2go](https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go) makes it extremely easy to compile and run eBPF program. You just have to run:
```bash

go build
go generate
sudo ./ebpf

```

By running random commands in another terminal, you should be able to see `prog list` logs under `sudo bpftool prog list` command.


## Example Metric

```text
# HELP execve_calls_total Number of execve syscalls per program
# TYPE execve_calls_total counter
execve_calls_total{path="/bin/bash"} 42
execve_calls_total{path="/usr/bin/docker"} 7

How It Works

eBPF program attaches to the sys_enter_execve tracepoint.

Every time a process executes a new binary, it updates a map (exec_count).

The Go userspace program reads this map periodically.

Metrics are exposed over HTTP for Prometheus scraping.

Future Improvements

Add TCP/UDP network syscall tracking (connect, send, recv)

Export system call latency metrics

Include Grafana dashboards for visualization

Package as a Kubernetes DaemonSet for cluster-wide observability

License
This project is licensed under the GPL-3.0 License.

```

## Author
```text
Md Sumon Mia
DevOps & eBPF Enthusiast
miamohammadsumon10@gmail.com
https://github.com/SumonMohammad

```
---
