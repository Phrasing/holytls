# Chad-TLS Stress Test Benchmark

## Test Configuration

**Client:**
- Windows Server 2022 (GCloud VM)
- 8 vCPUs, 32GB RAM
- chad-tls with Chrome TLS fingerprint
- 16 reactor threads, 6000 connections
- 8 target URLs for multi-reactor distribution

**Server:**
- Ubuntu 24.04 (GCloud VM)
- h2o 2.3.0-DEV with 32 worker threads
- 8 HTTPS ports (8443-8450)
- Self-signed TLS certificate

## Results

```
=== Chad-TLS Stress Test ===
URLs:        8 targets (multi-reactor mode)
Connections: 6000
Duration:    10s (+ 5s warmup)
Target RPS:  unlimited
TLS Verify:  DISABLED (insecure mode)

[Test] Running for 10s...
[T+  1s] RPS:  164637 | InFlight:  6001 | Complete:   164637 | Failed:     0 | P99: <500ms
[T+  2s] RPS:  168971 | InFlight:  6001 | Complete:   333610 | Failed:     0 | P99: <500ms
[T+  3s] RPS:  168374 | InFlight:  6001 | Complete:   501982 | Failed:     0 | P99: <500ms
[T+  4s] RPS:  171184 | InFlight:  6001 | Complete:   673166 | Failed:     0 | P99: <500ms
[T+  5s] RPS:  167495 | InFlight:  6001 | Complete:   840661 | Failed:     0 | P99: <500ms
[T+  6s] RPS:  168878 | InFlight:  6001 | Complete:  1009539 | Failed:     0 | P99: <500ms
[T+  7s] RPS:  164774 | InFlight:  6001 | Complete:  1174313 | Failed:     0 | P99: <500ms
[T+  8s] RPS:  168654 | InFlight:  6002 | Complete:  1342967 | Failed:     0 | P99: <500ms
[T+  9s] RPS:  168857 | InFlight:  6002 | Complete:  1511824 | Failed:     0 | P99: <500ms

=== Final Report ===
Connections:     6000
Duration:        10.0s

Total Requests:  1,662,005
Successful:      1,662,005
Failed:          0
Success Rate:    100.00%

Avg RPS:         165,870
Peak RPS:        171,184
Bytes Received:  26,592,080 (25.36 MB)

Latency P50:     25.93 ms
Latency P95:     103.94 ms
Latency P99:     145.06 ms
Latency P99.9:   207.98 ms
```

## Summary

| Metric | Value |
|--------|-------|
| **Peak RPS** | 171,184 |
| **Avg RPS** | 165,870 |
| **Total Requests** | 1.66M |
| **Success Rate** | 100% |
| **P50 Latency** | 26ms |
| **P99 Latency** | 145ms |

All requests use full TLS 1.3 encryption with Chrome browser fingerprint over HTTP/2 multiplexed connections.
