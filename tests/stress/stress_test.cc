// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT
//
// Stress test for chad-tls HTTP client.
// Tests throughput and connection stability under high load.

#include <chad/client.h>
#include <chad/config.h>

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

// Configuration from command line
struct StressConfig {
  std::string url;
  size_t num_connections = 1000;
  size_t target_rps = 0;  // 0 = unlimited
  size_t duration_sec = 60;
  size_t warmup_sec = 5;
  size_t num_threads = 0;  // 0 = auto-detect
  bool verbose = false;
};

// Latency histogram buckets (microseconds)
// <1ms, <5ms, <10ms, <50ms, <100ms, <500ms, >=500ms
constexpr size_t kNumLatencyBuckets = 7;
constexpr uint64_t kLatencyBucketLimits[kNumLatencyBuckets] = {
    1000,    // <1ms
    5000,    // <5ms
    10000,   // <10ms
    50000,   // <50ms
    100000,  // <100ms
    500000,  // <500ms
    UINT64_MAX  // >=500ms
};

// Lock-free metrics collection
struct StressMetrics {
  std::atomic<uint64_t> requests_sent{0};
  std::atomic<uint64_t> requests_completed{0};
  std::atomic<uint64_t> requests_failed{0};
  std::atomic<uint64_t> bytes_received{0};
  std::atomic<uint64_t> connections_active{0};

  // Latency histogram (lock-free buckets)
  std::atomic<uint64_t> latency_buckets[kNumLatencyBuckets]{};

  // For calculating percentiles, we store sample latencies
  // This is a simple approach; a production system might use HDR Histogram
  std::mutex latency_mutex;
  std::vector<uint64_t> latency_samples;

  // Time series for RPS calculation
  std::mutex rps_mutex;
  std::vector<uint64_t> rps_history;

  void RecordLatency(uint64_t latency_us) {
    // Update histogram
    for (size_t i = 0; i < kNumLatencyBuckets; ++i) {
      if (latency_us < kLatencyBucketLimits[i]) {
        latency_buckets[i].fetch_add(1, std::memory_order_relaxed);
        break;
      }
    }

    // Store sample for percentile calculation (with sampling)
    // Only store every Nth sample to bound memory usage
    static thread_local uint64_t sample_counter = 0;
    if (++sample_counter % 100 == 0) {
      std::lock_guard<std::mutex> lock(latency_mutex);
      if (latency_samples.size() < 100000) {
        latency_samples.push_back(latency_us);
      }
    }
  }

  void RecordRps(uint64_t rps) {
    std::lock_guard<std::mutex> lock(rps_mutex);
    rps_history.push_back(rps);
  }
};

// Parse URL into host, port, path
struct ParsedUrl {
  std::string host;
  uint16_t port = 443;
  std::string path = "/";
  bool valid = false;
};

ParsedUrl ParseUrl(const std::string& url) {
  ParsedUrl result;

  // Must start with https://
  if (url.rfind("https://", 0) != 0) {
    return result;
  }

  size_t host_start = 8;  // strlen("https://")
  size_t host_end = url.find('/', host_start);
  if (host_end == std::string::npos) {
    host_end = url.length();
  }

  std::string host_port = url.substr(host_start, host_end - host_start);

  // Check for port
  size_t colon = host_port.find(':');
  if (colon != std::string::npos) {
    result.host = host_port.substr(0, colon);
    result.port =
        static_cast<uint16_t>(std::stoul(host_port.substr(colon + 1)));
  } else {
    result.host = host_port;
  }

  if (host_end < url.length()) {
    result.path = url.substr(host_end);
  }

  result.valid = !result.host.empty();
  return result;
}

void PrintUsage(const char* prog) {
  std::fprintf(stderr,
               "Usage: %s [options]\n"
               "\n"
               "Options:\n"
               "  --url URL          Target URL (required, must be https://)\n"
               "  --connections N    Number of concurrent connections (default: 1000)\n"
               "  --rps N            Target requests per second, 0=unlimited (default: 0)\n"
               "  --duration N       Test duration in seconds (default: 60)\n"
               "  --warmup N         Warmup period in seconds (default: 5)\n"
               "  --threads N        Number of worker threads, 0=auto (default: 0)\n"
               "  --verbose          Print verbose output\n"
               "  --help             Show this help\n"
               "\n"
               "Example:\n"
               "  %s --url https://httpbin.org/get --connections 100 --duration 30\n",
               prog, prog);
}

bool ParseArgs(int argc, char* argv[], StressConfig* config) {
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--help") == 0 ||
        std::strcmp(argv[i], "-h") == 0) {
      PrintUsage(argv[0]);
      return false;
    }
    if (std::strcmp(argv[i], "--url") == 0 && i + 1 < argc) {
      config->url = argv[++i];
    } else if (std::strcmp(argv[i], "--connections") == 0 && i + 1 < argc) {
      config->num_connections = std::stoul(argv[++i]);
    } else if (std::strcmp(argv[i], "--rps") == 0 && i + 1 < argc) {
      config->target_rps = std::stoul(argv[++i]);
    } else if (std::strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
      config->duration_sec = std::stoul(argv[++i]);
    } else if (std::strcmp(argv[i], "--warmup") == 0 && i + 1 < argc) {
      config->warmup_sec = std::stoul(argv[++i]);
    } else if (std::strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
      config->num_threads = std::stoul(argv[++i]);
    } else if (std::strcmp(argv[i], "--verbose") == 0) {
      config->verbose = true;
    } else {
      std::fprintf(stderr, "Unknown option: %s\n", argv[i]);
      PrintUsage(argv[0]);
      return false;
    }
  }

  if (config->url.empty()) {
    std::fprintf(stderr, "Error: --url is required\n");
    PrintUsage(argv[0]);
    return false;
  }

  return true;
}

void PrintLiveStats(size_t elapsed_sec, const StressMetrics& metrics,
                    uint64_t rps) {
  uint64_t completed = metrics.requests_completed.load(std::memory_order_relaxed);
  uint64_t failed = metrics.requests_failed.load(std::memory_order_relaxed);
  uint64_t active = metrics.connections_active.load(std::memory_order_relaxed);

  // Calculate P99 from histogram
  uint64_t total = 0;
  for (size_t i = 0; i < kNumLatencyBuckets; ++i) {
    total += metrics.latency_buckets[i].load(std::memory_order_relaxed);
  }

  // Find P99 bucket
  uint64_t p99_target = total * 99 / 100;
  uint64_t cumulative = 0;
  const char* p99_label = ">500ms";
  for (size_t i = 0; i < kNumLatencyBuckets; ++i) {
    cumulative += metrics.latency_buckets[i].load(std::memory_order_relaxed);
    if (cumulative >= p99_target) {
      static const char* labels[] = {"<1ms", "<5ms", "<10ms", "<50ms",
                                     "<100ms", "<500ms", ">500ms"};
      p99_label = labels[i];
      break;
    }
  }

  std::printf("[T+%3zus] RPS: %7" PRIu64 " | Active: %5" PRIu64
              " | Complete: %8" PRIu64 " | Failed: %5" PRIu64
              " | P99: %s\n",
              elapsed_sec, rps, active, completed, failed, p99_label);
  std::fflush(stdout);
}

double CalculatePercentile(std::vector<uint64_t>& samples, double percentile) {
  if (samples.empty()) return 0.0;

  std::sort(samples.begin(), samples.end());
  size_t idx = static_cast<size_t>(samples.size() * percentile / 100.0);
  if (idx >= samples.size()) idx = samples.size() - 1;
  return static_cast<double>(samples[idx]) / 1000.0;  // Convert to ms
}

void PrintFinalReport(const StressConfig& config, const StressMetrics& metrics,
                      std::chrono::steady_clock::duration test_duration) {
  double duration_sec =
      std::chrono::duration<double>(test_duration).count();

  uint64_t completed = metrics.requests_completed.load();
  uint64_t failed = metrics.requests_failed.load();
  uint64_t bytes = metrics.bytes_received.load();

  double success_rate = completed > 0
                            ? (100.0 * completed / (completed + failed))
                            : 0.0;
  double avg_rps = completed / duration_sec;

  // Get peak RPS
  uint64_t peak_rps = 0;
  {
    std::lock_guard<std::mutex> lock(
        const_cast<std::mutex&>(metrics.rps_mutex));
    for (uint64_t rps : metrics.rps_history) {
      if (rps > peak_rps) peak_rps = rps;
    }
  }

  // Calculate percentiles
  std::vector<uint64_t> samples;
  {
    std::lock_guard<std::mutex> lock(
        const_cast<std::mutex&>(metrics.latency_mutex));
    samples = metrics.latency_samples;
  }

  double p50 = CalculatePercentile(samples, 50.0);
  double p95 = CalculatePercentile(samples, 95.0);
  double p99 = CalculatePercentile(samples, 99.0);
  double p999 = CalculatePercentile(samples, 99.9);

  std::printf("\n");
  std::printf("=== Final Report ===\n");
  std::printf("Target URL:      %s\n", config.url.c_str());
  std::printf("Connections:     %zu\n", config.num_connections);
  std::printf("Duration:        %.1fs\n", duration_sec);
  std::printf("\n");
  std::printf("Total Requests:  %" PRIu64 "\n", completed + failed);
  std::printf("Successful:      %" PRIu64 "\n", completed);
  std::printf("Failed:          %" PRIu64 "\n", failed);
  std::printf("Success Rate:    %.2f%%\n", success_rate);
  std::printf("\n");
  std::printf("Avg RPS:         %.0f\n", avg_rps);
  std::printf("Peak RPS:        %" PRIu64 "\n", peak_rps);
  std::printf("Bytes Received:  %" PRIu64 " (%.2f MB)\n", bytes,
              static_cast<double>(bytes) / (1024.0 * 1024.0));
  std::printf("\n");
  std::printf("Latency P50:     %.2f ms\n", p50);
  std::printf("Latency P95:     %.2f ms\n", p95);
  std::printf("Latency P99:     %.2f ms\n", p99);
  std::printf("Latency P99.9:   %.2f ms\n", p999);
  std::printf("\n");

  // Print histogram
  std::printf("Latency Distribution:\n");
  static const char* labels[] = {"  <1ms  ", "  <5ms  ", "  <10ms ",
                                 "  <50ms ", "  <100ms", "  <500ms", "  >=500ms"};
  uint64_t histogram_total = 0;
  for (size_t i = 0; i < kNumLatencyBuckets; ++i) {
    histogram_total += metrics.latency_buckets[i].load();
  }
  for (size_t i = 0; i < kNumLatencyBuckets; ++i) {
    uint64_t count = metrics.latency_buckets[i].load();
    double pct = histogram_total > 0
                     ? (100.0 * count / histogram_total)
                     : 0.0;
    int bar_len = static_cast<int>(pct / 2);  // 50 chars = 100%
    std::printf("  %s: %8" PRIu64 " (%5.1f%%) ", labels[i], count, pct);
    for (int j = 0; j < bar_len; ++j) std::printf("#");
    std::printf("\n");
  }
}

class StressTest {
 public:
  StressTest(const StressConfig& config) : config_(config) {}

  int Run() {
    auto parsed = ParseUrl(config_.url);
    if (!parsed.valid) {
      std::fprintf(stderr, "Error: Invalid URL: %s\n", config_.url.c_str());
      return 1;
    }

    std::printf("=== Chad-TLS Stress Test ===\n");
    std::printf("URL:         %s\n", config_.url.c_str());
    std::printf("Connections: %zu\n", config_.num_connections);
    std::printf("Duration:    %zus (+ %zus warmup)\n", config_.duration_sec,
                config_.warmup_sec);
    std::printf("Target RPS:  %s\n",
                config_.target_rps == 0 ? "unlimited"
                                        : std::to_string(config_.target_rps).c_str());
    std::printf("\n");

    // Configure client
    auto client_config = chad::ClientConfig::ChromeLatest();
    client_config.pool.max_connections_per_host = config_.num_connections;
    client_config.pool.max_total_connections = config_.num_connections;
    if (config_.num_threads > 0) {
      client_config.threads.num_workers = config_.num_threads;
    }

    // Create client
    client_ = std::make_unique<chad::HttpClient>(client_config);

    // Warmup phase
    std::printf("[Warmup] Establishing connections and warming up for %zus...\n",
                config_.warmup_sec);

    warmup_phase_ = true;
    auto warmup_start = std::chrono::steady_clock::now();

    // Send initial batch of requests to establish connections
    for (size_t i = 0; i < config_.num_connections; ++i) {
      SendRequest();
    }

    // Run warmup
    auto warmup_end = warmup_start + std::chrono::seconds(config_.warmup_sec);
    while (std::chrono::steady_clock::now() < warmup_end) {
      client_->RunOnce();
    }

    std::printf("[Warmup] Complete. Active connections: %" PRIu64 "\n",
                metrics_.connections_active.load());
    std::printf("\n");

    // Reset metrics for actual test
    metrics_.requests_completed.store(0);
    metrics_.requests_failed.store(0);
    metrics_.bytes_received.store(0);
    for (size_t i = 0; i < kNumLatencyBuckets; ++i) {
      metrics_.latency_buckets[i].store(0);
    }
    {
      std::lock_guard<std::mutex> lock(metrics_.latency_mutex);
      metrics_.latency_samples.clear();
    }

    // Test phase
    warmup_phase_ = false;
    auto test_start = std::chrono::steady_clock::now();
    auto test_end = test_start + std::chrono::seconds(config_.duration_sec);
    auto last_report = test_start;
    uint64_t last_completed = 0;
    size_t elapsed_sec = 0;

    std::printf("[Test] Running for %zus...\n", config_.duration_sec);

    while (std::chrono::steady_clock::now() < test_end) {
      client_->RunOnce();

      // Send more requests to maintain concurrency
      // With HTTP/2 multiplexing, we can have many in-flight requests
      size_t in_flight = metrics_.requests_sent.load() -
                         metrics_.requests_completed.load() -
                         metrics_.requests_failed.load();
      while (in_flight < config_.num_connections * 10) {
        SendRequest();
        ++in_flight;

        // Rate limiting if configured
        if (config_.target_rps > 0) {
          auto now = std::chrono::steady_clock::now();
          auto test_elapsed =
              std::chrono::duration<double>(now - test_start).count();
          uint64_t expected_sent =
              static_cast<uint64_t>(test_elapsed * config_.target_rps);
          if (metrics_.requests_sent.load() >= expected_sent) {
            break;
          }
        }
      }

      // Live reporting every second
      auto now = std::chrono::steady_clock::now();
      if (now - last_report >= std::chrono::seconds(1)) {
        ++elapsed_sec;
        uint64_t completed = metrics_.requests_completed.load();
        uint64_t rps = completed - last_completed;
        metrics_.RecordRps(rps);
        PrintLiveStats(elapsed_sec, metrics_, rps);
        last_completed = completed;
        last_report = now;
      }
    }

    auto test_duration = std::chrono::steady_clock::now() - test_start;

    // Stop and drain
    std::printf("\n[Test] Stopping and draining...\n");
    running_ = false;

    // Brief drain period to collect final responses
    auto drain_end =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    while (std::chrono::steady_clock::now() < drain_end) {
      client_->RunOnce();
    }

    PrintFinalReport(config_, metrics_, test_duration);

    return 0;
  }

 private:
  void SendRequest() {
    auto start_time = std::chrono::steady_clock::now();
    auto parsed = ParseUrl(config_.url);

    chad::Request req;
    req.SetMethod(chad::Method::kGet).SetUrl(config_.url);

    metrics_.requests_sent.fetch_add(1, std::memory_order_relaxed);
    metrics_.connections_active.fetch_add(1, std::memory_order_relaxed);

    client_->SendAsync(
        std::move(req),
        [this, start_time](chad::Response response, chad::Error error) {
          metrics_.connections_active.fetch_sub(1, std::memory_order_relaxed);

          auto end_time = std::chrono::steady_clock::now();
          uint64_t latency_us =
              std::chrono::duration_cast<std::chrono::microseconds>(end_time -
                                                                    start_time)
                  .count();

          if (!error) {
            metrics_.requests_completed.fetch_add(1, std::memory_order_relaxed);
            metrics_.bytes_received.fetch_add(response.body().size(),
                                              std::memory_order_relaxed);
            if (!warmup_phase_) {
              metrics_.RecordLatency(latency_us);
            }
          } else {
            metrics_.requests_failed.fetch_add(1, std::memory_order_relaxed);
            if (config_.verbose) {
              std::fprintf(stderr, "Request failed: %s\n",
                           error.message().c_str());
            }
          }

          // Send another request to maintain concurrency (if still running)
          if (running_) {
            SendRequest();
          }
        });
  }

  StressConfig config_;
  StressMetrics metrics_;
  std::unique_ptr<chad::HttpClient> client_;
  std::atomic<bool> running_{true};
  bool warmup_phase_ = false;
};

}  // namespace

int main(int argc, char* argv[]) {
  StressConfig config;
  if (!ParseArgs(argc, argv, &config)) {
    return 1;
  }

  StressTest test(config);
  return test.Run();
}
