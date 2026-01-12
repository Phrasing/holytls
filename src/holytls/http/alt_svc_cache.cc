// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/http/alt_svc_cache.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>

namespace holytls {
namespace http {

AltSvcCache::AltSvcCache(const AltSvcCacheConfig& config) : config_(config) {}

void AltSvcCache::ProcessAltSvc(std::string_view origin_host,
                                 uint16_t origin_port,
                                 std::string_view header) {
  std::string key = MakeOriginKey(origin_host, origin_port);
  uint64_t now = NowMs();

  std::vector<AltSvcEntry> entries;

  // Handle "clear" directive
  std::string_view trimmed = Trim(header);
  if (trimmed == "clear") {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.erase(key);
    return;
  }

  if (!ParseAltSvcHeader(header, &entries, now, config_.default_max_age_ms,
                         config_.max_max_age_ms)) {
    return;  // Parse failed, don't update cache
  }

  std::lock_guard<std::mutex> lock(mutex_);

  // Enforce cache size limit (simple eviction: remove oldest)
  if (cache_.size() >= config_.max_entries && cache_.find(key) == cache_.end()) {
    // Find and remove oldest entry
    std::string oldest_key;
    uint64_t oldest_time = UINT64_MAX;
    for (const auto& [k, v] : cache_) {
      if (v.last_updated_ms < oldest_time) {
        oldest_time = v.last_updated_ms;
        oldest_key = k;
      }
    }
    if (!oldest_key.empty()) {
      cache_.erase(oldest_key);
    }
  }

  OriginAltSvc& origin = cache_[key];
  origin.entries = std::move(entries);
  origin.last_updated_ms = now;
}

std::optional<AltSvcEntry> AltSvcCache::GetHttp3Endpoint(std::string_view host,
                                                          uint16_t port) const {
  std::string key = MakeOriginKey(host, port);
  uint64_t now = NowMs();

  std::lock_guard<std::mutex> lock(mutex_);

  // Check failure cache first
  auto fail_it = h3_failures_.find(key);
  if (fail_it != h3_failures_.end() && fail_it->second > now) {
    return std::nullopt;  // Still in failure penalty period
  }

  auto it = cache_.find(key);
  if (it == cache_.end()) {
    return std::nullopt;
  }

  // Find best H3 entry (prefer "h3" over "h3-XX" versions)
  const AltSvcEntry* best = nullptr;
  for (const auto& entry : it->second.entries) {
    if (!entry.IsExpired(now) && entry.SupportsHttp3()) {
      if (!best || entry.protocol == "h3") {
        best = &entry;
        if (entry.protocol == "h3") {
          break;  // "h3" is preferred, stop searching
        }
      }
    }
  }

  if (best) {
    return *best;
  }
  return std::nullopt;
}

bool AltSvcCache::HasHttp3Support(std::string_view host, uint16_t port) const {
  return GetHttp3Endpoint(host, port).has_value();
}

void AltSvcCache::MarkHttp3Failed(std::string_view host, uint16_t port) {
  std::string key = MakeOriginKey(host, port);
  uint64_t expiry = NowMs() + config_.failure_penalty_ms;

  std::lock_guard<std::mutex> lock(mutex_);
  h3_failures_[key] = expiry;
}

void AltSvcCache::ClearHttp3Failure(std::string_view host, uint16_t port) {
  std::string key = MakeOriginKey(host, port);

  std::lock_guard<std::mutex> lock(mutex_);
  h3_failures_.erase(key);
}

void AltSvcCache::ClearOrigin(std::string_view host, uint16_t port) {
  std::string key = MakeOriginKey(host, port);

  std::lock_guard<std::mutex> lock(mutex_);
  cache_.erase(key);
  h3_failures_.erase(key);
}

void AltSvcCache::ClearAll() {
  std::lock_guard<std::mutex> lock(mutex_);
  cache_.clear();
  h3_failures_.clear();
}

size_t AltSvcCache::ClearExpired() {
  uint64_t now = NowMs();
  size_t removed = 0;

  std::lock_guard<std::mutex> lock(mutex_);

  // Clear expired cache entries
  for (auto it = cache_.begin(); it != cache_.end();) {
    // Remove expired entries from this origin
    auto& entries = it->second.entries;
    entries.erase(
        std::remove_if(entries.begin(), entries.end(),
                       [now](const AltSvcEntry& e) { return e.IsExpired(now); }),
        entries.end());

    // Remove origin if no entries left
    if (entries.empty()) {
      it = cache_.erase(it);
      removed++;
    } else {
      ++it;
    }
  }

  // Clear expired failure entries
  for (auto it = h3_failures_.begin(); it != h3_failures_.end();) {
    if (it->second <= now) {
      it = h3_failures_.erase(it);
    } else {
      ++it;
    }
  }

  return removed;
}

size_t AltSvcCache::Size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return cache_.size();
}

size_t AltSvcCache::FailureCount() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return h3_failures_.size();
}

std::string AltSvcCache::MakeOriginKey(std::string_view host, uint16_t port) {
  std::string key;
  key.reserve(host.size() + 6);
  key.append(host);
  key += ':';
  key += std::to_string(port);
  return key;
}

uint64_t AltSvcCache::NowMs() {
  auto now = std::chrono::steady_clock::now();
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          now.time_since_epoch())
          .count());
}

std::string_view AltSvcCache::Trim(std::string_view s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
    s.remove_prefix(1);
  }
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
    s.remove_suffix(1);
  }
  return s;
}

bool AltSvcCache::ParseAltSvcHeader(std::string_view header,
                                     std::vector<AltSvcEntry>* entries,
                                     uint64_t now_ms,
                                     uint64_t default_max_age_ms,
                                     uint64_t max_max_age_ms) {
  header = Trim(header);
  if (header.empty()) {
    return false;
  }

  // Split by comma, handling quoted strings
  while (!header.empty()) {
    // Find comma not inside quotes
    size_t pos = 0;
    bool in_quotes = false;
    while (pos < header.size()) {
      char c = header[pos];
      if (c == '"') {
        in_quotes = !in_quotes;
      } else if (c == ',' && !in_quotes) {
        break;
      }
      pos++;
    }

    std::string_view entry_str = Trim(header.substr(0, pos));
    if (!entry_str.empty()) {
      AltSvcEntry entry;
      if (ParseSingleEntry(entry_str, &entry, now_ms, default_max_age_ms,
                           max_max_age_ms)) {
        entries->push_back(std::move(entry));
      }
    }

    if (pos >= header.size()) {
      break;
    }
    header.remove_prefix(pos + 1);
    header = Trim(header);
  }

  return !entries->empty();
}

bool AltSvcCache::ParseSingleEntry(std::string_view entry_str,
                                    AltSvcEntry* entry, uint64_t now_ms,
                                    uint64_t default_max_age_ms,
                                    uint64_t max_max_age_ms) {
  entry_str = Trim(entry_str);
  if (entry_str.empty()) {
    return false;
  }

  // Format: protocol="host:port"; ma=seconds; persist=1
  // Example: h3=":443"; ma=86400
  // Example: h3="alt.example.com:8443"; ma=3600

  // Find '=' separating protocol from authority
  size_t eq_pos = entry_str.find('=');
  if (eq_pos == std::string_view::npos || eq_pos == 0) {
    return false;
  }

  entry->protocol = std::string(Trim(entry_str.substr(0, eq_pos)));
  entry_str.remove_prefix(eq_pos + 1);
  entry_str = Trim(entry_str);

  // Parse quoted authority
  if (entry_str.empty() || entry_str[0] != '"') {
    return false;
  }

  size_t end_quote = entry_str.find('"', 1);
  if (end_quote == std::string_view::npos) {
    return false;
  }

  std::string_view authority = entry_str.substr(1, end_quote - 1);
  entry_str.remove_prefix(end_quote + 1);

  // Parse authority: either ":port" or "host:port"
  size_t colon_pos = authority.rfind(':');
  if (colon_pos == std::string_view::npos) {
    return false;
  }

  if (colon_pos == 0) {
    entry->host.clear();  // Same host as origin
  } else {
    entry->host = std::string(authority.substr(0, colon_pos));
  }

  // Parse port
  std::string_view port_str = authority.substr(colon_pos + 1);
  uint16_t port_val = 0;
  auto [ptr, ec] =
      std::from_chars(port_str.data(), port_str.data() + port_str.size(), port_val);
  if (ec != std::errc{} || port_val == 0) {
    return false;
  }
  entry->port = port_val;

  // Parse parameters (ma=, persist=, etc.)
  uint64_t max_age_seconds = default_max_age_ms / 1000;

  while (!entry_str.empty()) {
    entry_str = Trim(entry_str);
    if (entry_str.empty() || entry_str[0] != ';') {
      break;
    }
    entry_str.remove_prefix(1);
    entry_str = Trim(entry_str);

    // Find parameter name=value
    size_t param_end = entry_str.find(';');
    std::string_view param =
        Trim(entry_str.substr(0, param_end == std::string_view::npos
                                     ? entry_str.size()
                                     : param_end));

    // Check for ma= parameter
    if (param.size() > 3 && param[0] == 'm' && param[1] == 'a' &&
        param[2] == '=') {
      std::string_view ma_str = param.substr(3);
      uint64_t ma_val = 0;
      auto [ma_ptr, ma_ec] =
          std::from_chars(ma_str.data(), ma_str.data() + ma_str.size(), ma_val);
      if (ma_ec == std::errc{}) {
        max_age_seconds = ma_val;
      }
    }

    if (param_end == std::string_view::npos) {
      break;
    }
    entry_str.remove_prefix(param_end);
  }

  // Cap max-age
  uint64_t max_age_ms = max_age_seconds * 1000;
  if (max_age_ms > max_max_age_ms) {
    max_age_ms = max_max_age_ms;
  }

  entry->expires_ms = now_ms + max_age_ms;
  return true;
}

}  // namespace http
}  // namespace holytls
