// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_TLS_TLS_CONTEXT_H_
#define HOLYTLS_TLS_TLS_CONTEXT_H_

// Include platform.h first for Windows compatibility
#include "holytls/util/platform.h"

#include <openssl/ssl.h>

#include <memory>
#include <string>
#include <string_view>

#include "holytls/config.h"
#include "holytls/tls/chrome_profile.h"

namespace holytls {
namespace tls {

// Forward declaration
class TlsSessionCache;

// Custom deleters for OpenSSL types
struct SslCtxDeleter {
  void operator()(SSL_CTX* ctx) {
    if (ctx != nullptr) {
      SSL_CTX_free(ctx);
    }
  }
};

using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;

// TLS context factory - creates SSL_CTX configured for Chrome impersonation.
// The SSL_CTX is thread-safe for concurrent SSL_new() calls.
class TlsContextFactory {
 public:
  TlsContextFactory();
  ~TlsContextFactory();

  // Non-copyable, non-movable
  TlsContextFactory(const TlsContextFactory&) = delete;
  TlsContextFactory& operator=(const TlsContextFactory&) = delete;
  TlsContextFactory(TlsContextFactory&&) = delete;
  TlsContextFactory& operator=(TlsContextFactory&&) = delete;

  // Two-phase initialization - must call before use
  bool Initialize(const TlsConfig& config);

  // Check if initialized successfully
  bool IsInitialized() const { return ctx_ != nullptr; }

  // Error message from last failed operation
  std::string_view last_error() const { return last_error_; }

  // Get the SSL_CTX for creating new SSL connections
  SSL_CTX* ctx() const { return ctx_.get(); }

  // Get the Chrome profile being used
  const ChromeTlsProfile& profile() const { return profile_; }

  // Get the Chrome version
  ChromeVersion chrome_version() const { return config_.chrome_version; }

  // Create a new SSL object for a connection
  SSL* CreateSsl();

  // Get session cache (for TlsConnection to attempt resumption)
  TlsSessionCache* session_cache() const { return session_cache_.get(); }

 private:
  // Configure SSL_CTX for Chrome impersonation
  bool ConfigureCipherSuites();
  void ConfigureSupportedGroups();
  void ConfigureExtensions();
  void ConfigureAlpn();
  void ConfigureSessionCache();
  bool ConfigureCertificateVerification();
  bool ConfigureClientCertificate();

  SslCtxPtr ctx_;
  TlsConfig config_;
  ChromeTlsProfile profile_;
  std::unique_ptr<TlsSessionCache> session_cache_;

  // Error message from last failed initialization
  std::string last_error_;
};

}  // namespace tls
}  // namespace holytls

#endif  // HOLYTLS_TLS_TLS_CONTEXT_H_
