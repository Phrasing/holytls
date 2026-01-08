// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_TLS_TLS_CONTEXT_H_
#define CHAD_TLS_TLS_CONTEXT_H_

#include <openssl/ssl.h>

#include <memory>
#include <string>

#include "chad/config.h"
#include "tls/chrome_profile.h"

namespace chad {
namespace tls {

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
  explicit TlsContextFactory(const TlsConfig& config);
  ~TlsContextFactory();

  // Non-copyable, non-movable
  TlsContextFactory(const TlsContextFactory&) = delete;
  TlsContextFactory& operator=(const TlsContextFactory&) = delete;
  TlsContextFactory(TlsContextFactory&&) = delete;
  TlsContextFactory& operator=(TlsContextFactory&&) = delete;

  // Get the SSL_CTX for creating new SSL connections
  SSL_CTX* ctx() const { return ctx_.get(); }

  // Get the Chrome profile being used
  const ChromeTlsProfile& profile() const { return profile_; }

  // Get the Chrome version
  ChromeVersion chrome_version() const { return config_.chrome_version; }

  // Create a new SSL object for a connection
  SSL* CreateSsl();

 private:
  // Configure SSL_CTX for Chrome impersonation
  void ConfigureCipherSuites();
  void ConfigureSupportedGroups();
  void ConfigureExtensions();
  void ConfigureAlpn();
  void ConfigureSessionCache();
  void ConfigureCertificateVerification();
  void ConfigureClientCertificate();

  SslCtxPtr ctx_;
  TlsConfig config_;
  ChromeTlsProfile profile_;
};

}  // namespace tls
}  // namespace chad

#endif  // CHAD_TLS_TLS_CONTEXT_H_
