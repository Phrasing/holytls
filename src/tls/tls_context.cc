// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "tls/tls_context.h"

#include <brotli/decode.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <stdexcept>
#include <vector>

namespace chad {
namespace tls {

namespace {

// Brotli decompression callback for certificate compression (RFC 8879)
// Algorithm ID 2 = Brotli
int BrotliDecompressCert(SSL* /*ssl*/, CRYPTO_BUFFER** out,
                         size_t uncompressed_len, const uint8_t* in,
                         size_t in_len) {
  // Thread-local buffer reuses memory across handshakes on same thread
  thread_local std::vector<uint8_t> buf;
  buf.resize(uncompressed_len);
  size_t decoded_size = uncompressed_len;

  BrotliDecoderResult result =
      BrotliDecoderDecompress(in_len, in, &decoded_size, buf.data());

  if (result != BROTLI_DECODER_RESULT_SUCCESS ||
      decoded_size != uncompressed_len) {
    return 0;
  }

  *out = CRYPTO_BUFFER_new(buf.data(), decoded_size, nullptr);
  return *out != nullptr ? 1 : 0;
}

}  // namespace

TlsContextFactory::TlsContextFactory(const TlsConfig& config)
    : config_(config), profile_(GetChromeTlsProfile(config.chrome_version)) {
  // Create TLS client context
  ctx_.reset(SSL_CTX_new(TLS_client_method()));
  if (!ctx_) {
    throw std::runtime_error("Failed to create SSL_CTX");
  }

  // Configure for Chrome impersonation
  ConfigureCipherSuites();
  ConfigureSupportedGroups();
  ConfigureExtensions();
  ConfigureAlpn();
  ConfigureSessionCache();
  ConfigureCertificateVerification();
  ConfigureClientCertificate();
}

TlsContextFactory::~TlsContextFactory() = default;

SSL* TlsContextFactory::CreateSsl() {
  SSL* ssl = SSL_new(ctx_.get());
  if (ssl == nullptr) {
    return nullptr;
  }

  // Per-connection settings from lexiforest/boringssl patches

  // Enable extension permutation (Chrome 110+)
  // This randomizes the order of TLS extensions in each ClientHello
  if (profile_.permute_extensions) {
    SSL_set_permute_extensions(ssl, 1);
  }

  // Note: Chrome 143 does NOT send record_size_limit extension
  // SSL_set_record_size_limit(ssl, profile_.record_size_limit);

  // Control number of key shares offered
  SSL_set_key_shares_limit(ssl, profile_.key_shares_limit);

  // Enable ECH GREASE (Chrome 130+)
  // Adds fake ECH extension when no ECHConfig available
  if (profile_.encrypted_client_hello) {
    SSL_set_enable_ech_grease(ssl, 1);
  }

  // Enable ALPS for HTTP/2 with new codepoint (17613)
  // Chrome 143 uses the new ALPS extension ID instead of old 17513
  SSL_set_alps_use_new_codepoint(ssl, 1);
  static const uint8_t kH2Proto[] = {'h', '2'};
  SSL_add_application_settings(ssl, kH2Proto, sizeof(kH2Proto), nullptr, 0);

  return ssl;
}

void TlsContextFactory::ConfigureCipherSuites() {
  // Get Chrome cipher suite string
  std::string ciphers = GetCipherSuiteString(config_.chrome_version);

  // BoringSSL uses SSL_CTX_set_cipher_list for all ciphers (TLS 1.2 and 1.3)
  // Unlike OpenSSL 1.1.1+, there's no separate SSL_CTX_set_ciphersuites
  if (SSL_CTX_set_cipher_list(ctx_.get(), ciphers.c_str()) != 1) {
    throw std::runtime_error("Failed to set cipher suites");
  }
}

void TlsContextFactory::ConfigureSupportedGroups() {
  // Set supported groups (elliptic curves) to match Chrome
  std::string groups = GetSupportedGroupsString(config_.chrome_version);

  // Note: BoringSSL uses SSL_CTX_set1_groups_list
  // This sets the supported groups in Chrome's order
  if (SSL_CTX_set1_groups_list(ctx_.get(), groups.c_str()) != 1) {
    // Some groups might not be supported (e.g., Kyber)
    // Fall back to standard groups
    SSL_CTX_set1_groups_list(ctx_.get(), "X25519:P-256:P-384");
  }
}

void TlsContextFactory::ConfigureExtensions() {
  // Enable GREASE (RFC 8701)
  // This adds random fake extension values to prevent ossification
  if (profile_.grease_enabled) {
    SSL_CTX_set_grease_enabled(ctx_.get(), 1);
  }

  // Enable extension permutation at context level
  if (profile_.permute_extensions) {
    SSL_CTX_set_permute_extensions(ctx_.get(), 1);
  }

  // Set signature algorithms from Chrome profile (8 algorithms, no rsa_pkcs1_sha1)
  if (!profile_.signature_algorithms.empty()) {
    SSL_CTX_set_verify_algorithm_prefs(
        ctx_.get(), profile_.signature_algorithms.data(),
        profile_.signature_algorithms.size());
  }

  // Enable OCSP stapling request (Chrome sends this)
  SSL_CTX_enable_ocsp_stapling(ctx_.get());

  // Enable SCT request (Certificate Transparency)
  SSL_CTX_enable_signed_cert_timestamps(ctx_.get());

  // Enable certificate compression (Chrome uses Brotli)
  // Algorithm ID 2 = Brotli per RFC 8879
  // Client only needs decompression callback; compression is nullptr
  SSL_CTX_add_cert_compression_alg(ctx_.get(), 2, nullptr, BrotliDecompressCert);
}

void TlsContextFactory::ConfigureAlpn() {
  // Set ALPN protocols - Chrome sends "h2" and "http/1.1"
  // Wire format: length-prefixed strings
  static const unsigned char kAlpnProtos[] = {
      2, 'h', '2',                               // HTTP/2
      8, 'h', 't', 't', 'p', '/', '1', '.', '1'  // HTTP/1.1
  };

  SSL_CTX_set_alpn_protos(ctx_.get(), kAlpnProtos, sizeof(kAlpnProtos));
}

void TlsContextFactory::ConfigureSessionCache() {
  if (config_.enable_session_cache) {
    // Enable client-side session caching
    SSL_CTX_set_session_cache_mode(ctx_.get(), SSL_SESS_CACHE_CLIENT);

    // Set cache size (cast carefully to avoid sign warnings)
    auto cache_size = static_cast<unsigned long>(config_.session_cache_size);
    SSL_CTX_sess_set_cache_size(ctx_.get(), cache_size);
  } else {
    SSL_CTX_set_session_cache_mode(ctx_.get(), SSL_SESS_CACHE_OFF);
  }
}

void TlsContextFactory::ConfigureCertificateVerification() {
  if (config_.verify_certificates) {
    // Enable certificate verification
    SSL_CTX_set_verify(ctx_.get(), SSL_VERIFY_PEER, nullptr);

    // Load CA certificates
    if (!config_.ca_bundle_path.empty()) {
      if (SSL_CTX_load_verify_locations(ctx_.get(),
                                        config_.ca_bundle_path.c_str(),
                                        nullptr) != 1) {
        throw std::runtime_error("Failed to load CA certificates from: " +
                                 config_.ca_bundle_path);
      }
    } else {
      // Use default CA paths
      if (SSL_CTX_set_default_verify_paths(ctx_.get()) != 1) {
        throw std::runtime_error("Failed to set default CA paths");
      }
    }
  } else {
    // Disable verification (not recommended for production)
    SSL_CTX_set_verify(ctx_.get(), SSL_VERIFY_NONE, nullptr);
  }
}

void TlsContextFactory::ConfigureClientCertificate() {
  if (config_.client_cert_path.empty()) {
    return;
  }

  // Load client certificate
  if (SSL_CTX_use_certificate_file(ctx_.get(), config_.client_cert_path.c_str(),
                                   SSL_FILETYPE_PEM) != 1) {
    throw std::runtime_error("Failed to load client certificate: " +
                             config_.client_cert_path);
  }

  // Load client private key
  if (!config_.client_key_path.empty()) {
    if (SSL_CTX_use_PrivateKey_file(ctx_.get(), config_.client_key_path.c_str(),
                                    SSL_FILETYPE_PEM) != 1) {
      throw std::runtime_error("Failed to load client private key: " +
                               config_.client_key_path);
    }
  }

  // Verify key matches certificate
  if (SSL_CTX_check_private_key(ctx_.get()) != 1) {
    throw std::runtime_error("Client certificate and private key don't match");
  }
}

}  // namespace tls
}  // namespace chad
