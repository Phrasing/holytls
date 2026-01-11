// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_TLS_CHROME_PROFILE_H_
#define HOLYTLS_TLS_CHROME_PROFILE_H_

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "holytls/config.h"

namespace holytls {
namespace tls {

// TLS fingerprint profile for a specific Chrome version.
// Contains all parameters needed to match Chrome's JA3/JA4 fingerprint.
struct ChromeTlsProfile {
  ChromeVersion version;
  std::string version_string;  // e.g., "120.0.0.0"

  // TLS cipher suites in Chrome's exact order
  // These are the hex values from the ClientHello
  std::vector<uint16_t> cipher_suites;

  // Supported groups (elliptic curves) in Chrome's order
  std::vector<uint16_t> supported_groups;

  // Signature algorithms in Chrome's order
  std::vector<uint16_t> signature_algorithms;

  // TLS extension order string for SSL_CTX_set_extension_order()
  // Format: dash-separated TLSEXT_TYPE IDs (e.g., "11-23-45-18-...")
  const char* extension_order = nullptr;

  // ALPN protocols
  std::vector<std::string> alpn_protocols;

  // Feature flags
  bool grease_enabled = true;         // RFC 8701 GREASE
  bool permute_extensions = true;     // Chrome 110+ randomizes extension order
  bool compress_certificates = true;  // Certificate compression (Brotli)
  bool encrypted_client_hello = false;  // ECH (Chrome 119+, experimental)

  // Record size limit (RFC 8449)
  uint16_t record_size_limit = 16385;

  // Number of key shares to offer (X25519 + P-256 typically)
  uint8_t key_shares_limit = 2;

  // User-Agent string
  std::string user_agent;
};

// Get the TLS profile for a specific Chrome version
const ChromeTlsProfile& GetChromeTlsProfile(ChromeVersion version);

// Get cipher suite string for SSL_CTX_set_cipher_list
std::string GetCipherSuiteString(ChromeVersion version);

// Get supported groups string for SSL_CTX_set1_groups_list
std::string GetSupportedGroupsString(ChromeVersion version);

// Chrome 131 cipher suites (latest stable as of implementation)
// TLS 1.3 ciphers first, then TLS 1.2 fallbacks
inline const std::vector<uint16_t> kChrome131CipherSuites = {
    // TLS 1.3 cipher suites (in Chrome's order)
    0x1301,  // TLS_AES_128_GCM_SHA256
    0x1302,  // TLS_AES_256_GCM_SHA384
    0x1303,  // TLS_CHACHA20_POLY1305_SHA256

    // TLS 1.2 cipher suites (ECDHE preferred)
    0xc02b,  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc02f,  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc02c,  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc030,  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xcca9,  // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xcca8,  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

    // Legacy fallbacks (CBC modes, less preferred)
    0xc013,  // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc014,  // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x009c,  // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009d,  // TLS_RSA_WITH_AES_256_GCM_SHA256
    0x002f,  // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035,  // TLS_RSA_WITH_AES_256_CBC_SHA
};

// Chrome 131 supported groups
inline const std::vector<uint16_t> kChrome131SupportedGroups = {
    0x6399,  // X25519Kyber768Draft00 (post-quantum hybrid)
    0x001d,  // X25519
    0x0017,  // secp256r1 (P-256)
    0x0018,  // secp384r1 (P-384)
};

// Chrome 131 signature algorithms
inline const std::vector<uint16_t> kChrome131SignatureAlgorithms = {
    0x0403,  // ecdsa_secp256r1_sha256
    0x0804,  // rsa_pss_rsae_sha256
    0x0401,  // rsa_pkcs1_sha256
    0x0503,  // ecdsa_secp384r1_sha384
    0x0805,  // rsa_pss_rsae_sha384
    0x0501,  // rsa_pkcs1_sha384
    0x0806,  // rsa_pss_rsae_sha512
    0x0601,  // rsa_pkcs1_sha512
};

// Chrome 120 (fallback for older fingerprint)
inline const std::vector<uint16_t> kChrome120SupportedGroups = {
    0x001d,  // X25519
    0x0017,  // secp256r1 (P-256)
    0x0018,  // secp384r1 (P-384)
};

// Chrome 143 supported groups (X25519MLKEM768 replaces X25519Kyber768)
inline const std::vector<uint16_t> kChrome143SupportedGroups = {
    0x11ec,  // X25519MLKEM768 (post-quantum hybrid, ID 4588)
    0x001d,  // X25519
    0x0017,  // secp256r1 (P-256)
    0x0018,  // secp384r1 (P-384)
};

// Chrome 143 cipher suites (same order as 131, with GREASE handled separately)
inline const std::vector<uint16_t> kChrome143CipherSuites = {
    // TLS 1.3 cipher suites
    0x1301,  // TLS_AES_128_GCM_SHA256
    0x1302,  // TLS_AES_256_GCM_SHA384
    0x1303,  // TLS_CHACHA20_POLY1305_SHA256

    // TLS 1.2 cipher suites (ECDHE preferred)
    0xc02b,  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc02f,  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc02c,  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc030,  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xcca9,  // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xcca8,  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

    // Legacy fallbacks
    0xc013,  // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc014,  // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x009c,  // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009d,  // TLS_RSA_WITH_AES_256_GCM_SHA384
    0x002f,  // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035,  // TLS_RSA_WITH_AES_256_CBC_SHA
};

// Chrome 143 signature algorithms (same as 131)
inline const std::vector<uint16_t> kChrome143SignatureAlgorithms = {
    0x0403,  // ecdsa_secp256r1_sha256
    0x0804,  // rsa_pss_rsae_sha256
    0x0401,  // rsa_pkcs1_sha256
    0x0503,  // ecdsa_secp384r1_sha384
    0x0805,  // rsa_pss_rsae_sha384
    0x0501,  // rsa_pkcs1_sha384
    0x0806,  // rsa_pss_rsae_sha512
    0x0601,  // rsa_pkcs1_sha512
};

// Chrome 143 extension order (from real Chrome 143 capture)
// Format: dash-separated TLSEXT_TYPE IDs for SSL_CTX_set_extension_order()
// This order was captured from a genuine Chrome 143 ClientHello
inline const char* kChrome143ExtensionOrder =
    "11-23-45-18-35-65037-5-0-27-16-13-10-65281-17613-43-51";

}  // namespace tls
}  // namespace holytls

#endif  // HOLYTLS_TLS_CHROME_PROFILE_H_
