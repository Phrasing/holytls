# BoringSSL Impersonation Patches

This document describes the patches needed to add Chrome impersonation APIs to upstream BoringSSL.
These patches are extracted from lexiforest/boringssl (impersonate branch).

## Overview

The impersonation patches add the following APIs:

| API | Purpose |
|-----|---------|
| `SSL_CTX_set_extension_order()` | Set exact TLS extension ordering |
| `SSL_CTX_set_permute_extensions()` | Enable Chrome 110+ extension randomization |
| `SSL_set_permute_extensions()` | Per-connection extension randomization |
| `SSL_set_key_shares_limit()` | Limit number of key shares offered |
| `SSL_CTX_set_key_shares_limit()` | Context-level key shares limit |
| `SSL_set_enable_ech_grease()` | Enable ECH GREASE placeholder |
| `SSL_set_alps_use_new_codepoint()` | Use new ALPS extension codepoint (17613) |

## Files to Modify

### 1. `include/openssl/ssl.h`

Add API declarations:

```c
// curl-impersonate: set the extension order by given string
// Format: dash-separated TLSEXT_TYPE IDs, e.g. "11-23-45-18-35-65037-5-0-27-16-13-10-65281-17613-43-51"
OPENSSL_EXPORT int SSL_CTX_set_extension_order(SSL_CTX *ctx, char *order);

// SSL_CTX_set_permute_extensions configures whether sockets on |ctx| should
// permute the order of TLS extensions.
OPENSSL_EXPORT void SSL_CTX_set_permute_extensions(SSL_CTX *ctx, int enabled);

// SSL_set_permute_extensions configures whether |ssl| should permute the order
// of TLS extensions.
OPENSSL_EXPORT void SSL_set_permute_extensions(SSL *ssl, int enabled);

// SSL_set_key_shares_limit limits the number of key shares offered in ClientHello.
OPENSSL_EXPORT void SSL_set_key_shares_limit(SSL *ssl, uint8_t limit);

// SSL_CTX_set_key_shares_limit sets the default key shares limit for |ctx|.
OPENSSL_EXPORT void SSL_CTX_set_key_shares_limit(SSL_CTX *ctx, uint8_t limit);

// SSL_set_enable_ech_grease configures whether the client will send a GREASE
// ECH extension when ECH is not configured.
OPENSSL_EXPORT void SSL_set_enable_ech_grease(SSL *ssl, int enable);

// SSL_set_alps_use_new_codepoint configures whether to use the new ALPS
// extension codepoint (17613) instead of the old one (17513).
OPENSSL_EXPORT void SSL_set_alps_use_new_codepoint(SSL *ssl, int use_new);
```

### 2. `ssl/internal.h`

Add to `SSL_CONFIG` struct:

```cpp
// Extension ordering string (dash-separated TLSEXT_TYPE IDs)
char *extension_order = nullptr;

// Whether to permute extensions when sending messages
bool permute_extensions : 1;

// Maximum number of key shares to offer (0 = no limit)
uint8_t key_shares_limit = 0;

// Whether to use new ALPS extension codepoint
bool alps_use_new_codepoint : 1;
```

Add to `SSL_CTX` struct (same fields):

```cpp
char *extension_order = nullptr;
bool permute_extensions : 1;
uint8_t key_shares_limit = 0;
```

Add function declaration:

```cpp
// Sets up extension permutation array from extension_order string
bool ssl_set_extension_order(SSL_HANDSHAKE *hs);
```

### 3. `ssl/ssl_lib.cc`

Add function implementations:

```cpp
void SSL_set_key_shares_limit(SSL *ssl, uint8_t limit) {
  if (!ssl->config) {
    return;
  }
  ssl->config->key_shares_limit = limit;
}

void SSL_CTX_set_key_shares_limit(SSL_CTX *ctx, uint8_t limit) {
  ctx->key_shares_limit = limit;
}

void SSL_set_alps_use_new_codepoint(SSL *ssl, int use_new) {
  if (!ssl->config) {
    return;
  }
  ssl->config->alps_use_new_codepoint = !!use_new;
}

void SSL_CTX_set_permute_extensions(SSL_CTX *ctx, int enabled) {
  ctx->permute_extensions = !!enabled;
}

// curl-impersonate: set extensions order
int SSL_CTX_set_extension_order(SSL_CTX *ctx, char *order) {
  ctx->extension_order = order;
  return 0;
}

void SSL_set_permute_extensions(SSL *ssl, int enabled) {
  if (!ssl->config) {
    return;
  }
  ssl->config->permute_extensions = !!enabled;
}
```

In `ssl_new()`, copy context settings to connection config:

```cpp
ssl->config->extension_order = ctx->extension_order;
ssl->config->key_shares_limit = ctx->key_shares_limit;
```

### 4. `ssl/extensions.cc`

Add extension ordering implementation:

```cpp
//
// Generate the extension_permutation array from a customized extension order string.
// The customized extension order string is a dash-separated list of extensions.
//
bool ssl_set_extension_order(SSL_HANDSHAKE *hs) {
  if (hs->config->extension_order == nullptr) {
    return true;
  }

  Array<uint8_t> order;
  if (!order.Init(kNumExtensions)) {
    return false;
  }

  // By default, nothing is reordered.
  for (size_t i = 0; i < kNumExtensions; i++) {
    order[i] = 255;
  }

  // Split the order string, and put the order in the table
  const char *delimiter = "-";
  char *tmp = strdup(hs->config->extension_order);
  char *ext = strtok(tmp, delimiter);
  size_t idx = 0;

  while (ext != nullptr) {
    unsigned ext_index = 0;
    tls_extension_find(&ext_index, atoi(ext));
    order[idx] = ext_index;
    ext = strtok(NULL, delimiter);
    idx++;
  }
  free(tmp);

  hs->extension_permutation = std::move(order);
  return true;
}
```

### 5. `ssl/encrypted_client_hello.cc`

Add ECH GREASE implementation:

```cpp
void SSL_set_enable_ech_grease(SSL *ssl, int enable) {
  if (!ssl->config) {
    return;
  }
  ssl->config->ech_grease_enabled = !!enable;
}
```

### 6. `ssl/handshake_client.cc`

Call `ssl_set_extension_order()` during ClientHello construction:

```cpp
// In ssl_write_client_hello() or similar, add:
if (!ssl_set_extension_order(hs)) {
  return false;
}
```

## MSVC Compatibility Patches

For Windows/MSVC builds, additional patches may be needed:

### `ssl/extensions.cc`
Replace `strdup` with `_strdup` for MSVC compatibility:
```cpp
#ifdef _MSC_VER
  char *tmp = _strdup(hs->config->extension_order);
#else
  char *tmp = strdup(hs->config->extension_order);
#endif
```

### `ssl/handshake_client.cc`
Explicit Span conversion for MSVC strict mode in ternary expressions.

## Application

To apply these patches:

1. Fork google/boringssl
2. Create an `impersonate` branch
3. Apply changes to each file as documented above
4. Test with holytls fingerprint_check tool

## Reference

Full source files from lexiforest/boringssl are saved in:
- `ssl_lib_reference.cc` - ssl/ssl_lib.cc impersonation sections
- `extensions_reference.cc` - ssl/extensions.cc extension ordering
- `internal_h_reference.txt` - ssl/internal.h struct additions
