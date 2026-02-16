# NFS over TLS — Implementation Plan

RFC 9289: "Towards Remote Procedure Call Encryption by Default" (September 2022)

## Overview

Add optional TLS encryption to the RPC transport layer. All protocols (NFSv3, NFSv4, MOUNT, NLM) benefit automatically since TLS operates below the RPC dispatch. Uses an in-band STARTTLS-style upgrade on the existing port — no separate TLS port needed.

**Effort estimate: L-XL (4-8 hours to 1-2 days)**

---

## How It Works (RFC 9289 §4)

```
Client                              Server
  |                                    |
  |--- TCP connect (port 2049) ------->|
  |                                    |
  |--- RPC NULL, auth=AUTH_TLS(7) ---->|   (probe for TLS support)
  |<-- ACCEPTED, verf="STARTTLS" ------|   (server signals TLS ready)
  |                                    |
  |--- TLS ClientHello --------------->|   (TLS 1.3 handshake begins)
  |<-- TLS ServerHello + certs --------|
  |--- TLS Finished ------------------>|
  |<-- TLS Finished -------------------|
  |                                    |
  |=== All subsequent RPC over TLS ===>|   (MOUNT, NFS, NLM calls)
```

Key points:
- **AUTH_TLS** is auth flavor **7** (registered by RFC 9289)
- Server responds to NULL+AUTH_TLS with verifier body = `"STARTTLS"` (8 bytes, NUL-padded)
- TLS 1.3 minimum required
- ALPN extension must use identifier `"sunrpc"`
- Same port handles both TLS and non-TLS clients (per-connection)

---

## Files to Create/Modify

| File | Action | Effort | Description |
|------|--------|--------|-------------|
| `src/rpc/rpc_tls.h` | **New** | S | TLS context wrapper: `RpcTlsContext` (owns `SSL_CTX*`), `RpcTlsSession` (owns `SSL*` per connection) |
| `src/rpc/rpc_tls.cpp` | **New** | M | OpenSSL init, cert/key loading, ALPN setup, handshake, read/write wrappers |
| `src/rpc/rpc_server.h` | Modify | S | Add `RpcTlsContext*` optional member, per-client `RpcTlsSession` |
| `src/rpc/rpc_server.cpp` | Modify | M-L | AUTH_TLS detection in NULL proc, STARTTLS reply, TLS upgrade, replace raw `recv()`/`send()` with TLS-aware I/O |
| `src/rpc/rpc_types.h` | Modify | S | Add `AUTH_TLS = 7` to `RpcAuthFlavor` enum |
| `src/main.cpp` | Modify | S | Add `--tls-cert` and `--tls-key` CLI options, create `RpcTlsContext` |
| `CMakeLists.txt` | Modify | S | `find_package(OpenSSL REQUIRED)`, link, add new sources |
| `Dockerfile` | Modify | S | `apt-get install libssl-dev` |
| `tests/test_rpc.cpp` | Modify | S | Test AUTH_TLS constant, STARTTLS verifier encoding |

---

## Step 1: OpenSSL Dependency

### CMakeLists.txt

```cmake
find_package(OpenSSL REQUIRED)
target_link_libraries(nfs_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto)
```

### Dockerfile

```dockerfile
RUN apt-get install -y ... libssl-dev
```

---

## Step 2: AUTH_TLS Constant

### rpc_types.h

```cpp
enum class RpcAuthFlavor : uint32_t {
    AUTH_NONE = 0,
    AUTH_SYS  = 1,
    AUTH_TLS  = 7,   // RFC 9289 §4.1
};
```

---

## Step 3: TLS Context and Session (`src/rpc/rpc_tls.h/.cpp`)

```cpp
#include <openssl/ssl.h>

class RpcTlsContext {
public:
    // Initialize OpenSSL, create SSL_CTX with TLS 1.3, set ALPN "sunrpc"
    RpcTlsContext(const std::string& cert_path, const std::string& key_path);
    ~RpcTlsContext();

    // Create a per-connection SSL session
    SSL* create_session(int fd);

    bool valid() const;

private:
    SSL_CTX* ctx_ = nullptr;
};

class RpcTlsSession {
public:
    RpcTlsSession() = default;
    explicit RpcTlsSession(SSL* ssl);
    ~RpcTlsSession();

    // Perform TLS handshake (call after STARTTLS reply sent)
    bool handshake();

    // TLS-aware I/O (replaces raw recv/send)
    ssize_t read(void* buf, size_t len);
    ssize_t write(const void* buf, size_t len);

    bool is_active() const { return ssl_ != nullptr; }

private:
    SSL* ssl_ = nullptr;
};
```

### ALPN Configuration

```cpp
// RFC 9289 §5.1 — ALPN protocol identifier
static const uint8_t alpn_sunrpc[] = {6, 's','u','n','r','p','c'};
SSL_CTX_set_alpn_protos(ctx_, alpn_sunrpc, sizeof(alpn_sunrpc));

// Server-side ALPN selection callback
SSL_CTX_set_alpn_select_cb(ctx_, [](SSL*, const uint8_t** out, uint8_t* outlen,
                                     const uint8_t* in, uint32_t inlen, void*) {
    if (SSL_select_next_proto((uint8_t**)out, outlen,
                               (const uint8_t*)"\x06sunrpc", 7,
                               in, inlen) == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}, nullptr);
```

### TLS 1.3 Enforcement

```cpp
SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
```

---

## Step 4: RPC Server Changes (`rpc_server.cpp`)

### 4a. Per-Client TLS State

Currently `handle_client(int client_fd)` uses raw fd. Add an optional TLS session:

```cpp
struct ClientConnection {
    int fd;
    RpcTlsSession tls;  // empty if not upgraded

    ssize_t recv(void* buf, size_t len) {
        return tls.is_active() ? tls.read(buf, len) : ::recv(fd, buf, len, 0);
    }
    bool send(const void* buf, size_t len) {
        if (tls.is_active())
            return tls.write(buf, len) == (ssize_t)len;
        return ::send(fd, buf, len, MSG_NOSIGNAL) == (ssize_t)len;
    }
};
```

### 4b. AUTH_TLS Detection

In `process_rpc_message()`, after decoding the call header:

```cpp
if (call.procedure == 0 &&  // NULL proc
    call.credential.flavor == RpcAuthFlavor::AUTH_TLS &&
    tls_ctx_ != nullptr) {
    // Send STARTTLS reply
    XdrEncoder body;  // empty body for NULL
    send_accepted_reply_starttls(conn, call.xid);

    // Upgrade connection to TLS
    SSL* ssl = tls_ctx_->create_session(conn.fd);
    conn.tls = RpcTlsSession(ssl);
    if (!conn.tls.handshake()) {
        // TLS handshake failed — close connection
        return;
    }
    return;  // Connection now encrypted, wait for next RPC
}
```

### 4c. STARTTLS Verifier Reply

RFC 9289 §4.1: The accepted reply verifier must have flavor=AUTH_NONE and body=`"STARTTLS"`:

```cpp
void send_accepted_reply_starttls(ClientConnection& conn, uint32_t xid) {
    XdrEncoder enc;
    enc.encode_uint32(xid);
    enc.encode_uint32(1);  // REPLY
    enc.encode_uint32(0);  // MSG_ACCEPTED
    // Verifier: AUTH_NONE + "STARTTLS" (8 bytes, NUL-padded)
    enc.encode_uint32(0);  // AUTH_NONE
    enc.encode_uint32(8);  // verf length
    const char starttls[8] = {'S','T','A','R','T','T','L','S'};
    enc.encode_opaque_fixed(starttls, 8);
    enc.encode_uint32(0);  // SUCCESS
    // NULL proc has empty result
    // Send with record marking
    send_record(conn, enc.data(), enc.size());
}
```

### 4d. Refactor I/O Path

Replace all raw `recv()`/`send()` calls in `handle_client()` and `send_tcp()` to go through `ClientConnection`:

| Current | After |
|---------|-------|
| `recv(client_fd, buf, len, 0)` | `conn.recv(buf, len)` |
| `send(client_fd, buf, len, MSG_NOSIGNAL)` | `conn.send(buf, len)` |

This is the largest change — the record marking read loop and reply sending both need to use the connection abstraction.

---

## Step 5: CLI Options (`main.cpp`)

```cpp
std::string tls_cert, tls_key;

// In arg parsing:
} else if (arg == "--tls-cert" && i + 1 < argc) {
    tls_cert = argv[++i];
} else if (arg == "--tls-key" && i + 1 < argc) {
    tls_key = argv[++i];
}

// After creating RPC server:
if (!tls_cert.empty() && !tls_key.empty()) {
    auto tls_ctx = std::make_unique<RpcTlsContext>(tls_cert, tls_key);
    rpc.set_tls_context(std::move(tls_ctx));
    std::cout << "  TLS:    enabled\n";
}
```

Usage:
```bash
./build/nfsd --export /path --port 2049 --tls-cert server.pem --tls-key server.key
```

If `--tls-cert`/`--tls-key` not provided, TLS is disabled and AUTH_TLS probes are silently rejected (client falls back to unencrypted).

---

## Step 6: Tests

| Test | Verifies |
|------|----------|
| `AuthTlsFlavor` | `AUTH_TLS == 7` |
| `StarttlsVerifier` | Verifier body is exactly `"STARTTLS"` (8 bytes) |
| `AlpnIdentifier` | ALPN string is `"sunrpc"` |
| `TlsContextLoadsCert` | `RpcTlsContext` loads a self-signed cert without error |
| `NullWithoutTls` | NULL+AUTH_NONE still works on a TLS-enabled server |

Integration test (Docker):
```bash
# Generate self-signed cert
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem \
  -days 365 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# Start server with TLS
./build/nfsd --export /export --port 2049 --tls-cert server.pem --tls-key server.key &

# Test with openssl s_client (after AUTH_TLS probe)
# Or test with Linux mount -o xprtsec=tls (requires kernel 6.5+ and tlshd)
```

---

## Design Decisions

1. **Optional TLS** — Server works with or without `--tls-cert`/`--tls-key`. When disabled, AUTH_TLS probes get a normal NULL reply (no STARTTLS), and the client falls back transparently.

2. **Application-level TLS, not kTLS** — Linux knfsd uses kernel TLS (kTLS) for performance. Our user-space server will use OpenSSL's `SSL_read()`/`SSL_write()` directly, which is simpler and portable. Performance is sufficient for a user-space server.

3. **All programs share one TLS session** — Since MOUNT, NFS, and NLM share port 2049 on a single TCP connection, one TLS handshake covers all programs. RFC 9289 §4.3 notes this is acceptable when programs share a transport.

4. **No mutual TLS initially** — Start with server-only authentication (client verifies server cert). Mutual TLS (client certs) can be added later by configuring `SSL_CTX_set_verify()` with `SSL_VERIFY_PEER`.

---

## Implementation Order

1. OpenSSL dependency (CMake, Dockerfile)
2. `AUTH_TLS` constant
3. `RpcTlsContext` / `RpcTlsSession` wrapper
4. `ClientConnection` abstraction (refactor I/O path)
5. AUTH_TLS detection + STARTTLS reply
6. TLS handshake upgrade
7. CLI options
8. Tests
9. Integration test with Linux client (`xprtsec=tls`)
