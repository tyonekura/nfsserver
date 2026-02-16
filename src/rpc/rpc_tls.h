#pragma once

#include <memory>
#include <string>
#include <openssl/ssl.h>

// RFC 9289 — RPC-with-TLS support
// TLS context (one per server) and session (one per connection).

class RpcTlsContext {
public:
    // Create TLS context with server certificate and private key.
    // Enforces TLS 1.3 minimum and ALPN "sunrpc".
    RpcTlsContext(const std::string& cert_path, const std::string& key_path);
    ~RpcTlsContext();

    RpcTlsContext(const RpcTlsContext&) = delete;
    RpcTlsContext& operator=(const RpcTlsContext&) = delete;

    // Create a server-side SSL object bound to an existing fd.
    // Caller must call SSL_do_handshake() via RpcTlsSession.
    SSL* create_ssl(int fd);

    bool valid() const { return ctx_ != nullptr; }

private:
    SSL_CTX* ctx_ = nullptr;
};

class RpcTlsSession {
public:
    RpcTlsSession() = default;
    explicit RpcTlsSession(SSL* ssl);
    ~RpcTlsSession();

    RpcTlsSession(RpcTlsSession&& other) noexcept;
    RpcTlsSession& operator=(RpcTlsSession&& other) noexcept;
    RpcTlsSession(const RpcTlsSession&) = delete;
    RpcTlsSession& operator=(const RpcTlsSession&) = delete;

    // Perform TLS handshake. Returns true on success.
    bool handshake();

    // TLS-aware I/O. Returns bytes read/written, or -1 on error.
    ssize_t read(void* buf, size_t len);
    ssize_t write(const void* buf, size_t len);

    bool is_active() const { return ssl_ != nullptr; }

private:
    SSL* ssl_ = nullptr;
};
