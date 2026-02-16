#include "rpc/rpc_tls.h"
#include <openssl/err.h>
#include <iostream>

// RFC 9289 §5.1 — ALPN protocol identifier for ONC RPC
static int alpn_select_cb(SSL*, const unsigned char** out, unsigned char* outlen,
                          const unsigned char* in, unsigned int inlen, void*) {
    // Look for "sunrpc" in the client's ALPN list
    const unsigned char sunrpc[] = {6, 's','u','n','r','p','c'};
    for (unsigned int i = 0; i < inlen; ) {
        unsigned int proto_len = in[i];
        if (i + 1 + proto_len > inlen) break;
        if (proto_len == 6 && memcmp(in + i + 1, "sunrpc", 6) == 0) {
            *out = in + i + 1;
            *outlen = proto_len;
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1 + proto_len;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

RpcTlsContext::RpcTlsContext(const std::string& cert_path,
                             const std::string& key_path) {
    const SSL_METHOD* method = TLS_server_method();
    ctx_ = SSL_CTX_new(method);
    if (!ctx_) {
        std::cerr << "  TLS: failed to create SSL_CTX\n";
        return;
    }

    // RFC 9289 §5.2.1 — TLS 1.3 minimum
    SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);

    // ALPN callback for server-side protocol selection
    SSL_CTX_set_alpn_select_cb(ctx_, alpn_select_cb, nullptr);

    // Load server certificate
    if (SSL_CTX_use_certificate_chain_file(ctx_, cert_path.c_str()) != 1) {
        std::cerr << "  TLS: failed to load certificate from " << cert_path << "\n";
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
        return;
    }

    // Load private key (must be unencrypted)
    if (SSL_CTX_use_PrivateKey_file(ctx_, key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
        std::cerr << "  TLS: failed to load private key from " << key_path << "\n";
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
        return;
    }

    if (SSL_CTX_check_private_key(ctx_) != 1) {
        std::cerr << "  TLS: certificate and private key do not match\n";
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
        return;
    }
}

RpcTlsContext::~RpcTlsContext() {
    if (ctx_) SSL_CTX_free(ctx_);
}

SSL* RpcTlsContext::create_ssl(int fd) {
    if (!ctx_) return nullptr;
    SSL* ssl = SSL_new(ctx_);
    if (!ssl) return nullptr;
    if (SSL_set_fd(ssl, fd) != 1) {
        SSL_free(ssl);
        return nullptr;
    }
    return ssl;
}

// --- RpcTlsSession ---

RpcTlsSession::RpcTlsSession(SSL* ssl) : ssl_(ssl) {}

RpcTlsSession::~RpcTlsSession() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
    }
}

RpcTlsSession::RpcTlsSession(RpcTlsSession&& other) noexcept : ssl_(other.ssl_) {
    other.ssl_ = nullptr;
}

RpcTlsSession& RpcTlsSession::operator=(RpcTlsSession&& other) noexcept {
    if (this != &other) {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
        }
        ssl_ = other.ssl_;
        other.ssl_ = nullptr;
    }
    return *this;
}

bool RpcTlsSession::handshake() {
    if (!ssl_) return false;
    int ret = SSL_accept(ssl_);
    if (ret != 1) {
        int err = SSL_get_error(ssl_, ret);
        std::cerr << "  TLS: handshake failed (SSL error " << err << ")\n";
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

ssize_t RpcTlsSession::read(void* buf, size_t len) {
    if (!ssl_) return -1;
    int n = SSL_read(ssl_, buf, static_cast<int>(len));
    if (n <= 0) {
        int err = SSL_get_error(ssl_, n);
        if (err == SSL_ERROR_ZERO_RETURN) return 0;  // clean shutdown
        return -1;
    }
    return n;
}

ssize_t RpcTlsSession::write(const void* buf, size_t len) {
    if (!ssl_) return -1;
    int n = SSL_write(ssl_, buf, static_cast<int>(len));
    if (n <= 0) return -1;
    return n;
}
