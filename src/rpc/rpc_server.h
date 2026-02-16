#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <vector>
#include "rpc/rpc_types.h"
#include "rpc/rpc_tls.h"
#include "xdr/xdr_codec.h"

// RFC 5531 - ONC RPC v2
// Callback receives decoded call header + decoder positioned at procedure args.
using RpcProcedureHandler = std::function<void(
    const RpcCallHeader& call,
    XdrDecoder& args,
    XdrEncoder& reply)>;

struct RpcProgramHandlers {
    // Key: procedure number
    std::map<uint32_t, RpcProcedureHandler> procedures;
};

// Per-client connection state (raw TCP or TLS-upgraded)
struct ClientConnection {
    int fd = -1;
    RpcTlsSession tls;

    // Read exactly len bytes. Returns true on success.
    bool read_exact(void* buf, size_t len);
    // Read up to len bytes. Returns bytes read, 0 on close, -1 on error.
    ssize_t read_some(void* buf, size_t len);
    // Write all bytes. Returns true on success.
    bool write_all(const void* buf, size_t len);
};

class RpcServer {
public:
    RpcServer();
    ~RpcServer();

    // Register a handler for a program/version.
    void register_program(uint32_t program, uint32_t version,
                          RpcProgramHandlers handlers);

    // Set TLS context (optional — if not set, AUTH_TLS probes are ignored).
    void set_tls_context(std::unique_ptr<RpcTlsContext> ctx);

    // Start listening on the given port (TCP).
    void start(uint16_t port);
    void stop();

    // Parse AUTH_SYS credentials from opaque auth body.
    static RpcAuthSys parse_auth_sys(const RpcOpaqueAuth& auth);

private:
    void accept_loop(int listen_fd);
    void handle_client(int client_fd);

    // Returns true if the message was handled (STARTTLS upgrade).
    // Returns false if normal dispatch should continue.
    bool try_tls_upgrade(ClientConnection& conn, const RpcCallHeader& call);

    void process_rpc_message(const uint8_t* data, size_t len, ClientConnection& conn);

    RpcCallHeader decode_call_header(XdrDecoder& dec);
    void send_accepted_reply(ClientConnection& conn, uint32_t xid,
                             RpcAcceptStatus status, const XdrEncoder& body);
    void send_starttls_reply(ClientConnection& conn, uint32_t xid);
    void send_denied_reply(ClientConnection& conn, uint32_t xid,
                           RpcRejectStatus reject_stat,
                           uint32_t low_ver, uint32_t high_ver);
    bool send_record(ClientConnection& conn, const uint8_t* data, size_t len);

    // Key: {program, version}
    std::map<std::pair<uint32_t, uint32_t>, RpcProgramHandlers> programs_;

    std::unique_ptr<RpcTlsContext> tls_ctx_;
    std::atomic<bool> running_{false};
    std::mutex threads_mu_;
    std::vector<std::thread> threads_;
    int listen_fd_ = -1;
};
