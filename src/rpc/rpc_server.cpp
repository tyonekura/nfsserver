#include "rpc/rpc_server.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

// --- ClientConnection I/O ---

bool ClientConnection::read_exact(void* buf, size_t len) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n;
        if (tls.is_active()) {
            n = tls.read(p, remaining);
        } else {
            n = recv(fd, p, remaining, 0);
        }
        if (n <= 0) return false;
        p += n;
        remaining -= n;
    }
    return true;
}

ssize_t ClientConnection::read_some(void* buf, size_t len) {
    if (tls.is_active())
        return tls.read(buf, len);
    return recv(fd, buf, len, 0);
}

bool ClientConnection::write_all(const void* buf, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n;
        if (tls.is_active()) {
            n = tls.write(p, remaining);
        } else {
            n = send(fd, p, remaining, MSG_NOSIGNAL);
        }
        if (n <= 0) return false;
        p += n;
        remaining -= n;
    }
    return true;
}

// --- RpcServer ---

RpcServer::RpcServer() = default;

RpcServer::~RpcServer() {
    stop();
}

void RpcServer::register_program(uint32_t program, uint32_t version,
                                  RpcProgramHandlers handlers) {
    programs_[{program, version}] = std::move(handlers);
}

void RpcServer::set_tls_context(std::unique_ptr<RpcTlsContext> ctx) {
    tls_ctx_ = std::move(ctx);
}

void RpcServer::start(uint16_t port) {
    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0)
        throw std::runtime_error("socket() failed: " + std::string(strerror(errno)));

    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(listen_fd_, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
        throw std::runtime_error("bind() failed: " + std::string(strerror(errno)));

    if (listen(listen_fd_, 16) < 0)
        throw std::runtime_error("listen() failed: " + std::string(strerror(errno)));

    running_ = true;
    {
        std::lock_guard<std::mutex> lk(threads_mu_);
        threads_.emplace_back(&RpcServer::accept_loop, this, listen_fd_);
    }

    std::cout << "RPC server listening on port " << port << std::endl;
}

void RpcServer::stop() {
    running_ = false;
    if (listen_fd_ >= 0) {
        shutdown(listen_fd_, SHUT_RDWR);
        close(listen_fd_);
        listen_fd_ = -1;
    }
    std::vector<std::thread> to_join;
    {
        std::lock_guard<std::mutex> lk(threads_mu_);
        to_join = std::move(threads_);
    }
    for (auto& t : to_join) {
        if (t.joinable())
            t.join();
    }
}

void RpcServer::accept_loop(int listen_fd) {
    while (running_) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd,
                               reinterpret_cast<sockaddr*>(&client_addr),
                               &client_len);
        if (client_fd < 0) {
            if (!running_) break;
            continue;
        }

        int opt = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        {
            std::lock_guard<std::mutex> lk(threads_mu_);
            threads_.emplace_back(&RpcServer::handle_client, this, client_fd);
        }
    }
}

// RFC 5531 §11 - Record Marking Standard (TCP)
// Each record is a sequence of fragments; last fragment has bit 31 set in length header.
void RpcServer::handle_client(int client_fd) {
    ClientConnection conn;
    conn.fd = client_fd;

    while (running_) {
        std::vector<uint8_t> record;
        bool complete = false;

        while (!complete) {
            uint8_t hdr[4];
            if (!conn.read_exact(hdr, 4)) { close(client_fd); return; }

            uint32_t raw = (static_cast<uint32_t>(hdr[0]) << 24) |
                           (static_cast<uint32_t>(hdr[1]) << 16) |
                           (static_cast<uint32_t>(hdr[2]) << 8) |
                           static_cast<uint32_t>(hdr[3]);
            bool last_fragment = (raw & 0x80000000) != 0;
            uint32_t frag_len = raw & 0x7FFFFFFF;

            if (frag_len > 1024 * 1024) { close(client_fd); return; }

            size_t old_size = record.size();
            record.resize(old_size + frag_len);
            if (!conn.read_exact(record.data() + old_size, frag_len)) {
                close(client_fd);
                return;
            }

            complete = last_fragment;

            // Guard against unbounded accumulation
            if (record.size() > 16 * 1024 * 1024) { close(client_fd); return; }
        }

        process_rpc_message(record.data(), record.size(), conn);
    }
    close(client_fd);
}

// RFC 5531 §7.1 - Decode call_body (xid, msg_type, rpcvers, prog, vers, proc, cred, verf)
RpcCallHeader RpcServer::decode_call_header(XdrDecoder& dec) {
    RpcCallHeader call;
    call.xid = dec.decode_uint32();
    uint32_t msg_type = dec.decode_uint32();
    if (msg_type != static_cast<uint32_t>(RpcMsgType::CALL))
        throw std::runtime_error("expected RPC CALL");

    call.rpc_version = dec.decode_uint32();
    call.program = dec.decode_uint32();
    call.version = dec.decode_uint32();
    call.procedure = dec.decode_uint32();

    // Credential
    call.credential.flavor = static_cast<RpcAuthFlavor>(dec.decode_uint32());
    call.credential.body = dec.decode_opaque();

    // Verifier
    call.verifier.flavor = static_cast<RpcAuthFlavor>(dec.decode_uint32());
    call.verifier.body = dec.decode_opaque();

    return call;
}

// RFC 5531 §8.2.2 - AUTH_SYS (stamp, machinename, uid, gid, gids)
RpcAuthSys RpcServer::parse_auth_sys(const RpcOpaqueAuth& auth) {
    RpcAuthSys sys;
    if (auth.body.empty()) return sys;

    XdrDecoder dec(auth.body.data(), auth.body.size());
    sys.stamp = dec.decode_uint32();
    sys.machinename = dec.decode_string();
    sys.uid = dec.decode_uint32();
    sys.gid = dec.decode_uint32();
    uint32_t ngids = dec.decode_uint32();
    for (uint32_t i = 0; i < ngids; ++i)
        sys.gids.push_back(dec.decode_uint32());
    return sys;
}

// RFC 9289 §4.1 - Check for AUTH_TLS on NULL procedure and upgrade to TLS
bool RpcServer::try_tls_upgrade(ClientConnection& conn, const RpcCallHeader& call) {
    if (call.procedure != 0)
        return false;
    if (call.credential.flavor != RpcAuthFlavor::AUTH_TLS)
        return false;
    if (!tls_ctx_ || !tls_ctx_->valid())
        return false;
    if (conn.tls.is_active())
        return false;  // already upgraded

    // Send STARTTLS reply before upgrading
    send_starttls_reply(conn, call.xid);

    // Upgrade to TLS
    SSL* ssl = tls_ctx_->create_ssl(conn.fd);
    if (!ssl) {
        std::cerr << "  TLS: failed to create SSL session\n";
        return true;  // handled (but failed)
    }

    conn.tls = RpcTlsSession(ssl);
    if (!conn.tls.handshake()) {
        std::cerr << "  TLS: handshake failed, closing connection\n";
        conn.tls = RpcTlsSession();  // clear failed session
        return true;  // handled (but failed)
    }

    std::cerr << "  TLS: connection upgraded successfully\n";
    return true;
}

// RFC 5531 §7 - RPC message dispatch (program/version/procedure lookup)
void RpcServer::process_rpc_message(const uint8_t* data, size_t len,
                                     ClientConnection& conn) {
    XdrDecoder dec(data, len);
    RpcCallHeader call;
    try {
        call = decode_call_header(dec);
    } catch (...) {
        return; // malformed, drop silently
    }

    if (call.rpc_version != 2) {
        std::cerr << "RPC version mismatch: " << call.rpc_version << std::endl;
        send_denied_reply(conn, call.xid, RpcRejectStatus::RPC_MISMATCH, 2, 2);
        return;
    }

    // RFC 9289 — Check for TLS upgrade before normal dispatch
    if (try_tls_upgrade(conn, call))
        return;

    auto it = programs_.find({call.program, call.version});
    if (it == programs_.end()) {
        std::cerr << "RPC: program/version not found" << std::endl;
        XdrEncoder body;
        send_accepted_reply(conn, call.xid, RpcAcceptStatus::PROG_UNAVAIL, body);
        return;
    }

    auto proc_it = it->second.procedures.find(call.procedure);
    if (proc_it == it->second.procedures.end()) {
        XdrEncoder body;
        send_accepted_reply(conn, call.xid, RpcAcceptStatus::PROC_UNAVAIL, body);
        return;
    }

    XdrEncoder reply_body;
    try {
        proc_it->second(call, dec, reply_body);
    } catch (const std::exception& e) {
        std::cerr << "RPC procedure error: " << e.what() << std::endl;
        XdrEncoder err_body;
        send_accepted_reply(conn, call.xid, RpcAcceptStatus::SYSTEM_ERR, err_body);
        return;
    }

    send_accepted_reply(conn, call.xid, RpcAcceptStatus::SUCCESS, reply_body);
}

// RFC 9289 §4.1 - STARTTLS accepted reply
// Verifier: flavor=AUTH_NONE, body="STARTTLS" (8 bytes)
void RpcServer::send_starttls_reply(ClientConnection& conn, uint32_t xid) {
    XdrEncoder reply;
    reply.encode_uint32(xid);
    reply.encode_uint32(static_cast<uint32_t>(RpcMsgType::REPLY));
    reply.encode_uint32(static_cast<uint32_t>(RpcReplyStatus::MSG_ACCEPTED));

    // Verifier with STARTTLS magic
    reply.encode_uint32(static_cast<uint32_t>(RpcAuthFlavor::AUTH_NONE));
    reply.encode_uint32(8);  // verifier body length
    const char starttls[8] = {'S','T','A','R','T','T','L','S'};
    reply.encode_opaque_fixed(starttls, 8);

    reply.encode_uint32(static_cast<uint32_t>(RpcAcceptStatus::SUCCESS));

    // NULL procedure has empty result — no body to append
    send_record(conn, reply.data().data(), reply.size());
}

// RFC 5531 §7.2 - accepted_reply (MSG_ACCEPTED + accept_stat + result)
void RpcServer::send_accepted_reply(ClientConnection& conn, uint32_t xid,
                                     RpcAcceptStatus status,
                                     const XdrEncoder& body) {
    XdrEncoder reply;
    reply.encode_uint32(xid);
    reply.encode_uint32(static_cast<uint32_t>(RpcMsgType::REPLY));
    reply.encode_uint32(static_cast<uint32_t>(RpcReplyStatus::MSG_ACCEPTED));

    // Verifier: AUTH_NONE
    reply.encode_uint32(static_cast<uint32_t>(RpcAuthFlavor::AUTH_NONE));
    reply.encode_uint32(0); // verifier body length

    reply.encode_uint32(static_cast<uint32_t>(status));

    // Append procedure reply body
    if (!body.data().empty()) {
        const auto& bdata = body.data();
        reply.encode_opaque_fixed(bdata.data(), bdata.size());
    }

    if (!send_record(conn, reply.data().data(), reply.size())) {
        std::cerr << "send_record failed for xid " << xid << std::endl;
    }
}

// RFC 5531 §7.2 - rejected_reply (MSG_DENIED + reject_stat)
void RpcServer::send_denied_reply(ClientConnection& conn, uint32_t xid,
                                   RpcRejectStatus reject_stat,
                                   uint32_t low_ver, uint32_t high_ver) {
    XdrEncoder reply;
    reply.encode_uint32(xid);
    reply.encode_uint32(static_cast<uint32_t>(RpcMsgType::REPLY));
    reply.encode_uint32(static_cast<uint32_t>(RpcReplyStatus::MSG_DENIED));
    reply.encode_uint32(static_cast<uint32_t>(reject_stat));
    if (reject_stat == RpcRejectStatus::RPC_MISMATCH) {
        reply.encode_uint32(low_ver);
        reply.encode_uint32(high_ver);
    }

    if (!send_record(conn, reply.data().data(), reply.size())) {
        std::cerr << "send_record failed for xid " << xid << std::endl;
    }
}

// RFC 5531 §11 - Send with TCP record marking (last-fragment bit set)
bool RpcServer::send_record(ClientConnection& conn, const uint8_t* data, size_t len) {
    uint32_t hdr = htonl(static_cast<uint32_t>(len) | 0x80000000);
    if (!conn.write_all(&hdr, 4)) return false;
    return conn.write_all(data, len);
}
