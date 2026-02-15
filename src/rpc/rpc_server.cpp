#include "rpc/rpc_server.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

RpcServer::RpcServer() = default;

RpcServer::~RpcServer() {
    stop();
}

void RpcServer::register_program(uint32_t program, uint32_t version,
                                  RpcProgramHandlers handlers) {
    programs_[{program, version}] = std::move(handlers);
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
    while (running_) {
        std::vector<uint8_t> record;
        bool complete = false;

        while (!complete) {
            uint8_t hdr[4];
            ssize_t n = recv(client_fd, hdr, 4, MSG_WAITALL);
            if (n <= 0) { close(client_fd); return; }

            uint32_t raw = (static_cast<uint32_t>(hdr[0]) << 24) |
                           (static_cast<uint32_t>(hdr[1]) << 16) |
                           (static_cast<uint32_t>(hdr[2]) << 8) |
                           static_cast<uint32_t>(hdr[3]);
            bool last_fragment = (raw & 0x80000000) != 0;
            uint32_t frag_len = raw & 0x7FFFFFFF;

            if (frag_len > 1024 * 1024) { close(client_fd); return; }

            size_t old_size = record.size();
            record.resize(old_size + frag_len);
            n = recv(client_fd, record.data() + old_size, frag_len, MSG_WAITALL);
            if (n <= 0) { close(client_fd); return; }

            complete = last_fragment;

            // Guard against unbounded accumulation
            if (record.size() > 16 * 1024 * 1024) { close(client_fd); return; }
        }

        process_rpc_message(record.data(), record.size(), client_fd);
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

// RFC 5531 §7 - RPC message dispatch (program/version/procedure lookup)
void RpcServer::process_rpc_message(const uint8_t* data, size_t len, int client_fd) {
    XdrDecoder dec(data, len);
    RpcCallHeader call;
    try {
        call = decode_call_header(dec);
    } catch (...) {
        return; // malformed, drop silently
    }

    if (call.rpc_version != 2) {
        send_denied_reply(client_fd, call.xid, RpcRejectStatus::RPC_MISMATCH, 2, 2);
        return;
    }

    auto it = programs_.find({call.program, call.version});
    if (it == programs_.end()) {
        XdrEncoder body;
        send_accepted_reply(client_fd, call.xid, RpcAcceptStatus::PROG_UNAVAIL, body);
        return;
    }

    auto proc_it = it->second.procedures.find(call.procedure);
    if (proc_it == it->second.procedures.end()) {
        XdrEncoder body;
        send_accepted_reply(client_fd, call.xid, RpcAcceptStatus::PROC_UNAVAIL, body);
        return;
    }

    XdrEncoder reply_body;
    try {
        proc_it->second(call, dec, reply_body);
    } catch (const std::exception& e) {
        std::cerr << "RPC procedure error: " << e.what() << std::endl;
        XdrEncoder err_body;
        send_accepted_reply(client_fd, call.xid, RpcAcceptStatus::SYSTEM_ERR, err_body);
        return;
    }

    send_accepted_reply(client_fd, call.xid, RpcAcceptStatus::SUCCESS, reply_body);
}

// RFC 5531 §7.2 - accepted_reply (MSG_ACCEPTED + accept_stat + result)
void RpcServer::send_accepted_reply(int fd, uint32_t xid,
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

    if (!send_tcp(fd, reply.data().data(), reply.size())) {
        std::cerr << "send_tcp failed for xid " << xid << std::endl;
    }
}

// RFC 5531 §7.2 - rejected_reply (MSG_DENIED + reject_stat)
void RpcServer::send_denied_reply(int fd, uint32_t xid,
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

    if (!send_tcp(fd, reply.data().data(), reply.size())) {
        std::cerr << "send_tcp failed for xid " << xid << std::endl;
    }
}

// RFC 5531 §11 - Send with TCP record marking (last-fragment bit set)
bool RpcServer::send_tcp(int fd, const uint8_t* data, size_t len) {
    uint32_t hdr = htonl(static_cast<uint32_t>(len) | 0x80000000);
    if (send(fd, &hdr, 4, MSG_NOSIGNAL) != 4) return false;
    ssize_t sent = send(fd, data, len, MSG_NOSIGNAL);
    return sent == static_cast<ssize_t>(len);
}
