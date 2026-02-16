#include "nfs4/nfs4_callback.h"
#include "xdr/xdr_codec.h"

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>

bool parse_universal_addr(const std::string& r_addr,
                          std::string& out_host,
                          uint16_t& out_port) {
    // Split by '.'
    std::vector<std::string> parts;
    std::istringstream iss(r_addr);
    std::string token;
    while (std::getline(iss, token, '.')) {
        parts.push_back(token);
    }
    if (parts.size() != 6) return false;

    out_host = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3];

    unsigned long p1, p2;
    try {
        p1 = std::stoul(parts[4]);
        p2 = std::stoul(parts[5]);
    } catch (...) {
        return false;
    }
    if (p1 > 255 || p2 > 255) return false;

    out_port = static_cast<uint16_t>(p1 * 256 + p2);
    return true;
}

// Open TCP connection to callback address with timeout
static int connect_callback(const Nfs4CallbackInfo& cb, int timeout_sec) {
    std::string host;
    uint16_t port;
    if (!parse_universal_addr(cb.r_addr, host, port)) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int nodelay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// Send data with TCP record marking (last-fragment bit set)
static bool send_record(int fd, const uint8_t* data, size_t len) {
    uint32_t hdr = htonl(static_cast<uint32_t>(len) | 0x80000000);
    if (send(fd, &hdr, 4, MSG_NOSIGNAL) != 4) return false;
    ssize_t sent = send(fd, data, len, MSG_NOSIGNAL);
    return sent == static_cast<ssize_t>(len);
}

// Receive one complete RPC record (reassemble fragments)
static bool recv_record(int fd, std::vector<uint8_t>& out) {
    out.clear();
    for (;;) {
        uint8_t hdr_buf[4];
        size_t got = 0;
        while (got < 4) {
            ssize_t n = recv(fd, hdr_buf + got, 4 - got, 0);
            if (n <= 0) return false;
            got += n;
        }
        uint32_t hdr = ntohl(*reinterpret_cast<uint32_t*>(hdr_buf));
        bool last = (hdr & 0x80000000) != 0;
        uint32_t frag_len = hdr & 0x7FFFFFFF;
        if (frag_len > 1024 * 1024) return false;  // sanity limit

        size_t old_size = out.size();
        out.resize(old_size + frag_len);
        size_t read_so_far = 0;
        while (read_so_far < frag_len) {
            ssize_t n = recv(fd, out.data() + old_size + read_so_far,
                             frag_len - read_so_far, 0);
            if (n <= 0) return false;
            read_so_far += n;
        }
        if (last) break;
    }
    return true;
}

// Encode RPC CALL header with AUTH_NONE
static void encode_rpc_call(XdrEncoder& enc, uint32_t xid,
                            uint32_t program, uint32_t version,
                            uint32_t procedure) {
    enc.encode_uint32(xid);
    enc.encode_uint32(0);  // CALL
    enc.encode_uint32(2);  // rpcvers
    enc.encode_uint32(program);
    enc.encode_uint32(version);
    enc.encode_uint32(procedure);
    // AUTH_NONE credentials
    enc.encode_uint32(0);  // flavor = AUTH_NONE
    enc.encode_uint32(0);  // length = 0
    // AUTH_NONE verifier
    enc.encode_uint32(0);
    enc.encode_uint32(0);
}

static constexpr uint32_t NFS4_CB_VERSION = 1;

bool cb_null_probe(const Nfs4CallbackInfo& cb, uint32_t xid) {
    int fd = connect_callback(cb, 5);
    if (fd < 0) return false;

    XdrEncoder enc;
    encode_rpc_call(enc, xid, cb.cb_program, NFS4_CB_VERSION, CB_NULL);

    bool ok = send_record(fd, enc.data().data(), enc.size());
    if (!ok) { close(fd); return false; }

    std::vector<uint8_t> reply;
    ok = recv_record(fd, reply);
    close(fd);

    if (!ok || reply.size() < 24) return false;

    // Verify: xid match, REPLY(1), MSG_ACCEPTED(0), accept_stat SUCCESS(0)
    XdrDecoder dec(reply.data(), reply.size());
    uint32_t reply_xid = dec.decode_uint32();
    uint32_t msg_type = dec.decode_uint32();
    if (reply_xid != xid || msg_type != 1) return false;

    // Skip verifier (flavor + opaque)
    dec.decode_uint32();  // verf flavor
    dec.decode_opaque();  // verf data
    uint32_t accept_stat = dec.decode_uint32();

    return accept_stat == 0;  // SUCCESS
}

bool cb_recall(const Nfs4CallbackInfo& cb,
               uint32_t xid,
               const Nfs4StateId& stateid,
               bool truncate,
               const FileHandle& fh,
               int timeout_ms) {
    int fd = connect_callback(cb, (timeout_ms / 1000) + 1);
    if (fd < 0) return false;

    XdrEncoder enc;
    encode_rpc_call(enc, xid, cb.cb_program, NFS4_CB_VERSION, CB_COMPOUND);

    // CB_COMPOUND4args: tag, minorversion, callback_ident, num_ops
    enc.encode_string("");              // tag
    enc.encode_uint32(0);              // minorversion
    enc.encode_uint32(cb.callback_ident);
    enc.encode_uint32(1);              // num_ops = 1

    // OP_CB_RECALL
    enc.encode_uint32(OP_CB_RECALL);
    // stateid4
    enc.encode_uint32(stateid.seqid);
    enc.encode_opaque_fixed(stateid.other, 12);
    // truncate
    enc.encode_bool(truncate);
    // fh (nfs_fh4 = opaque<NFS4_FHSIZE>)
    enc.encode_opaque(fh.data, fh.len);

    bool ok = send_record(fd, enc.data().data(), enc.size());
    if (!ok) { close(fd); return false; }

    std::vector<uint8_t> reply;
    ok = recv_record(fd, reply);
    close(fd);

    if (!ok || reply.size() < 24) return false;

    // Verify reply
    XdrDecoder dec(reply.data(), reply.size());
    uint32_t reply_xid = dec.decode_uint32();
    uint32_t msg_type = dec.decode_uint32();
    if (reply_xid != xid || msg_type != 1) return false;

    // Skip verifier
    dec.decode_uint32();
    dec.decode_opaque();
    uint32_t accept_stat = dec.decode_uint32();
    if (accept_stat != 0) return false;

    // CB_COMPOUND4res: status, tag, num_resops
    uint32_t status = dec.decode_uint32();
    return status == 0;  // NFS4_OK
}
