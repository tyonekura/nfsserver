#include "rpc/portmapper.h"
#include "rpc/rpc_types.h"
#include "nfs4/nfs4_types.h"
#include "nlm/nlm_types.h"
#include "xdr/xdr_codec.h"

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

// Connect to local portmapper (127.0.0.1:111) with timeout
static int connect_portmapper(int timeout_sec) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(111);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// Send data with TCP record marking (last-fragment bit set)
static bool send_record(int fd, const uint8_t* data, size_t len) {
    uint32_t hdr = htonl(static_cast<uint32_t>(len) | 0x80000000);
    if (send(fd, &hdr, 4, 0) != 4) return false;
    ssize_t sent = send(fd, data, len, 0);
    return sent == static_cast<ssize_t>(len);
}

// Receive one complete RPC record
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
        if (frag_len > 1024 * 1024) return false;

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
    enc.encode_uint32(0);
    enc.encode_uint32(0);
    // AUTH_NONE verifier
    enc.encode_uint32(0);
    enc.encode_uint32(0);
}

// Common portmapper SET/UNSET call
static bool pmap_call(uint32_t procedure, uint32_t program,
                      uint32_t version, uint32_t protocol, uint32_t port) {
    int fd = connect_portmapper(2);
    if (fd < 0) return false;

    XdrEncoder enc;
    static uint32_t xid = 1;
    encode_rpc_call(enc, xid++, PMAP_PROGRAM, PMAP_VERSION, procedure);

    // mapping: {program, version, protocol, port}
    enc.encode_uint32(program);
    enc.encode_uint32(version);
    enc.encode_uint32(protocol);
    enc.encode_uint32(port);

    bool ok = send_record(fd, enc.data().data(), enc.size());
    if (!ok) { close(fd); return false; }

    std::vector<uint8_t> reply;
    ok = recv_record(fd, reply);
    close(fd);

    if (!ok || reply.size() < 28) return false;

    // RPC reply: xid, REPLY(1), reply_stat(0=ACCEPTED), verifier, accept_stat, result
    XdrDecoder dec(reply.data(), reply.size());
    dec.decode_uint32();  // xid
    uint32_t msg_type = dec.decode_uint32();
    if (msg_type != 1) return false;
    uint32_t reply_stat = dec.decode_uint32();
    if (reply_stat != 0) return false;  // MSG_ACCEPTED

    // Skip verifier
    dec.decode_uint32();  // verf flavor
    dec.decode_opaque();  // verf data
    uint32_t accept_stat = dec.decode_uint32();
    if (accept_stat != 0) return false;

    // Result: bool (uint32)
    uint32_t result = dec.decode_uint32();
    return result != 0;
}

bool pmap_register(uint32_t program, uint32_t version, uint16_t port) {
    return pmap_call(PMAPPROC_SET, program, version, IPPROTO_TCP_PMAP, port);
}

bool pmap_unregister(uint32_t program, uint32_t version) {
    return pmap_call(PMAPPROC_UNSET, program, version, IPPROTO_TCP_PMAP, 0);
}

void pmap_register_all(uint16_t port) {
    struct { uint32_t prog; uint32_t ver; const char* name; } entries[] = {
        {NFS_PROGRAM,   NFS_V3,    "NFS v3"},
        {NFS_PROGRAM,   NFS_V4,    "NFS v4"},
        {MOUNT_PROGRAM, MOUNT_V3,  "MOUNT v3"},
        {NLM_PROGRAM,   NLM_V4,    "NLM v4"},
    };

    // Retry a few times in case rpcbind is still starting
    bool registered = false;
    for (int attempt = 0; attempt < 5; attempt++) {
        if (pmap_register(entries[0].prog, entries[0].ver, port)) {
            registered = true;
            break;
        }
        std::cerr << "  Portmapper not ready, retrying in 1s...\n";
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    if (!registered) {
        std::cerr << "  Warning: could not register with portmapper"
                  << " (rpcbind may not be running)\n";
        return;
    }

    // First succeeded — register the rest
    for (size_t i = 1; i < sizeof(entries)/sizeof(entries[0]); i++)
        pmap_register(entries[i].prog, entries[i].ver, port);

    for (const auto& e : entries)
        std::cout << "  Registered " << e.name << " with portmapper\n";
}

void pmap_unregister_all() {
    struct { uint32_t prog; uint32_t ver; } entries[] = {
        {NFS_PROGRAM,   NFS_V3},
        {NFS_PROGRAM,   NFS_V4},
        {MOUNT_PROGRAM, MOUNT_V3},
        {NLM_PROGRAM,   NLM_V4},
    };

    for (const auto& e : entries) {
        pmap_unregister(e.prog, e.ver);
    }
}

uint16_t pmap_getport(uint32_t program, uint32_t version) {
    int fd = connect_portmapper(2);
    if (fd < 0) return 0;

    XdrEncoder enc;
    static uint32_t xid = 100;
    encode_rpc_call(enc, xid++, PMAP_PROGRAM, PMAP_VERSION, PMAPPROC_GETPORT);

    // mapping: {program, version, protocol, port(ignored)}
    enc.encode_uint32(program);
    enc.encode_uint32(version);
    enc.encode_uint32(IPPROTO_TCP_PMAP);
    enc.encode_uint32(0);

    bool ok = send_record(fd, enc.data().data(), enc.size());
    if (!ok) { close(fd); return 0; }

    std::vector<uint8_t> reply;
    ok = recv_record(fd, reply);
    close(fd);

    if (!ok || reply.size() < 28) return 0;

    XdrDecoder dec(reply.data(), reply.size());
    dec.decode_uint32();  // xid
    uint32_t msg_type = dec.decode_uint32();
    if (msg_type != 1) return 0;
    uint32_t reply_stat = dec.decode_uint32();
    if (reply_stat != 0) return 0;
    dec.decode_uint32();  // verf flavor
    dec.decode_opaque();  // verf data
    uint32_t accept_stat = dec.decode_uint32();
    if (accept_stat != 0) return 0;

    uint32_t port = dec.decode_uint32();
    return static_cast<uint16_t>(port);
}
