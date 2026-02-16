#include "nsm/nsm_client.h"
#include "rpc/portmapper.h"
#include "xdr/xdr_codec.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <vector>

NsmClient::NsmClient(ByteRangeLockTable& lock_table, std::mutex& lock_mu)
    : lock_table_(lock_table), lock_mu_(lock_mu) {}

// Connect to local statd on its discovered port
static int connect_statd(uint16_t port, int timeout_sec) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool send_record(int fd, const uint8_t* data, size_t len) {
    uint32_t hdr = htonl(static_cast<uint32_t>(len) | 0x80000000);
    if (send(fd, &hdr, 4, 0) != 4) return false;
    ssize_t sent = send(fd, data, len, 0);
    return sent == static_cast<ssize_t>(len);
}

static bool recv_record(int fd, std::vector<uint8_t>& out) {
    out.clear();
    uint8_t hdr_buf[4];
    size_t got = 0;
    while (got < 4) {
        ssize_t n = recv(fd, hdr_buf + got, 4 - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    uint32_t hdr = ntohl(*reinterpret_cast<uint32_t*>(hdr_buf));
    uint32_t frag_len = hdr & 0x7FFFFFFF;
    if (frag_len > 1024 * 1024) return false;

    out.resize(frag_len);
    size_t read_so_far = 0;
    while (read_so_far < frag_len) {
        ssize_t n = recv(fd, out.data() + read_so_far,
                         frag_len - read_so_far, 0);
        if (n <= 0) return false;
        read_so_far += n;
    }
    return true;
}

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

static bool decode_nsm_reply(const std::vector<uint8_t>& reply) {
    if (reply.size() < 28) return false;
    XdrDecoder dec(reply.data(), reply.size());
    dec.decode_uint32();  // xid
    uint32_t msg_type = dec.decode_uint32();
    if (msg_type != 1) return false;
    uint32_t reply_stat = dec.decode_uint32();
    if (reply_stat != 0) return false;
    dec.decode_uint32();  // verf flavor
    dec.decode_opaque();  // verf data
    uint32_t accept_stat = dec.decode_uint32();
    return accept_stat == 0;
}

bool NsmClient::monitor(const std::string& client_name,
                         const std::string& my_name,
                         uint32_t my_prog, uint32_t my_vers, uint32_t my_proc) {
    // Look up statd port via portmapper
    uint16_t port = pmap_getport(SM_PROGRAM, SM_VERSION);
    if (port == 0) {
        std::cerr << "  NSM: rpc.statd not registered with portmapper\n";
        return false;
    }

    int fd = connect_statd(port, 2);
    if (fd < 0) {
        std::cerr << "  NSM: cannot connect to rpc.statd on port " << port << "\n";
        return false;
    }

    static uint32_t xid = 200;
    XdrEncoder enc;
    encode_rpc_call(enc, xid++, SM_PROGRAM, SM_VERSION, SM_MON);

    // mon_id: mon_name + my_id
    enc.encode_string(client_name);  // mon_name
    enc.encode_string(my_name);      // my_id.my_name
    enc.encode_uint32(my_prog);      // my_id.my_prog
    enc.encode_uint32(my_vers);      // my_id.my_vers
    enc.encode_uint32(my_proc);      // my_id.my_proc
    // priv: 16 bytes opaque (unused)
    uint8_t priv[16] = {};
    enc.encode_opaque_fixed(priv, 16);

    bool ok = send_record(fd, enc.data().data(), enc.size());
    if (!ok) { close(fd); return false; }

    std::vector<uint8_t> reply;
    ok = recv_record(fd, reply);
    close(fd);

    if (!ok || !decode_nsm_reply(reply)) return false;

    std::lock_guard<std::mutex> lk(nsm_mu_);
    monitored_.insert(client_name);
    return true;
}

bool NsmClient::unmonitor(const std::string& client_name,
                           const std::string& my_name) {
    uint16_t port = pmap_getport(SM_PROGRAM, SM_VERSION);
    if (port == 0) return false;

    int fd = connect_statd(port, 2);
    if (fd < 0) return false;

    static uint32_t xid = 300;
    XdrEncoder enc;
    encode_rpc_call(enc, xid++, SM_PROGRAM, SM_VERSION, SM_UNMON);

    // mon_id
    enc.encode_string(client_name);
    enc.encode_string(my_name);
    enc.encode_uint32(0);  // my_prog (unused for unmon)
    enc.encode_uint32(0);
    enc.encode_uint32(0);

    bool ok = send_record(fd, enc.data().data(), enc.size());
    if (!ok) { close(fd); return false; }

    std::vector<uint8_t> reply;
    ok = recv_record(fd, reply);
    close(fd);

    std::lock_guard<std::mutex> lk(nsm_mu_);
    monitored_.erase(client_name);
    return ok;
}

bool NsmClient::unmonitor_all(const std::string& my_name) {
    uint16_t port = pmap_getport(SM_PROGRAM, SM_VERSION);
    if (port == 0) return false;

    int fd = connect_statd(port, 2);
    if (fd < 0) return false;

    static uint32_t xid = 400;
    XdrEncoder enc;
    encode_rpc_call(enc, xid++, SM_PROGRAM, SM_VERSION, SM_UNMON_ALL);

    enc.encode_string(my_name);
    enc.encode_uint32(0);
    enc.encode_uint32(0);
    enc.encode_uint32(0);

    bool ok = send_record(fd, enc.data().data(), enc.size());
    if (!ok) { close(fd); return false; }

    std::vector<uint8_t> reply;
    ok = recv_record(fd, reply);
    close(fd);

    std::lock_guard<std::mutex> lk(nsm_mu_);
    monitored_.clear();
    return ok;
}

void NsmClient::handle_notify(const std::string& client_name) {
    std::lock_guard<std::mutex> lk(lock_mu_);
    // Release all NLM locks for this client
    std::string prefix = "nlm:" + client_name + ":";
    lock_table_.release_all_matching(prefix);

    std::lock_guard<std::mutex> lk2(nsm_mu_);
    monitored_.erase(client_name);
}

bool NsmClient::is_monitored(const std::string& client_name) {
    std::lock_guard<std::mutex> lk(nsm_mu_);
    return monitored_.count(client_name) > 0;
}
