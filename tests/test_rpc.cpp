#include <gtest/gtest.h>
#include "rpc/rpc_server.h"
#include "rpc/rpc_types.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <chrono>

TEST(RpcTypes, AuthSysParse) {
    // Encode a fake AUTH_SYS body.
    XdrEncoder enc;
    enc.encode_uint32(12345);          // stamp
    enc.encode_string("testhost");     // machinename
    enc.encode_uint32(1000);           // uid
    enc.encode_uint32(1000);           // gid
    enc.encode_uint32(2);              // num gids
    enc.encode_uint32(100);
    enc.encode_uint32(200);

    RpcOpaqueAuth auth;
    auth.flavor = RpcAuthFlavor::AUTH_SYS;
    auth.body = std::vector<uint8_t>(enc.data().begin(), enc.data().end());

    auto sys = RpcServer::parse_auth_sys(auth);
    EXPECT_EQ(sys.stamp, 12345u);
    EXPECT_EQ(sys.machinename, "testhost");
    EXPECT_EQ(sys.uid, 1000u);
    EXPECT_EQ(sys.gid, 1000u);
    ASSERT_EQ(sys.gids.size(), 2u);
    EXPECT_EQ(sys.gids[0], 100u);
    EXPECT_EQ(sys.gids[1], 200u);
}

TEST(RpcTypes, ProgramConstants) {
    EXPECT_EQ(NFS_PROGRAM, 100003u);
    EXPECT_EQ(NFS_V3, 3u);
    EXPECT_EQ(MOUNT_PROGRAM, 100005u);
    EXPECT_EQ(MOUNT_V3, 3u);
}

// Helper: build an RPC CALL record with given rpc_version, program, version, procedure
static std::vector<uint8_t> make_rpc_call(uint32_t xid, uint32_t rpc_ver,
                                           uint32_t prog, uint32_t ver,
                                           uint32_t proc) {
    XdrEncoder enc;
    enc.encode_uint32(xid);
    enc.encode_uint32(static_cast<uint32_t>(RpcMsgType::CALL));
    enc.encode_uint32(rpc_ver);
    enc.encode_uint32(prog);
    enc.encode_uint32(ver);
    enc.encode_uint32(proc);
    // AUTH_NONE credential
    enc.encode_uint32(0); // flavor
    enc.encode_uint32(0); // body length
    // AUTH_NONE verifier
    enc.encode_uint32(0);
    enc.encode_uint32(0);
    return std::vector<uint8_t>(enc.data().begin(), enc.data().end());
}

// Helper: wrap data as a TCP record marking frame (single fragment, last=true)
static std::vector<uint8_t> frame_record(const std::vector<uint8_t>& data) {
    uint32_t hdr = htonl(static_cast<uint32_t>(data.size()) | 0x80000000u);
    std::vector<uint8_t> framed(4 + data.size());
    std::memcpy(framed.data(), &hdr, 4);
    std::memcpy(framed.data() + 4, data.data(), data.size());
    return framed;
}

// Helper: read a full TCP-framed RPC reply from a socket
static std::vector<uint8_t> read_reply(int fd) {
    uint8_t hdr[4];
    ssize_t n = recv(fd, hdr, 4, MSG_WAITALL);
    if (n != 4) return {};
    uint32_t raw = (uint32_t(hdr[0]) << 24) | (uint32_t(hdr[1]) << 16) |
                   (uint32_t(hdr[2]) << 8) | uint32_t(hdr[3]);
    uint32_t len = raw & 0x7FFFFFFF;
    std::vector<uint8_t> buf(len);
    n = recv(fd, buf.data(), len, MSG_WAITALL);
    if (n != static_cast<ssize_t>(len)) return {};
    return buf;
}

TEST(RpcServer, RpcVersionMismatchSendsDenied) {
    RpcServer server;
    // Register a dummy program so the server has something
    RpcProgramHandlers handlers;
    handlers.procedures[0] = [](const RpcCallHeader&, XdrDecoder&, XdrEncoder&) {};
    server.register_program(100003, 3, std::move(handlers));
    server.start(0); // port 0 = let OS choose

    // We need to find the actual port. Use getsockname trick — but we don't
    // have access to listen_fd_. Instead, try a range. Actually, let's use
    // a fixed high port.
    server.stop();

    // Use a fixed port for testing
    uint16_t port = 19321;
    RpcServer server2;
    RpcProgramHandlers handlers2;
    handlers2.procedures[0] = [](const RpcCallHeader&, XdrDecoder&, XdrEncoder&) {};
    server2.register_program(100003, 3, std::move(handlers2));
    server2.start(port);

    // Connect
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(fd, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    // Send an RPC call with rpc_version=1 (invalid)
    auto call = make_rpc_call(0x42, 1, 100003, 3, 0);
    auto framed = frame_record(call);
    send(fd, framed.data(), framed.size(), 0);

    // Read reply
    auto reply = read_reply(fd);
    ASSERT_GE(reply.size(), 24u);

    XdrDecoder dec(reply.data(), reply.size());
    EXPECT_EQ(dec.decode_uint32(), 0x42u);        // xid
    EXPECT_EQ(dec.decode_uint32(), 1u);            // REPLY
    EXPECT_EQ(dec.decode_uint32(), 1u);            // MSG_DENIED
    EXPECT_EQ(dec.decode_uint32(), 0u);            // RPC_MISMATCH
    EXPECT_EQ(dec.decode_uint32(), 2u);            // low version
    EXPECT_EQ(dec.decode_uint32(), 2u);            // high version

    close(fd);
    server2.stop();
}

TEST(RpcServer, MultiFragmentReassembly) {
    uint16_t port = 19322;
    RpcServer server;
    // Register a NULL procedure that just succeeds
    RpcProgramHandlers handlers;
    handlers.procedures[0] = [](const RpcCallHeader&, XdrDecoder&, XdrEncoder&) {};
    server.register_program(100003, 3, std::move(handlers));
    server.start(port);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(fd, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    // Build a valid RPC call
    auto call = make_rpc_call(0x99, 2, 100003, 3, 0);

    // Split into two fragments
    size_t split = call.size() / 2;
    // Fragment 1: first half, last_fragment=false
    uint32_t hdr1 = htonl(static_cast<uint32_t>(split) & 0x7FFFFFFF);
    send(fd, &hdr1, 4, 0);
    send(fd, call.data(), split, 0);

    // Fragment 2: second half, last_fragment=true
    uint32_t remain = static_cast<uint32_t>(call.size() - split);
    uint32_t hdr2 = htonl(remain | 0x80000000u);
    send(fd, &hdr2, 4, 0);
    send(fd, call.data() + split, remain, 0);

    // Read reply — should get a valid accepted reply
    auto reply = read_reply(fd);
    ASSERT_GE(reply.size(), 24u);

    XdrDecoder dec(reply.data(), reply.size());
    EXPECT_EQ(dec.decode_uint32(), 0x99u);         // xid
    EXPECT_EQ(dec.decode_uint32(), 1u);             // REPLY
    EXPECT_EQ(dec.decode_uint32(), 0u);             // MSG_ACCEPTED
    dec.decode_uint32(); // verifier flavor
    dec.decode_uint32(); // verifier length
    EXPECT_EQ(dec.decode_uint32(), 0u);             // SUCCESS

    close(fd);
    server.stop();
}

TEST(RpcServer, SendTcpErrorHandling) {
    // Verify send_tcp returns false on a closed fd
    // We test indirectly: a server should handle send failures gracefully
    // by not crashing. This is a basic smoke test.
    RpcServer server;
    RpcProgramHandlers handlers;
    handlers.procedures[0] = [](const RpcCallHeader&, XdrDecoder&, XdrEncoder&) {};
    server.register_program(100003, 3, std::move(handlers));

    uint16_t port = 19323;
    server.start(port);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(fd, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    // Send a valid call, then immediately close our end before reading reply
    auto call = make_rpc_call(0xAA, 2, 100003, 3, 0);
    auto framed = frame_record(call);
    send(fd, framed.data(), framed.size(), 0);
    close(fd);

    // Give server time to process and attempt the send (which should fail gracefully)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Server should still be running fine
    server.stop();
    // If we get here without crash/hang, the test passes
}
