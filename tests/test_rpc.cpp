#include <gtest/gtest.h>
#include "rpc/rpc_server.h"
#include "rpc/rpc_types.h"

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
