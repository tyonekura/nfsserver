#pragma once

#include <cstdint>
#include <string>
#include <vector>

// ONC RPC v2 types per RFC 5531

enum class RpcMsgType : uint32_t {
    CALL  = 0,
    REPLY = 1
};

enum class RpcAuthFlavor : uint32_t {
    AUTH_NONE = 0,
    AUTH_SYS  = 1,
};

enum class RpcReplyStatus : uint32_t {
    MSG_ACCEPTED = 0,
    MSG_DENIED   = 1
};

enum class RpcAcceptStatus : uint32_t {
    SUCCESS       = 0,
    PROG_UNAVAIL  = 1,
    PROG_MISMATCH = 2,
    PROC_UNAVAIL  = 3,
    GARBAGE_ARGS  = 4,
    SYSTEM_ERR    = 5
};

enum class RpcRejectStatus : uint32_t {
    RPC_MISMATCH = 0,
    AUTH_ERROR    = 1
};

struct RpcOpaqueAuth {
    RpcAuthFlavor flavor = RpcAuthFlavor::AUTH_NONE;
    std::vector<uint8_t> body;
};

struct RpcAuthSys {
    uint32_t stamp = 0;
    std::string machinename;
    uint32_t uid = 0;
    uint32_t gid = 0;
    std::vector<uint32_t> gids;
};

struct RpcCallHeader {
    uint32_t xid = 0;
    uint32_t rpc_version = 2;
    uint32_t program = 0;
    uint32_t version = 0;
    uint32_t procedure = 0;
    RpcOpaqueAuth credential;
    RpcOpaqueAuth verifier;
};

// NFS program numbers
constexpr uint32_t NFS_PROGRAM   = 100003;
constexpr uint32_t NFS_V3        = 3;
constexpr uint32_t MOUNT_PROGRAM = 100005;
constexpr uint32_t MOUNT_V3      = 3;
