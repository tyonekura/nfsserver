#pragma once

#include <cstdint>
#include <string>
#include <vector>

// ONC RPC v2 types per RFC 5531

// RFC 5531 §7.1 - msg_type
enum class RpcMsgType : uint32_t {
    CALL  = 0,
    REPLY = 1
};

// RFC 5531 §8.2 - Authentication Flavors
enum class RpcAuthFlavor : uint32_t {
    AUTH_NONE = 0,   // RFC 5531 §8.2.1
    AUTH_SYS  = 1,   // RFC 5531 §8.2.2
};

// RFC 5531 §7.2 - reply_stat
enum class RpcReplyStatus : uint32_t {
    MSG_ACCEPTED = 0,
    MSG_DENIED   = 1
};

// RFC 5531 §7.2 - accept_stat
enum class RpcAcceptStatus : uint32_t {
    SUCCESS       = 0,
    PROG_UNAVAIL  = 1,
    PROG_MISMATCH = 2,
    PROC_UNAVAIL  = 3,
    GARBAGE_ARGS  = 4,
    SYSTEM_ERR    = 5
};

// RFC 5531 §7.2 - reject_stat
enum class RpcRejectStatus : uint32_t {
    RPC_MISMATCH = 0,
    AUTH_ERROR    = 1
};

// RFC 5531 §7.1 - opaque_auth
struct RpcOpaqueAuth {
    RpcAuthFlavor flavor = RpcAuthFlavor::AUTH_NONE;
    std::vector<uint8_t> body;
};

// RFC 5531 §8.2.2 - authsys_parms
struct RpcAuthSys {
    uint32_t stamp = 0;
    std::string machinename;
    uint32_t uid = 0;
    uint32_t gid = 0;
    std::vector<uint32_t> gids;
};

// RFC 5531 §7.1 - call_body
struct RpcCallHeader {
    uint32_t xid = 0;
    uint32_t rpc_version = 2;
    uint32_t program = 0;
    uint32_t version = 0;
    uint32_t procedure = 0;
    RpcOpaqueAuth credential;
    RpcOpaqueAuth verifier;
};

// RFC 1813 §3 - NFS program number and version
constexpr uint32_t NFS_PROGRAM   = 100003;
constexpr uint32_t NFS_V3        = 3;
// RFC 1813 Appendix I - MOUNT program number and version
constexpr uint32_t MOUNT_PROGRAM = 100005;
constexpr uint32_t MOUNT_V3      = 3;
