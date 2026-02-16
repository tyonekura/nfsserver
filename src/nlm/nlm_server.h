#pragma once

#include "rpc/rpc_server.h"
#include "locking/lock_table.h"
#include "nlm/nlm_types.h"
#include <mutex>
#include <set>
#include <string>

class NlmServer {
public:
    NlmServer(ByteRangeLockTable& lock_table, std::mutex& lock_mu);

    // Returns RPC handlers to register with RpcServer.
    RpcProgramHandlers get_handlers();

private:
    void proc_null(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_test(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_lock(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_cancel(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_unlock(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_free_all(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);

    // XDR decode helpers
    NlmLock decode_nlm4_lock(XdrDecoder& dec);
    std::vector<uint8_t> decode_cookie(XdrDecoder& dec);

    // Build a lock owner key for the shared table
    static LockOwnerKey make_nlm_key(const NlmLock& lock);

    // Convert NLM length (0 = EOF) to lock table length (UINT64_MAX = EOF)
    static uint64_t nlm_length(uint64_t len);

    ByteRangeLockTable& lock_table_;
    std::mutex& lock_mu_;  // shared with Nfs4StateManager
};
