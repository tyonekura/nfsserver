#include "nlm/nlm_server.h"
#include <sstream>

NlmServer::NlmServer(ByteRangeLockTable& lock_table, std::mutex& lock_mu)
    : lock_table_(lock_table), lock_mu_(lock_mu) {}

RpcProgramHandlers NlmServer::get_handlers() {
    RpcProgramHandlers h;
    h.procedures[NLMPROC4_NULL] = [this](auto& c, auto& a, auto& r) { proc_null(c, a, r); };
    h.procedures[NLMPROC4_TEST] = [this](auto& c, auto& a, auto& r) { proc_test(c, a, r); };
    h.procedures[NLMPROC4_LOCK] = [this](auto& c, auto& a, auto& r) { proc_lock(c, a, r); };
    h.procedures[NLMPROC4_CANCEL] = [this](auto& c, auto& a, auto& r) { proc_cancel(c, a, r); };
    h.procedures[NLMPROC4_UNLOCK] = [this](auto& c, auto& a, auto& r) { proc_unlock(c, a, r); };
    h.procedures[NLMPROC4_FREE_ALL] = [this](auto& c, auto& a, auto& r) { proc_free_all(c, a, r); };
    return h;
}

LockOwnerKey NlmServer::make_nlm_key(const NlmLock& lock) {
    std::ostringstream oss;
    oss << "nlm:" << lock.caller_name << ":" << lock.svid;
    return oss.str();
}

uint64_t NlmServer::nlm_length(uint64_t len) {
    // NLM convention: length=0 means "to EOF"
    // Lock table convention: UINT64_MAX means "to EOF"
    return (len == 0) ? UINT64_MAX : len;
}

std::vector<uint8_t> NlmServer::decode_cookie(XdrDecoder& dec) {
    return dec.decode_opaque();
}

NlmLock NlmServer::decode_nlm4_lock(XdrDecoder& dec) {
    NlmLock lock;
    lock.caller_name = dec.decode_string();
    // fh is variable-length opaque (fh3)
    auto fh_data = dec.decode_opaque();
    if (fh_data.size() <= sizeof(lock.fh.data)) {
        std::memcpy(lock.fh.data, fh_data.data(), fh_data.size());
        lock.fh.len = fh_data.size();
    }
    lock.oh = dec.decode_opaque();
    lock.svid = dec.decode_uint32();
    lock.offset = dec.decode_uint64();
    lock.length = dec.decode_uint64();
    return lock;
}

// NLMPROC4_NULL — do nothing
void NlmServer::proc_null(const RpcCallHeader&, XdrDecoder&, XdrEncoder&) {
}

// NLMPROC4_TEST — test for lock conflict
void NlmServer::proc_test(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    auto cookie = decode_cookie(args);
    bool exclusive = args.decode_bool();
    NlmLock lock = decode_nlm4_lock(args);

    // Encode cookie in reply
    reply.encode_opaque(cookie.data(), cookie.size());

    std::lock_guard<std::mutex> lk(lock_mu_);

    LockOwnerKey key = make_nlm_key(lock);
    LockConflict conflict;
    if (lock_table_.test(lock.fh, key, exclusive,
                         lock.offset, nlm_length(lock.length), conflict)) {
        // nlm4_testrply: denied
        reply.encode_uint32(static_cast<uint32_t>(NlmStat::LCK_DENIED));
        // nlm4_holder
        reply.encode_bool(conflict.exclusive);
        reply.encode_uint32(0);  // svid (unknown for cross-protocol)
        reply.encode_opaque(nullptr, 0);  // oh (empty)
        reply.encode_uint64(conflict.offset);
        uint64_t len = (conflict.length == UINT64_MAX) ? 0 : conflict.length;
        reply.encode_uint64(len);
    } else {
        reply.encode_uint32(static_cast<uint32_t>(NlmStat::LCK_GRANTED));
    }
}

// NLMPROC4_LOCK — acquire a lock
void NlmServer::proc_lock(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    auto cookie = decode_cookie(args);
    bool block = args.decode_bool();
    bool exclusive = args.decode_bool();
    NlmLock lock = decode_nlm4_lock(args);
    /*bool reclaim =*/ args.decode_bool();
    /*uint32_t state =*/ args.decode_uint32();

    reply.encode_opaque(cookie.data(), cookie.size());

    std::lock_guard<std::mutex> lk(lock_mu_);

    LockOwnerKey key = make_nlm_key(lock);
    LockConflict conflict;
    if (lock_table_.acquire(lock.fh, key, exclusive,
                            lock.offset, nlm_length(lock.length), conflict)) {
        reply.encode_uint32(static_cast<uint32_t>(NlmStat::LCK_GRANTED));
    } else {
        // Sync-only mode: if block=true, return LCK_BLOCKED (client will retry)
        // If block=false, return LCK_DENIED
        if (block)
            reply.encode_uint32(static_cast<uint32_t>(NlmStat::LCK_BLOCKED));
        else
            reply.encode_uint32(static_cast<uint32_t>(NlmStat::LCK_DENIED));
    }
}

// NLMPROC4_CANCEL — cancel a blocked lock request
void NlmServer::proc_cancel(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    auto cookie = decode_cookie(args);
    /*bool block =*/ args.decode_bool();
    /*bool exclusive =*/ args.decode_bool();
    NlmLock lock = decode_nlm4_lock(args);

    reply.encode_opaque(cookie.data(), cookie.size());
    // Sync-only mode: nothing to cancel (we don't queue blocked requests)
    reply.encode_uint32(static_cast<uint32_t>(NlmStat::LCK_GRANTED));
}

// NLMPROC4_UNLOCK — release a lock
void NlmServer::proc_unlock(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    auto cookie = decode_cookie(args);
    NlmLock lock = decode_nlm4_lock(args);

    reply.encode_opaque(cookie.data(), cookie.size());

    std::lock_guard<std::mutex> lk(lock_mu_);

    LockOwnerKey key = make_nlm_key(lock);
    lock_table_.release(lock.fh, key, lock.offset, nlm_length(lock.length));
    reply.encode_uint32(static_cast<uint32_t>(NlmStat::LCK_GRANTED));
}

// NLMPROC4_FREE_ALL — release all locks for a client (crash recovery)
void NlmServer::proc_free_all(const RpcCallHeader&, XdrDecoder& args, XdrEncoder&) {
    std::string name = args.decode_string();
    /*uint32_t state =*/ args.decode_uint32();

    std::lock_guard<std::mutex> lk(lock_mu_);

    // Release all locks with the "nlm:{name}:" prefix
    std::string prefix = "nlm:" + name + ":";
    lock_table_.release_all_matching(prefix);
}
