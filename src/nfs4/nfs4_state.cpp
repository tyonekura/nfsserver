#include "nfs4/nfs4_state.h"
#include <algorithm>
#include <cstring>
#include <random>
#include <thread>

// RFC 7530 - NFSv4 state management

Nfs4StateManager::Nfs4StateManager() {
    reaper_thread_ = std::thread(&Nfs4StateManager::reaper_loop, this);
}

Nfs4StateManager::~Nfs4StateManager() {
    reaper_running_ = false;
    if (reaper_thread_.joinable())
        reaper_thread_.join();
}

// RFC 7530 §9.6 - Lease expiry reaper thread
void Nfs4StateManager::reaper_loop() {
    while (reaper_running_) {
        // Sleep in 1-second increments to allow quick shutdown
        for (int i = 0; i < 30 && reaper_running_; i++)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!reaper_running_) break;
        expire_clients();
    }
}

void Nfs4StateManager::expire_clients() {
    std::lock_guard<std::mutex> lk(mu_);
    auto now = std::chrono::steady_clock::now();
    auto lease = std::chrono::seconds(NFS4_LEASE_TIME);

    std::vector<uint64_t> expired;
    for (auto& [cid, client] : clients_) {
        if (client.confirmed && (now - client.last_renewed) > lease) {
            expired.push_back(cid);
        }
    }

    for (uint64_t cid : expired) {
        // Remove all delegation state for this client
        deleg_states_.erase(
            std::remove_if(deleg_states_.begin(), deleg_states_.end(),
                [cid](const Nfs4DelegState& ds) { return ds.clientid == cid; }),
            deleg_states_.end());

        // Remove all lock state for this client
        lock_states_.erase(
            std::remove_if(lock_states_.begin(), lock_states_.end(),
                [cid](const Nfs4LockState& ls) { return ls.clientid == cid; }),
            lock_states_.end());

        // Remove all open state for this client
        open_states_.erase(
            std::remove_if(open_states_.begin(), open_states_.end(),
                [cid](const Nfs4OpenState& os) { return os.clientid == cid; }),
            open_states_.end());

        // Remove client_id mapping
        auto& client = clients_[cid];
        client_id_to_clientid_.erase(client.client_id);

        // Remove client
        clients_.erase(cid);
    }
}

void Nfs4StateManager::gen_stateid_other(uint8_t out[12]) {
    std::memset(out, 0, 12);
    uint64_t val = next_state_counter_++;
    std::memcpy(out, &val, sizeof(val));
}

bool Nfs4StateManager::is_special_stateid(const Nfs4StateId& sid) {
    // Anonymous stateid: all zeros
    static const uint8_t all_zero[12] = {};
    static const uint8_t all_ff[12] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                                        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    if (sid.seqid == 0 && std::memcmp(sid.other, all_zero, 12) == 0)
        return true;
    // READ bypass stateid: seqid=0, other=all 0xFF
    if (sid.seqid == 0 && std::memcmp(sid.other, all_ff, 12) == 0)
        return true;
    // Stateid with seqid=UINT32_MAX, other=all 0xFF (current stateid)
    if (sid.seqid == UINT32_MAX && std::memcmp(sid.other, all_ff, 12) == 0)
        return true;
    return false;
}

Nfs4OpenState* Nfs4StateManager::find_open_state(const Nfs4StateId& sid) {
    for (auto& os : open_states_) {
        if (std::memcmp(os.stateid.other, sid.other, 12) == 0)
            return &os;
    }
    return nullptr;
}

// RFC 7530 §16.33 - SETCLIENTID
std::pair<uint64_t, std::array<uint8_t, 8>>
Nfs4StateManager::set_clientid(const uint8_t verifier[8],
                                const std::vector<uint8_t>& client_id,
                                const Nfs4CallbackInfo& cb) {
    std::lock_guard<std::mutex> lk(mu_);

    // Check if this client_id already exists
    auto it = client_id_to_clientid_.find(client_id);
    if (it != client_id_to_clientid_.end()) {
        auto& client = clients_[it->second];
        // Update verifier, generate new confirm verifier
        std::memcpy(client.verifier, verifier, 8);
        client.confirmed = false;
        client.cb_info = cb;

        // Generate new confirm verifier
        std::random_device rd;
        uint32_t r1 = rd(), r2 = rd();
        std::memcpy(client.confirm_verifier, &r1, 4);
        std::memcpy(client.confirm_verifier + 4, &r2, 4);

        client.last_renewed = std::chrono::steady_clock::now();

        std::array<uint8_t, 8> cv;
        std::memcpy(cv.data(), client.confirm_verifier, 8);
        return {client.clientid, cv};
    }

    // New client
    Nfs4Client c;
    c.clientid = next_clientid_++;
    std::memcpy(c.verifier, verifier, 8);
    c.client_id = client_id;
    c.confirmed = false;
    c.cb_info = cb;
    c.last_renewed = std::chrono::steady_clock::now();

    // Generate confirm verifier
    std::random_device rd;
    uint32_t r1 = rd(), r2 = rd();
    std::memcpy(c.confirm_verifier, &r1, 4);
    std::memcpy(c.confirm_verifier + 4, &r2, 4);

    std::array<uint8_t, 8> cv;
    std::memcpy(cv.data(), c.confirm_verifier, 8);

    client_id_to_clientid_[client_id] = c.clientid;
    clients_[c.clientid] = std::move(c);

    return {clients_.rbegin()->second.clientid, cv};
}

// RFC 7530 §16.34 - SETCLIENTID_CONFIRM
Nfs4Stat Nfs4StateManager::confirm_clientid(uint64_t clientid,
                                              const uint8_t confirm[8]) {
    std::lock_guard<std::mutex> lk(mu_);

    auto it = clients_.find(clientid);
    if (it == clients_.end())
        return Nfs4Stat::NFS4ERR_STALE_CLIENTID;

    if (std::memcmp(it->second.confirm_verifier, confirm, 8) != 0)
        return Nfs4Stat::NFS4ERR_STALE_CLIENTID;

    it->second.confirmed = true;
    it->second.last_renewed = std::chrono::steady_clock::now();
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.16 - OPEN
Nfs4Stat Nfs4StateManager::open_file(uint64_t clientid,
                                      const std::vector<uint8_t>& owner,
                                      uint32_t seqid,
                                      const FileHandle& fh,
                                      uint32_t access, uint32_t deny,
                                      Nfs4StateId& out_stateid,
                                      bool& needs_confirm,
                                      uint32_t& out_deleg_type,
                                      Nfs4StateId& out_deleg_stateid,
                                      Nfs4CallbackInfo& out_recall_cb,
                                      Nfs4StateId& out_recall_deleg_sid,
                                      FileHandle& out_recall_fh) {
    std::lock_guard<std::mutex> lk(mu_);

    out_deleg_type = OPEN_DELEGATE_NONE;

    auto cit = clients_.find(clientid);
    if (cit == clients_.end() || !cit->second.confirmed)
        return Nfs4Stat::NFS4ERR_STALE_CLIENTID;

    // RFC 7530 §10.4 - Check for conflicting delegations from other clients
    for (auto& ds : deleg_states_) {
        if (!(ds.fh == fh) || ds.clientid == clientid) continue;
        // Write delegation always conflicts; read deleg conflicts with write access
        bool conflicts = (ds.deleg_type == OPEN_DELEGATE_WRITE) ||
                         (access & OPEN4_SHARE_ACCESS_WRITE);
        if (!conflicts) continue;

        if (!ds.recalled) {
            ds.recalled = true;
            auto dit = clients_.find(ds.clientid);
            if (dit != clients_.end())
                out_recall_cb = dit->second.cb_info;
            out_recall_deleg_sid = ds.stateid;
            out_recall_fh = ds.fh;
        }
        return Nfs4Stat::NFS4ERR_DELAY;
    }

    // Check if there's an existing open for same owner+fh
    for (auto& os : open_states_) {
        if (os.clientid == clientid && os.owner == owner && os.fh == fh) {
            // RFC 7530 §8.1.5 - Sequence ID validation
            if (seqid != os.open_seqid + 1)
                return Nfs4Stat::NFS4ERR_BAD_SEQID;
            // Upgrade access if needed
            os.access |= access;
            os.stateid.seqid++;
            os.open_seqid = seqid;
            out_stateid = os.stateid;
            needs_confirm = !os.confirmed;
            cit->second.last_renewed = std::chrono::steady_clock::now();
            return Nfs4Stat::NFS4_OK;
        }
    }

    // Create new open state
    Nfs4OpenState os;
    os.stateid.seqid = 1;
    gen_stateid_other(os.stateid.other);
    os.clientid = clientid;
    os.fh = fh;
    os.access = access;
    os.deny = deny;
    os.owner = owner;
    os.open_seqid = seqid;
    os.confirmed = false;

    out_stateid = os.stateid;
    needs_confirm = true;
    open_states_.push_back(std::move(os));

    // RFC 7530 §10.4 - Try to grant delegation
    // Only if no other client has the file open and client has valid callback
    bool other_client_open = false;
    for (const auto& oos : open_states_) {
        if (oos.fh == fh && oos.clientid != clientid) {
            other_client_open = true;
            break;
        }
    }
    if (!other_client_open && cit->second.cb_info.valid) {
        // Check if client already has delegation on this file
        for (const auto& ds : deleg_states_) {
            if (ds.fh == fh && ds.clientid == clientid) {
                out_deleg_type = ds.deleg_type;
                out_deleg_stateid = ds.stateid;
                goto deleg_done;
            }
        }
        // Grant new delegation
        {
            Nfs4DelegState ds;
            ds.stateid.seqid = 1;
            gen_stateid_other(ds.stateid.other);
            ds.clientid = clientid;
            ds.fh = fh;
            ds.deleg_type = (access & OPEN4_SHARE_ACCESS_WRITE)
                            ? OPEN_DELEGATE_WRITE : OPEN_DELEGATE_READ;
            out_deleg_type = ds.deleg_type;
            out_deleg_stateid = ds.stateid;
            deleg_states_.push_back(std::move(ds));
        }
    }
deleg_done:

    cit->second.last_renewed = std::chrono::steady_clock::now();
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.18 - OPEN_CONFIRM
Nfs4Stat Nfs4StateManager::confirm_open(const Nfs4StateId& stateid,
                                          uint32_t seqid,
                                          Nfs4StateId& out_stateid) {
    std::lock_guard<std::mutex> lk(mu_);

    auto* os = find_open_state(stateid);
    if (!os) return Nfs4Stat::NFS4ERR_BAD_STATEID;

    // RFC 7530 §8.1.5 - Sequence ID validation
    if (seqid != os->open_seqid + 1)
        return Nfs4Stat::NFS4ERR_BAD_SEQID;

    os->confirmed = true;
    os->stateid.seqid++;
    os->open_seqid = seqid;
    out_stateid = os->stateid;

    // Renew lease
    auto cit = clients_.find(os->clientid);
    if (cit != clients_.end())
        cit->second.last_renewed = std::chrono::steady_clock::now();

    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.4 - CLOSE
Nfs4Stat Nfs4StateManager::close_file(const Nfs4StateId& stateid,
                                        uint32_t seqid,
                                        Nfs4StateId& out_stateid) {
    std::lock_guard<std::mutex> lk(mu_);

    auto it = std::find_if(open_states_.begin(), open_states_.end(),
        [&](const Nfs4OpenState& os) {
            return std::memcmp(os.stateid.other, stateid.other, 12) == 0;
        });

    if (it == open_states_.end())
        return Nfs4Stat::NFS4ERR_BAD_STATEID;

    // RFC 7530 §8.1.5 - Sequence ID validation
    if (seqid != it->open_seqid + 1)
        return Nfs4Stat::NFS4ERR_BAD_SEQID;

    // RFC 7530 §9.1.4.4 - Check for held locks
    for (const auto& ls : lock_states_) {
        if (std::memcmp(ls.open_stateid_other, it->stateid.other, 12) == 0 &&
            !ls.ranges.empty()) {
            return Nfs4Stat::NFS4ERR_LOCKS_HELD;
        }
    }

    // Return a final stateid with seqid=UINT32_MAX to indicate closed
    out_stateid = it->stateid;
    out_stateid.seqid = UINT32_MAX;

    // Remove lock states associated with this open (empty ones)
    lock_states_.erase(
        std::remove_if(lock_states_.begin(), lock_states_.end(),
            [&](const Nfs4LockState& ls) {
                return std::memcmp(ls.open_stateid_other, it->stateid.other, 12) == 0;
            }),
        lock_states_.end());

    // Renew lease
    auto cit = clients_.find(it->clientid);
    if (cit != clients_.end())
        cit->second.last_renewed = std::chrono::steady_clock::now();

    open_states_.erase(it);
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.19 - OPEN_DOWNGRADE
Nfs4Stat Nfs4StateManager::open_downgrade(const Nfs4StateId& stateid,
                                            uint32_t seqid,
                                            uint32_t access, uint32_t deny,
                                            Nfs4StateId& out_stateid) {
    std::lock_guard<std::mutex> lk(mu_);

    auto* os = find_open_state(stateid);
    if (!os) return Nfs4Stat::NFS4ERR_BAD_STATEID;

    if (seqid != os->open_seqid + 1)
        return Nfs4Stat::NFS4ERR_BAD_SEQID;

    // New access must be a subset of current access
    if ((access & os->access) != access)
        return Nfs4Stat::NFS4ERR_INVAL;

    os->access = access;
    os->deny = deny;
    os->stateid.seqid++;
    os->open_seqid = seqid;
    out_stateid = os->stateid;

    auto cit = clients_.find(os->clientid);
    if (cit != clients_.end())
        cit->second.last_renewed = std::chrono::steady_clock::now();

    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.27 - RENEW
Nfs4Stat Nfs4StateManager::renew(uint64_t clientid) {
    std::lock_guard<std::mutex> lk(mu_);

    auto it = clients_.find(clientid);
    if (it == clients_.end())
        return Nfs4Stat::NFS4ERR_STALE_CLIENTID;

    it->second.last_renewed = std::chrono::steady_clock::now();
    return Nfs4Stat::NFS4_OK;
}

Nfs4Stat Nfs4StateManager::validate_stateid(const Nfs4StateId& stateid,
                                              uint32_t required_access) {
    // Special stateids are always valid
    if (is_special_stateid(stateid))
        return Nfs4Stat::NFS4_OK;

    std::lock_guard<std::mutex> lk(mu_);

    auto* os = find_open_state(stateid);
    if (os) {
        // Check that the open has the required access
        if ((required_access & os->access) != required_access)
            return Nfs4Stat::NFS4ERR_ACCESS;
        return Nfs4Stat::NFS4_OK;
    }

    // Also check lock stateids (RFC 7530 §9.1.3)
    auto* ls = find_lock_state(stateid);
    if (ls) return Nfs4Stat::NFS4_OK;

    // Also check delegation stateids (RFC 7530 §10.4)
    auto* ds = find_deleg_state(stateid);
    if (ds) {
        if (ds->deleg_type == OPEN_DELEGATE_READ &&
            (required_access & OPEN4_SHARE_ACCESS_WRITE))
            return Nfs4Stat::NFS4ERR_ACCESS;
        return Nfs4Stat::NFS4_OK;
    }

    return Nfs4Stat::NFS4ERR_BAD_STATEID;
}

// --- Byte-range locking ---

Nfs4LockState* Nfs4StateManager::find_lock_state(const Nfs4StateId& sid) {
    for (auto& ls : lock_states_) {
        if (std::memcmp(ls.stateid.other, sid.other, 12) == 0)
            return &ls;
    }
    return nullptr;
}

Nfs4LockState* Nfs4StateManager::find_lock_state_by_owner(
        const Nfs4LockOwner& owner, const FileHandle& fh) {
    for (auto& ls : lock_states_) {
        if (ls.lock_owner == owner && ls.fh == fh)
            return &ls;
    }
    return nullptr;
}

static bool ranges_overlap(uint64_t o1, uint64_t l1, uint64_t o2, uint64_t l2) {
    uint64_t end1 = (l1 == UINT64_MAX) ? UINT64_MAX : o1 + l1;
    uint64_t end2 = (l2 == UINT64_MAX) ? UINT64_MAX : o2 + l2;
    return o1 < end2 && o2 < end1;
}

bool Nfs4StateManager::check_lock_conflict(const FileHandle& fh,
                                            const Nfs4LockOwner& requester,
                                            uint32_t locktype,
                                            uint64_t offset, uint64_t length,
                                            Nfs4LockDenied& denied) {
    for (const auto& ls : lock_states_) {
        if (!(ls.fh == fh)) continue;
        if (ls.lock_owner == requester) continue;  // same owner never conflicts
        for (const auto& r : ls.ranges) {
            // READ-READ is compatible; anything with WRITE conflicts
            if (locktype == READ_LT && r.locktype == READ_LT) continue;
            if (ranges_overlap(offset, length, r.offset, r.length)) {
                denied.offset = r.offset;
                denied.length = r.length;
                denied.locktype = r.locktype;
                denied.owner = ls.lock_owner;
                return true;
            }
        }
    }
    return false;
}

void Nfs4StateManager::remove_lock_range(Nfs4LockState& ls,
                                          uint64_t offset, uint64_t length) {
    uint64_t rem_end = (length == UINT64_MAX) ? UINT64_MAX : offset + length;
    std::vector<Nfs4LockRange> new_ranges;

    for (const auto& r : ls.ranges) {
        uint64_t r_end = (r.length == UINT64_MAX) ? UINT64_MAX : r.offset + r.length;

        if (!ranges_overlap(offset, length, r.offset, r.length)) {
            // No overlap — keep as-is
            new_ranges.push_back(r);
            continue;
        }

        // Left remnant: range starts before removal window
        if (r.offset < offset) {
            Nfs4LockRange left = r;
            left.length = offset - r.offset;
            new_ranges.push_back(left);
        }

        // Right remnant: range extends past removal window
        if (r_end > rem_end && rem_end != UINT64_MAX) {
            Nfs4LockRange right = r;
            right.offset = rem_end;
            right.length = (r.length == UINT64_MAX) ? UINT64_MAX : r_end - rem_end;
            new_ranges.push_back(right);
        }
    }

    ls.ranges = std::move(new_ranges);
}

// RFC 7530 §16.10 - LOCK (new lock_owner)
Nfs4Stat Nfs4StateManager::lock_new(uint64_t clientid,
                                      const Nfs4StateId& open_stateid,
                                      uint32_t open_seqid,
                                      const Nfs4LockOwner& lock_owner,
                                      uint32_t lock_seqid,
                                      const FileHandle& fh,
                                      uint32_t locktype,
                                      uint64_t offset, uint64_t length,
                                      Nfs4StateId& out_stateid,
                                      Nfs4LockDenied& denied) {
    std::lock_guard<std::mutex> lk(mu_);

    // Find and validate open state
    auto* os = find_open_state(open_stateid);
    if (!os) return Nfs4Stat::NFS4ERR_BAD_STATEID;

    // Validate open_seqid
    if (open_seqid != os->open_seqid + 1)
        return Nfs4Stat::NFS4ERR_BAD_SEQID;

    // Bump the open seqid (consumed even on LOCK failure per RFC 7530 §8.1.5)
    os->open_seqid = open_seqid;
    os->stateid.seqid++;

    // Check for conflicts
    if (check_lock_conflict(fh, lock_owner, locktype, offset, length, denied))
        return Nfs4Stat::NFS4ERR_DENIED;

    // Find or create lock state for this owner+fh
    auto* ls = find_lock_state_by_owner(lock_owner, fh);
    if (!ls) {
        Nfs4LockState new_ls;
        new_ls.stateid.seqid = 1;
        gen_stateid_other(new_ls.stateid.other);
        new_ls.lock_owner = lock_owner;
        new_ls.fh = fh;
        new_ls.clientid = clientid;
        std::memcpy(new_ls.open_stateid_other, os->stateid.other, 12);
        new_ls.lock_seqid = lock_seqid;
        new_ls.ranges.push_back({offset, length, locktype});
        out_stateid = new_ls.stateid;
        lock_states_.push_back(std::move(new_ls));
    } else {
        // Existing lock state for this owner+fh
        if (lock_seqid != ls->lock_seqid + 1 && lock_seqid != 0)
            return Nfs4Stat::NFS4ERR_BAD_SEQID;
        ls->ranges.push_back({offset, length, locktype});
        ls->lock_seqid = lock_seqid;
        ls->stateid.seqid++;
        out_stateid = ls->stateid;
    }

    // Renew lease
    auto cit = clients_.find(clientid);
    if (cit != clients_.end())
        cit->second.last_renewed = std::chrono::steady_clock::now();

    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.10 - LOCK (existing lock_stateid)
Nfs4Stat Nfs4StateManager::lock_existing(const Nfs4StateId& lock_stateid,
                                           uint32_t lock_seqid,
                                           uint32_t locktype,
                                           uint64_t offset, uint64_t length,
                                           Nfs4StateId& out_stateid,
                                           Nfs4LockDenied& denied) {
    std::lock_guard<std::mutex> lk(mu_);

    auto* ls = find_lock_state(lock_stateid);
    if (!ls) return Nfs4Stat::NFS4ERR_BAD_STATEID;

    if (lock_seqid != ls->lock_seqid + 1)
        return Nfs4Stat::NFS4ERR_BAD_SEQID;

    // Check for conflicts
    if (check_lock_conflict(ls->fh, ls->lock_owner, locktype, offset, length, denied))
        return Nfs4Stat::NFS4ERR_DENIED;

    ls->ranges.push_back({offset, length, locktype});
    ls->lock_seqid = lock_seqid;
    ls->stateid.seqid++;
    out_stateid = ls->stateid;

    // Renew lease
    auto cit = clients_.find(ls->clientid);
    if (cit != clients_.end())
        cit->second.last_renewed = std::chrono::steady_clock::now();

    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.11 - LOCKT
Nfs4Stat Nfs4StateManager::lock_test(const FileHandle& fh,
                                       uint32_t locktype,
                                       uint64_t offset, uint64_t length,
                                       const Nfs4LockOwner& lock_owner,
                                       Nfs4LockDenied& denied) {
    std::lock_guard<std::mutex> lk(mu_);

    if (check_lock_conflict(fh, lock_owner, locktype, offset, length, denied))
        return Nfs4Stat::NFS4ERR_DENIED;

    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.12 - LOCKU
Nfs4Stat Nfs4StateManager::lock_unlock(const Nfs4StateId& lock_stateid,
                                         uint32_t seqid,
                                         uint64_t offset, uint64_t length,
                                         Nfs4StateId& out_stateid) {
    std::lock_guard<std::mutex> lk(mu_);

    auto* ls = find_lock_state(lock_stateid);
    if (!ls) return Nfs4Stat::NFS4ERR_BAD_STATEID;

    if (seqid != ls->lock_seqid + 1)
        return Nfs4Stat::NFS4ERR_BAD_SEQID;

    remove_lock_range(*ls, offset, length);
    ls->lock_seqid = seqid;
    ls->stateid.seqid++;
    out_stateid = ls->stateid;

    // Renew lease
    auto cit = clients_.find(ls->clientid);
    if (cit != clients_.end())
        cit->second.last_renewed = std::chrono::steady_clock::now();

    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.26 - RELEASE_LOCKOWNER
Nfs4Stat Nfs4StateManager::release_lock_owner(const Nfs4LockOwner& lock_owner) {
    std::lock_guard<std::mutex> lk(mu_);

    lock_states_.erase(
        std::remove_if(lock_states_.begin(), lock_states_.end(),
            [&](const Nfs4LockState& ls) { return ls.lock_owner == lock_owner; }),
        lock_states_.end());

    return Nfs4Stat::NFS4_OK;
}

// --- Delegation support ---

Nfs4DelegState* Nfs4StateManager::find_deleg_state(const Nfs4StateId& sid) {
    for (auto& ds : deleg_states_) {
        if (std::memcmp(ds.stateid.other, sid.other, 12) == 0)
            return &ds;
    }
    return nullptr;
}

Nfs4Stat Nfs4StateManager::delegreturn(const Nfs4StateId& stateid) {
    std::lock_guard<std::mutex> lk(mu_);

    auto it = std::find_if(deleg_states_.begin(), deleg_states_.end(),
        [&](const Nfs4DelegState& ds) {
            return std::memcmp(ds.stateid.other, stateid.other, 12) == 0;
        });
    if (it == deleg_states_.end())
        return Nfs4Stat::NFS4ERR_BAD_STATEID;

    deleg_states_.erase(it);
    return Nfs4Stat::NFS4_OK;
}

Nfs4Stat Nfs4StateManager::delegpurge(uint64_t clientid) {
    std::lock_guard<std::mutex> lk(mu_);

    deleg_states_.erase(
        std::remove_if(deleg_states_.begin(), deleg_states_.end(),
            [clientid](const Nfs4DelegState& ds) { return ds.clientid == clientid; }),
        deleg_states_.end());

    return Nfs4Stat::NFS4_OK;
}

Nfs4CallbackInfo Nfs4StateManager::get_client_callback(uint64_t clientid) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = clients_.find(clientid);
    if (it == clients_.end()) return {};
    return it->second.cb_info;
}

void Nfs4StateManager::invalidate_client_callback(uint64_t clientid) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = clients_.find(clientid);
    if (it != clients_.end())
        it->second.cb_info.valid = false;
}
