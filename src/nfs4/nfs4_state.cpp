#include "nfs4/nfs4_state.h"
#include <algorithm>
#include <cstring>
#include <random>

// RFC 7530 - NFSv4 state management

Nfs4StateManager::Nfs4StateManager() = default;

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
                                const std::vector<uint8_t>& client_id) {
    std::lock_guard<std::mutex> lk(mu_);

    // Check if this client_id already exists
    auto it = client_id_to_clientid_.find(client_id);
    if (it != client_id_to_clientid_.end()) {
        auto& client = clients_[it->second];
        // Update verifier, generate new confirm verifier
        std::memcpy(client.verifier, verifier, 8);
        client.confirmed = false;

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
                                      bool& needs_confirm) {
    std::lock_guard<std::mutex> lk(mu_);

    auto cit = clients_.find(clientid);
    if (cit == clients_.end() || !cit->second.confirmed)
        return Nfs4Stat::NFS4ERR_STALE_CLIENTID;

    // Check if there's an existing open for same owner+fh
    for (auto& os : open_states_) {
        if (os.clientid == clientid && os.owner == owner && os.fh == fh) {
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
                                        uint32_t /*seqid*/,
                                        Nfs4StateId& out_stateid) {
    std::lock_guard<std::mutex> lk(mu_);

    auto it = std::find_if(open_states_.begin(), open_states_.end(),
        [&](const Nfs4OpenState& os) {
            return std::memcmp(os.stateid.other, stateid.other, 12) == 0;
        });

    if (it == open_states_.end())
        return Nfs4Stat::NFS4ERR_BAD_STATEID;

    // Return a final stateid with seqid=UINT32_MAX to indicate closed
    out_stateid = it->stateid;
    out_stateid.seqid = UINT32_MAX;

    // Renew lease
    auto cit = clients_.find(it->clientid);
    if (cit != clients_.end())
        cit->second.last_renewed = std::chrono::steady_clock::now();

    open_states_.erase(it);
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
    if (!os) return Nfs4Stat::NFS4ERR_BAD_STATEID;

    // Check that the open has the required access
    if ((required_access & os->access) != required_access)
        return Nfs4Stat::NFS4ERR_ACCESS;

    return Nfs4Stat::NFS4_OK;
}
