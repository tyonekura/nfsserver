#pragma once

#include <cstdint>
#include <string>
#include "nfs4/nfs4_types.h"
#include "vfs/vfs.h"

// RFC 7530 §7.10 - Callback info stored per client
struct Nfs4CallbackInfo {
    uint32_t cb_program = 0;
    std::string r_netid;       // "tcp"
    std::string r_addr;        // universal address: h1.h2.h3.h4.p1.p2
    uint32_t callback_ident = 0;
    bool valid = false;
};

// Parse universal address (RFC 5665) into host and port.
// "192.168.1.1.8.1" -> host="192.168.1.1", port=2049
bool parse_universal_addr(const std::string& r_addr,
                          std::string& out_host,
                          uint16_t& out_port);

// RFC 7530 §15.3 - Send CB_NULL probe to verify callback path.
// Returns true on success. 5-second timeout.
bool cb_null_probe(const Nfs4CallbackInfo& cb, uint32_t xid);

// RFC 7530 §15.5 - Send CB_RECALL inside CB_COMPOUND.
// Returns true if reply indicates success.
bool cb_recall(const Nfs4CallbackInfo& cb,
               uint32_t xid,
               const Nfs4StateId& stateid,
               bool truncate,
               const FileHandle& fh,
               int timeout_ms = 10000);
