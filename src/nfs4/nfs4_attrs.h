#pragma once

#include "xdr/xdr_codec.h"
#include "vfs/vfs.h"
#include "nfs4/nfs4_types.h"
#include <vector>

// RFC 7530 §5.8 - NFSv4 bitmap-based attribute encoding/decoding

// Decode a bitmap (array of uint32_t) from XDR
std::vector<uint32_t> decode_bitmap(XdrDecoder& dec);

// Encode a bitmap (array of uint32_t) to XDR
void encode_bitmap(XdrEncoder& enc, const std::vector<uint32_t>& bm);

// Return the bitmap of attributes this server supports
std::vector<uint32_t> get_supported_bitmap();

// Check if a specific attribute bit is set in a bitmap
inline bool bitmap_isset(const std::vector<uint32_t>& bm, uint32_t bit) {
    uint32_t word = bit / 32;
    uint32_t mask = 1u << (bit % 32);
    return word < bm.size() && (bm[word] & mask) != 0;
}

// Set a specific attribute bit in a bitmap
inline void bitmap_set(std::vector<uint32_t>& bm, uint32_t bit) {
    uint32_t word = bit / 32;
    if (bm.size() <= word) bm.resize(word + 1, 0);
    bm[word] |= (1u << (bit % 32));
}

// Encode fattr4 for a given file: bitmap of what's returned + attribute data
// Only encodes attributes that are both requested and supported.
void encode_fattr4(XdrEncoder& enc,
                   const std::vector<uint32_t>& requested,
                   const Fattr3& attr,
                   const FileHandle& fh);

// Decode fattr4 attributes relevant for SETATTR (mode, size, atime, mtime).
// Returns which fields were set via out-params.
struct Nfs4SetAttr {
    uint32_t mode = UINT32_MAX;
    uint32_t uid = UINT32_MAX;
    uint32_t gid = UINT32_MAX;
    uint64_t size = UINT64_MAX;
    NfsTimeSet atime;
    NfsTimeSet mtime;
};

Nfs4SetAttr decode_fattr4_setattr(XdrDecoder& dec);
