#include "xdr/xdr_codec.h"

// RFC 4506 - XDR: External Data Representation Standard
// All data items are padded to 4-byte boundaries (RFC 4506 §3.1).

// --- XdrEncoder ---

void XdrEncoder::append(const void* data, size_t len) {
    auto p = static_cast<const uint8_t*>(data);
    buf_.insert(buf_.end(), p, p + len);
}

// RFC 4506 §3.1 - All XDR data aligned to 4-byte multiples
void XdrEncoder::pad_to_4() {
    size_t rem = buf_.size() % 4;
    if (rem != 0) {
        static const uint8_t zeros[4] = {};
        buf_.insert(buf_.end(), zeros, zeros + (4 - rem));
    }
}

// RFC 4506 §4.2 - Unsigned Integer
void XdrEncoder::encode_uint32(uint32_t v) {
    uint32_t net = htonl(v);
    append(&net, 4);
}

// RFC 4506 §4.1 - Integer
void XdrEncoder::encode_int32(int32_t v) {
    encode_uint32(static_cast<uint32_t>(v));
}

// RFC 4506 §4.5 - Unsigned Hyper Integer
void XdrEncoder::encode_uint64(uint64_t v) {
    encode_uint32(static_cast<uint32_t>(v >> 32));
    encode_uint32(static_cast<uint32_t>(v & 0xFFFFFFFF));
}

// RFC 4506 §4.5 - Hyper Integer
void XdrEncoder::encode_int64(int64_t v) {
    encode_uint64(static_cast<uint64_t>(v));
}

// RFC 4506 §4.4 - Boolean
void XdrEncoder::encode_bool(bool v) {
    encode_uint32(v ? 1 : 0);
}

// RFC 4506 §4.9 - Fixed-Length Opaque Data
void XdrEncoder::encode_opaque_fixed(const void* data, size_t len) {
    append(data, len);
    pad_to_4();
}

// RFC 4506 §4.10 - Variable-Length Opaque Data
void XdrEncoder::encode_opaque(const void* data, size_t len) {
    encode_uint32(static_cast<uint32_t>(len));
    append(data, len);
    pad_to_4();
}

// RFC 4506 §4.11 - String
void XdrEncoder::encode_string(const std::string& s) {
    encode_opaque(s.data(), s.size());
}

// --- XdrDecoder ---

XdrDecoder::XdrDecoder(const uint8_t* data, size_t len)
    : data_(data), len_(len) {}

void XdrDecoder::check(size_t n) {
    if (pos_ + n > len_)
        throw std::runtime_error("XDR decode: buffer underflow");
}

void XdrDecoder::skip_pad() {
    size_t rem = pos_ % 4;
    if (rem != 0)
        pos_ += (4 - rem);
}

void XdrDecoder::skip(size_t n) {
    check(n);
    pos_ += n;
    skip_pad();
}

// RFC 4506 §4.2 - Unsigned Integer
uint32_t XdrDecoder::decode_uint32() {
    check(4);
    uint32_t net;
    std::memcpy(&net, data_ + pos_, 4);
    pos_ += 4;
    return ntohl(net);
}

// RFC 4506 §4.1 - Integer
int32_t XdrDecoder::decode_int32() {
    return static_cast<int32_t>(decode_uint32());
}

// RFC 4506 §4.5 - Unsigned Hyper Integer
uint64_t XdrDecoder::decode_uint64() {
    uint64_t hi = decode_uint32();
    uint64_t lo = decode_uint32();
    return (hi << 32) | lo;
}

// RFC 4506 §4.5 - Hyper Integer
int64_t XdrDecoder::decode_int64() {
    return static_cast<int64_t>(decode_uint64());
}

// RFC 4506 §4.4 - Boolean
bool XdrDecoder::decode_bool() {
    return decode_uint32() != 0;
}

// RFC 4506 §4.9 - Fixed-Length Opaque Data
void XdrDecoder::decode_opaque_fixed(void* out, size_t len) {
    check(len);
    std::memcpy(out, data_ + pos_, len);
    pos_ += len;
    skip_pad();
}

// RFC 4506 §4.10 - Variable-Length Opaque Data
std::vector<uint8_t> XdrDecoder::decode_opaque() {
    uint32_t len = decode_uint32();
    check(len);
    std::vector<uint8_t> result(data_ + pos_, data_ + pos_ + len);
    pos_ += len;
    skip_pad();
    return result;
}

// RFC 4506 §4.11 - String
std::string XdrDecoder::decode_string() {
    uint32_t len = decode_uint32();
    check(len);
    std::string result(reinterpret_cast<const char*>(data_ + pos_), len);
    pos_ += len;
    skip_pad();
    return result;
}
