#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <arpa/inet.h>

// XDR encoding/decoding per RFC 4506.
// All XDR data is aligned to 4-byte boundaries, big-endian.

class XdrEncoder {
public:
    XdrEncoder() = default;

    void encode_uint32(uint32_t v);
    void encode_int32(int32_t v);
    void encode_uint64(uint64_t v);
    void encode_int64(int64_t v);
    void encode_bool(bool v);
    void encode_opaque_fixed(const void* data, size_t len);
    void encode_opaque(const void* data, size_t len);
    void encode_string(const std::string& s);

    const std::vector<uint8_t>& data() const { return buf_; }
    size_t size() const { return buf_.size(); }

private:
    void append(const void* data, size_t len);
    void pad_to_4();
    std::vector<uint8_t> buf_;
};

class XdrDecoder {
public:
    XdrDecoder(const uint8_t* data, size_t len);

    uint32_t decode_uint32();
    int32_t decode_int32();
    uint64_t decode_uint64();
    int64_t decode_int64();
    bool decode_bool();
    void decode_opaque_fixed(void* out, size_t len);
    std::vector<uint8_t> decode_opaque();
    std::string decode_string();

    size_t remaining() const { return len_ - pos_; }
    const uint8_t* current() const { return data_ + pos_; }
    void skip(size_t n);

private:
    void check(size_t n);
    void skip_pad();
    const uint8_t* data_;
    size_t len_;
    size_t pos_ = 0;
};
