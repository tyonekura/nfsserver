#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <arpa/inet.h>

// RFC 4506 - XDR: External Data Representation Standard
// All XDR data is aligned to 4-byte boundaries, big-endian.

class XdrEncoder {
public:
    XdrEncoder() = default;

    void encode_uint32(uint32_t v);       // RFC 4506 §4.2 - Unsigned Integer
    void encode_int32(int32_t v);         // RFC 4506 §4.1 - Integer
    void encode_uint64(uint64_t v);       // RFC 4506 §4.5 - Unsigned Hyper Integer
    void encode_int64(int64_t v);         // RFC 4506 §4.5 - Hyper Integer
    void encode_bool(bool v);             // RFC 4506 §4.4 - Boolean
    void encode_opaque_fixed(const void* data, size_t len); // RFC 4506 §4.9 - Fixed-Length Opaque
    void encode_opaque(const void* data, size_t len);       // RFC 4506 §4.10 - Variable-Length Opaque
    void encode_string(const std::string& s);               // RFC 4506 §4.11 - String

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

    uint32_t decode_uint32();                          // RFC 4506 §4.2 - Unsigned Integer
    int32_t decode_int32();                             // RFC 4506 §4.1 - Integer
    uint64_t decode_uint64();                           // RFC 4506 §4.5 - Unsigned Hyper Integer
    int64_t decode_int64();                             // RFC 4506 §4.5 - Hyper Integer
    bool decode_bool();                                 // RFC 4506 §4.4 - Boolean
    void decode_opaque_fixed(void* out, size_t len);    // RFC 4506 §4.9 - Fixed-Length Opaque
    std::vector<uint8_t> decode_opaque();               // RFC 4506 §4.10 - Variable-Length Opaque
    std::string decode_string();                        // RFC 4506 §4.11 - String

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
