#include <gtest/gtest.h>
#include "xdr/xdr_codec.h"

TEST(XdrCodec, Uint32RoundTrip) {
    XdrEncoder enc;
    enc.encode_uint32(0);
    enc.encode_uint32(42);
    enc.encode_uint32(UINT32_MAX);

    XdrDecoder dec(enc.data().data(), enc.size());
    EXPECT_EQ(dec.decode_uint32(), 0u);
    EXPECT_EQ(dec.decode_uint32(), 42u);
    EXPECT_EQ(dec.decode_uint32(), UINT32_MAX);
    EXPECT_EQ(dec.remaining(), 0u);
}

TEST(XdrCodec, Int32RoundTrip) {
    XdrEncoder enc;
    enc.encode_int32(-1);
    enc.encode_int32(0);
    enc.encode_int32(INT32_MAX);
    enc.encode_int32(INT32_MIN);

    XdrDecoder dec(enc.data().data(), enc.size());
    EXPECT_EQ(dec.decode_int32(), -1);
    EXPECT_EQ(dec.decode_int32(), 0);
    EXPECT_EQ(dec.decode_int32(), INT32_MAX);
    EXPECT_EQ(dec.decode_int32(), INT32_MIN);
}

TEST(XdrCodec, Uint64RoundTrip) {
    XdrEncoder enc;
    enc.encode_uint64(0);
    enc.encode_uint64(0x123456789ABCDEF0ULL);
    enc.encode_uint64(UINT64_MAX);

    XdrDecoder dec(enc.data().data(), enc.size());
    EXPECT_EQ(dec.decode_uint64(), 0u);
    EXPECT_EQ(dec.decode_uint64(), 0x123456789ABCDEF0ULL);
    EXPECT_EQ(dec.decode_uint64(), UINT64_MAX);
}

TEST(XdrCodec, BoolRoundTrip) {
    XdrEncoder enc;
    enc.encode_bool(true);
    enc.encode_bool(false);

    XdrDecoder dec(enc.data().data(), enc.size());
    EXPECT_TRUE(dec.decode_bool());
    EXPECT_FALSE(dec.decode_bool());
}

TEST(XdrCodec, StringRoundTrip) {
    XdrEncoder enc;
    enc.encode_string("");
    enc.encode_string("hello");
    enc.encode_string("abc");  // 3 bytes, tests padding

    XdrDecoder dec(enc.data().data(), enc.size());
    EXPECT_EQ(dec.decode_string(), "");
    EXPECT_EQ(dec.decode_string(), "hello");
    EXPECT_EQ(dec.decode_string(), "abc");
}

TEST(XdrCodec, OpaqueRoundTrip) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};

    XdrEncoder enc;
    enc.encode_opaque(data.data(), data.size());

    XdrDecoder dec(enc.data().data(), enc.size());
    auto result = dec.decode_opaque();
    EXPECT_EQ(result, data);
}

TEST(XdrCodec, OpaqueFixedRoundTrip) {
    uint8_t data[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    XdrEncoder enc;
    enc.encode_opaque_fixed(data, 6);

    // Should be padded to 8 bytes
    EXPECT_EQ(enc.size(), 8u);

    XdrDecoder dec(enc.data().data(), enc.size());
    uint8_t out[6] = {};
    dec.decode_opaque_fixed(out, 6);
    EXPECT_EQ(std::memcmp(data, out, 6), 0);
}

TEST(XdrCodec, FourByteAlignment) {
    // All XDR data must be 4-byte aligned.
    XdrEncoder enc;
    enc.encode_string("a");  // 1 byte + 3 padding + 4 length = 8
    EXPECT_EQ(enc.size() % 4, 0u);

    enc.encode_string("ab"); // 2 bytes + 2 padding + 4 length
    EXPECT_EQ(enc.size() % 4, 0u);

    enc.encode_string("abcd"); // 4 bytes + 0 padding + 4 length
    EXPECT_EQ(enc.size() % 4, 0u);
}

TEST(XdrCodec, BufferUnderflow) {
    XdrEncoder enc;
    enc.encode_uint32(42);

    XdrDecoder dec(enc.data().data(), enc.size());
    dec.decode_uint32(); // consume the only value
    EXPECT_THROW(dec.decode_uint32(), std::runtime_error);
}
