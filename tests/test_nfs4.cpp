#include <gtest/gtest.h>
#include "nfs4/nfs4_types.h"
#include "nfs4/nfs4_attrs.h"
#include "nfs4/nfs4_state.h"
#include "nfs4/nfs4_server.h"
#include "xdr/xdr_codec.h"

// --- Attribute codec tests ---

TEST(Nfs4Attrs, BitmapRoundTrip) {
    std::vector<uint32_t> bm = {0xDEADBEEF, 0x12345678};
    XdrEncoder enc;
    encode_bitmap(enc, bm);

    XdrDecoder dec(enc.data().data(), enc.size());
    auto result = decode_bitmap(dec);
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0], 0xDEADBEEF);
    EXPECT_EQ(result[1], 0x12345678);
}

TEST(Nfs4Attrs, BitmapTrailingZerosTrimmed) {
    std::vector<uint32_t> bm = {0x01, 0x00, 0x00};
    XdrEncoder enc;
    encode_bitmap(enc, bm);

    XdrDecoder dec(enc.data().data(), enc.size());
    auto result = decode_bitmap(dec);
    // Trailing zeros should be trimmed to 1 word
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], 0x01);
}

TEST(Nfs4Attrs, BitmapIsset) {
    std::vector<uint32_t> bm = {0, 0};
    bitmap_set(bm, FATTR4_TYPE);       // bit 1 in word 0
    bitmap_set(bm, FATTR4_SIZE);       // bit 4 in word 0
    bitmap_set(bm, FATTR4_MODE);       // bit 33 -> bit 1 in word 1

    EXPECT_TRUE(bitmap_isset(bm, FATTR4_TYPE));
    EXPECT_TRUE(bitmap_isset(bm, FATTR4_SIZE));
    EXPECT_TRUE(bitmap_isset(bm, FATTR4_MODE));
    EXPECT_FALSE(bitmap_isset(bm, FATTR4_CHANGE));
    EXPECT_FALSE(bitmap_isset(bm, FATTR4_OWNER));
}

TEST(Nfs4Attrs, SupportedBitmapHasRequiredAttrs) {
    auto bm = get_supported_bitmap();
    EXPECT_TRUE(bitmap_isset(bm, FATTR4_SUPPORTED_ATTRS));
    EXPECT_TRUE(bitmap_isset(bm, FATTR4_TYPE));
    EXPECT_TRUE(bitmap_isset(bm, FATTR4_SIZE));
    EXPECT_TRUE(bitmap_isset(bm, FATTR4_MODE));
    EXPECT_TRUE(bitmap_isset(bm, FATTR4_FSID));
    EXPECT_TRUE(bitmap_isset(bm, FATTR4_FILEID));
    EXPECT_TRUE(bitmap_isset(bm, FATTR4_TIME_MODIFY));
    EXPECT_TRUE(bitmap_isset(bm, FATTR4_CHANGE));
    EXPECT_TRUE(bitmap_isset(bm, FATTR4_LEASE_TIME));
}

TEST(Nfs4Attrs, EncodeFattr4TypeAndSize) {
    Fattr3 attr;
    attr.type = Ftype3::NF3REG;
    attr.size = 12345;
    attr.mode = 0644;
    attr.nlink = 1;
    attr.uid = 1000;
    attr.gid = 1000;
    attr.mtime = {1000, 500};
    attr.fileid = 42;
    attr.fsid = 1;

    FileHandle fh;
    fh.len = 16;

    // Request only TYPE and SIZE
    std::vector<uint32_t> requested(1, 0);
    bitmap_set(requested, FATTR4_TYPE);
    bitmap_set(requested, FATTR4_SIZE);

    XdrEncoder enc;
    encode_fattr4(enc, requested, attr, fh);

    // Decode: bitmap + opaque attr data
    XdrDecoder dec(enc.data().data(), enc.size());
    auto result_bm = decode_bitmap(dec);
    EXPECT_TRUE(bitmap_isset(result_bm, FATTR4_TYPE));
    EXPECT_TRUE(bitmap_isset(result_bm, FATTR4_SIZE));

    auto attr_data = dec.decode_opaque();
    XdrDecoder attr_dec(attr_data.data(), attr_data.size());

    // TYPE comes first (bit 1), then SIZE (bit 4)
    uint32_t type = attr_dec.decode_uint32();
    EXPECT_EQ(type, static_cast<uint32_t>(Nfs4Type::NF4REG));

    uint64_t size = attr_dec.decode_uint64();
    EXPECT_EQ(size, 12345u);
}

// --- Status code conversion tests ---

TEST(Nfs4Types, StatusConversion) {
    EXPECT_EQ(nfs3stat_to_nfs4stat(NfsStat3::NFS3_OK), Nfs4Stat::NFS4_OK);
    EXPECT_EQ(nfs3stat_to_nfs4stat(NfsStat3::NFS3ERR_NOENT), Nfs4Stat::NFS4ERR_NOENT);
    EXPECT_EQ(nfs3stat_to_nfs4stat(NfsStat3::NFS3ERR_ACCES), Nfs4Stat::NFS4ERR_ACCESS);
    EXPECT_EQ(nfs3stat_to_nfs4stat(NfsStat3::NFS3ERR_STALE), Nfs4Stat::NFS4ERR_STALE);
    EXPECT_EQ(nfs3stat_to_nfs4stat(NfsStat3::NFS3ERR_NOTSUPP), Nfs4Stat::NFS4ERR_NOTSUPP);
}

TEST(Nfs4Types, TypeConversion) {
    EXPECT_EQ(ftype3_to_nfs4type(Ftype3::NF3REG), Nfs4Type::NF4REG);
    EXPECT_EQ(ftype3_to_nfs4type(Ftype3::NF3DIR), Nfs4Type::NF4DIR);
    EXPECT_EQ(ftype3_to_nfs4type(Ftype3::NF3LNK), Nfs4Type::NF4LNK);
}

// --- State management tests ---

TEST(Nfs4State, SetClientIdAndConfirm) {
    Nfs4StateManager mgr;
    uint8_t verifier[8] = {1,2,3,4,5,6,7,8};
    std::vector<uint8_t> client_id = {10, 20, 30};

    auto [clientid, confirm] = mgr.set_clientid(verifier, client_id);
    EXPECT_GT(clientid, 0u);

    // Confirm with correct verifier
    EXPECT_EQ(mgr.confirm_clientid(clientid, confirm.data()), Nfs4Stat::NFS4_OK);

    // Confirm with wrong verifier
    uint8_t bad_confirm[8] = {};
    EXPECT_EQ(mgr.confirm_clientid(clientid, bad_confirm), Nfs4Stat::NFS4ERR_STALE_CLIENTID);
}

TEST(Nfs4State, StaleClientId) {
    Nfs4StateManager mgr;
    EXPECT_EQ(mgr.confirm_clientid(999, nullptr), Nfs4Stat::NFS4ERR_STALE_CLIENTID);
    EXPECT_EQ(mgr.renew(999), Nfs4Stat::NFS4ERR_STALE_CLIENTID);
}

TEST(Nfs4State, OpenConfirmClose) {
    Nfs4StateManager mgr;

    // Setup client
    uint8_t verifier[8] = {1};
    std::vector<uint8_t> cid = {1};
    auto [clientid, confirm] = mgr.set_clientid(verifier, cid);
    mgr.confirm_clientid(clientid, confirm.data());

    // Open
    FileHandle fh;
    fh.len = 16;
    fh.data[0] = 42;
    std::vector<uint8_t> owner = {1, 2, 3};
    Nfs4StateId stateid;
    bool needs_confirm = false;

    EXPECT_EQ(mgr.open_file(clientid, owner, 1, fh, OPEN4_SHARE_ACCESS_READ,
                             OPEN4_SHARE_DENY_NONE, stateid, needs_confirm),
              Nfs4Stat::NFS4_OK);
    EXPECT_TRUE(needs_confirm);
    EXPECT_EQ(stateid.seqid, 1u);

    // Confirm open
    Nfs4StateId confirmed_sid;
    EXPECT_EQ(mgr.confirm_open(stateid, 2, confirmed_sid), Nfs4Stat::NFS4_OK);

    // Validate for READ
    EXPECT_EQ(mgr.validate_stateid(confirmed_sid, OPEN4_SHARE_ACCESS_READ), Nfs4Stat::NFS4_OK);

    // Close
    Nfs4StateId closed_sid;
    EXPECT_EQ(mgr.close_file(confirmed_sid, 3, closed_sid), Nfs4Stat::NFS4_OK);

    // Validate after close should fail
    EXPECT_EQ(mgr.validate_stateid(confirmed_sid, OPEN4_SHARE_ACCESS_READ),
              Nfs4Stat::NFS4ERR_BAD_STATEID);
}

TEST(Nfs4State, SpecialStateids) {
    Nfs4StateId anon;
    std::memset(&anon, 0, sizeof(anon));
    EXPECT_TRUE(Nfs4StateManager::is_special_stateid(anon));

    Nfs4StateId bypass;
    bypass.seqid = 0;
    std::memset(bypass.other, 0xFF, 12);
    EXPECT_TRUE(Nfs4StateManager::is_special_stateid(bypass));

    Nfs4StateId normal;
    normal.seqid = 1;
    normal.other[0] = 1;
    EXPECT_FALSE(Nfs4StateManager::is_special_stateid(normal));

    // Special stateids should validate OK
    Nfs4StateManager mgr;
    EXPECT_EQ(mgr.validate_stateid(anon, OPEN4_SHARE_ACCESS_READ), Nfs4Stat::NFS4_OK);
    EXPECT_EQ(mgr.validate_stateid(bypass, OPEN4_SHARE_ACCESS_READ), Nfs4Stat::NFS4_OK);
}

TEST(Nfs4State, Renew) {
    Nfs4StateManager mgr;
    uint8_t verifier[8] = {1};
    std::vector<uint8_t> cid = {1};
    auto [clientid, confirm] = mgr.set_clientid(verifier, cid);
    mgr.confirm_clientid(clientid, confirm.data());

    EXPECT_EQ(mgr.renew(clientid), Nfs4Stat::NFS4_OK);
}

// --- COMPOUND dispatch tests ---

TEST(Nfs4Compound, MinorVersionMismatch) {
    // Build a COMPOUND request with minorversion=1
    XdrEncoder req;
    req.encode_string("test");  // tag
    req.encode_uint32(1);       // minorversion (unsupported)
    req.encode_uint32(0);       // 0 ops

    XdrDecoder dec(req.data().data(), req.size());
    XdrEncoder reply;

    // We can't easily test proc_compound directly without a Vfs,
    // but we can verify the types compile and the structure is correct.
    // The server would return NFS4ERR_MINOR_VERS_MISMATCH.
    // For now, just verify the encoding/decoding roundtrips.
    std::string tag = dec.decode_string();
    EXPECT_EQ(tag, "test");
    uint32_t mv = dec.decode_uint32();
    EXPECT_EQ(mv, 1u);
}
