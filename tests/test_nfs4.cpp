#include <gtest/gtest.h>
#include "nfs4/nfs4_types.h"
#include "nfs4/nfs4_attrs.h"
#include "nfs4/nfs4_callback.h"
#include "nfs4/nfs4_state.h"
#include "nfs4/nfs4_server.h"
#include "xdr/xdr_codec.h"

// Helper: call open_file with delegation out-params (ignoring them)
// Also ends grace period so tests that don't care about it work normally.
static Nfs4Stat open_file_simple(Nfs4StateManager& mgr, uint64_t clientid,
                                  const std::vector<uint8_t>& owner,
                                  uint32_t seqid, const FileHandle& fh,
                                  uint32_t access, uint32_t deny,
                                  Nfs4StateId& out_stateid,
                                  bool& needs_confirm) {
    mgr.end_grace_period();
    uint32_t deleg_type = OPEN_DELEGATE_NONE;
    Nfs4StateId deleg_sid;
    Nfs4CallbackInfo recall_cb;
    Nfs4StateId recall_sid;
    FileHandle recall_fh;
    return mgr.open_file(clientid, owner, seqid, fh, access, deny,
                          out_stateid, needs_confirm,
                          deleg_type, deleg_sid,
                          recall_cb, recall_sid, recall_fh);
}

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

    EXPECT_EQ(open_file_simple(mgr, clientid, owner, 1, fh, OPEN4_SHARE_ACCESS_READ,
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

TEST(Nfs4State, BadSeqid) {
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

    EXPECT_EQ(open_file_simple(mgr, clientid, owner, 1, fh, OPEN4_SHARE_ACCESS_READ,
                             OPEN4_SHARE_DENY_NONE, stateid, needs_confirm),
              Nfs4Stat::NFS4_OK);

    // Confirm with wrong seqid (should be 2, using 5)
    Nfs4StateId confirmed_sid;
    EXPECT_EQ(mgr.confirm_open(stateid, 5, confirmed_sid), Nfs4Stat::NFS4ERR_BAD_SEQID);

    // Confirm with correct seqid
    EXPECT_EQ(mgr.confirm_open(stateid, 2, confirmed_sid), Nfs4Stat::NFS4_OK);

    // Close with wrong seqid (should be 3, using 1)
    Nfs4StateId closed_sid;
    EXPECT_EQ(mgr.close_file(confirmed_sid, 1, closed_sid), Nfs4Stat::NFS4ERR_BAD_SEQID);

    // Close with correct seqid
    EXPECT_EQ(mgr.close_file(confirmed_sid, 3, closed_sid), Nfs4Stat::NFS4_OK);
}

// --- Lock tests ---

// Helper: set up a confirmed client and open state for lock testing
struct LockTestFixture {
    Nfs4StateManager mgr;
    uint64_t clientid = 0;
    Nfs4StateId open_stateid;
    FileHandle fh;
    uint32_t next_open_seqid = 0;

    LockTestFixture() {
        uint8_t verifier[8] = {1};
        std::vector<uint8_t> cid = {1};
        auto [cid_out, confirm] = mgr.set_clientid(verifier, cid);
        clientid = cid_out;
        mgr.confirm_clientid(clientid, confirm.data());

        fh.len = 16;
        fh.data[0] = 42;
        std::vector<uint8_t> owner = {1, 2, 3};
        bool needs_confirm = false;

        open_file_simple(mgr, clientid, owner, 1, fh, OPEN4_SHARE_ACCESS_BOTH,
                         OPEN4_SHARE_DENY_NONE, open_stateid, needs_confirm);
        Nfs4StateId confirmed_sid;
        mgr.confirm_open(open_stateid, 2, confirmed_sid);
        open_stateid = confirmed_sid;
        next_open_seqid = 3;
    }
};

TEST(Nfs4Lock, WriteWriteConflict) {
    LockTestFixture f;
    Nfs4LockOwner owner1{f.clientid, {10}};
    Nfs4LockOwner owner2{f.clientid, {20}};
    Nfs4StateId lock_sid1, lock_sid2;
    Nfs4LockDenied denied;

    // Owner1 gets a WRITE lock [0, 100)
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner1, 0, f.fh, WRITE_LT, 0, 100,
                              lock_sid1, denied), Nfs4Stat::NFS4_OK);

    // Owner2 tries overlapping WRITE lock → DENIED
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner2, 0, f.fh, WRITE_LT, 50, 100,
                              lock_sid2, denied), Nfs4Stat::NFS4ERR_DENIED);
    EXPECT_EQ(denied.locktype, WRITE_LT);
    EXPECT_EQ(denied.offset, 0u);
    EXPECT_EQ(denied.length, 100u);
}

TEST(Nfs4Lock, ReadReadNoConflict) {
    LockTestFixture f;
    Nfs4LockOwner owner1{f.clientid, {10}};
    Nfs4LockOwner owner2{f.clientid, {20}};
    Nfs4StateId lock_sid1, lock_sid2;
    Nfs4LockDenied denied;

    // Owner1 READ lock
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner1, 0, f.fh, READ_LT, 0, 100,
                              lock_sid1, denied), Nfs4Stat::NFS4_OK);

    // Owner2 READ lock on same range → OK
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner2, 0, f.fh, READ_LT, 0, 100,
                              lock_sid2, denied), Nfs4Stat::NFS4_OK);
}

TEST(Nfs4Lock, ReadWriteConflict) {
    LockTestFixture f;
    Nfs4LockOwner owner1{f.clientid, {10}};
    Nfs4LockOwner owner2{f.clientid, {20}};
    Nfs4StateId lock_sid1, lock_sid2;
    Nfs4LockDenied denied;

    // Owner1 READ lock
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner1, 0, f.fh, READ_LT, 0, 100,
                              lock_sid1, denied), Nfs4Stat::NFS4_OK);

    // Owner2 WRITE lock → DENIED
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner2, 0, f.fh, WRITE_LT, 0, 100,
                              lock_sid2, denied), Nfs4Stat::NFS4ERR_DENIED);
}

TEST(Nfs4Lock, SameOwnerNoConflict) {
    LockTestFixture f;
    Nfs4LockOwner owner1{f.clientid, {10}};
    Nfs4StateId lock_sid;
    Nfs4LockDenied denied;

    // Same owner can hold overlapping READ+WRITE
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner1, 0, f.fh, READ_LT, 0, 100,
                              lock_sid, denied), Nfs4Stat::NFS4_OK);

    // Same owner, WRITE on overlapping range → OK
    Nfs4StateId lock_sid2;
    EXPECT_EQ(f.mgr.lock_existing(lock_sid, 1, WRITE_LT, 50, 100,
                                   lock_sid2, denied), Nfs4Stat::NFS4_OK);
}

TEST(Nfs4Lock, LockUnlockRelock) {
    LockTestFixture f;
    Nfs4LockOwner owner1{f.clientid, {10}};
    Nfs4LockOwner owner2{f.clientid, {20}};
    Nfs4StateId lock_sid, lock_sid2;
    Nfs4LockDenied denied;

    // Owner1 WRITE lock [0, 100)
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner1, 0, f.fh, WRITE_LT, 0, 100,
                              lock_sid, denied), Nfs4Stat::NFS4_OK);

    // Unlock it
    Nfs4StateId unlocked_sid;
    EXPECT_EQ(f.mgr.lock_unlock(lock_sid, 1, 0, 100, unlocked_sid), Nfs4Stat::NFS4_OK);

    // Now owner2 can lock the same range
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner2, 0, f.fh, WRITE_LT, 0, 100,
                              lock_sid2, denied), Nfs4Stat::NFS4_OK);
}

TEST(Nfs4Lock, BadSeqid) {
    LockTestFixture f;
    Nfs4LockOwner owner1{f.clientid, {10}};
    Nfs4StateId lock_sid;
    Nfs4LockDenied denied;

    // Get a lock
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner1, 0, f.fh, WRITE_LT, 0, 100,
                              lock_sid, denied), Nfs4Stat::NFS4_OK);

    // Try to extend with wrong seqid
    Nfs4StateId lock_sid2;
    EXPECT_EQ(f.mgr.lock_existing(lock_sid, 99, WRITE_LT, 200, 100,
                                   lock_sid2, denied), Nfs4Stat::NFS4ERR_BAD_SEQID);

    // Try unlock with wrong seqid
    Nfs4StateId unlocked_sid;
    EXPECT_EQ(f.mgr.lock_unlock(lock_sid, 99, 0, 100, unlocked_sid),
              Nfs4Stat::NFS4ERR_BAD_SEQID);
}

TEST(Nfs4Lock, LockTest) {
    LockTestFixture f;
    Nfs4LockOwner owner1{f.clientid, {10}};
    Nfs4LockOwner owner2{f.clientid, {20}};
    Nfs4StateId lock_sid;
    Nfs4LockDenied denied;

    // Owner1 WRITE lock
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner1, 0, f.fh, WRITE_LT, 0, 100,
                              lock_sid, denied), Nfs4Stat::NFS4_OK);

    // LOCKT from owner2 → DENIED (no state change)
    EXPECT_EQ(f.mgr.lock_test(f.fh, WRITE_LT, 0, 100, owner2, denied),
              Nfs4Stat::NFS4ERR_DENIED);
    EXPECT_EQ(denied.owner.owner, owner1.owner);

    // LOCKT for non-overlapping range → OK
    EXPECT_EQ(f.mgr.lock_test(f.fh, WRITE_LT, 200, 100, owner2, denied),
              Nfs4Stat::NFS4_OK);
}

TEST(Nfs4Lock, ReleaseLockOwner) {
    LockTestFixture f;
    Nfs4LockOwner owner1{f.clientid, {10}};
    Nfs4LockOwner owner2{f.clientid, {20}};
    Nfs4StateId lock_sid;
    Nfs4LockDenied denied;

    // Owner1 WRITE lock
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner1, 0, f.fh, WRITE_LT, 0, 100,
                              lock_sid, denied), Nfs4Stat::NFS4_OK);

    // Release owner1's lock state
    EXPECT_EQ(f.mgr.release_lock_owner(owner1), Nfs4Stat::NFS4_OK);

    // Now owner2 can lock the range
    Nfs4StateId lock_sid2;
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner2, 0, f.fh, WRITE_LT, 0, 100,
                              lock_sid2, denied), Nfs4Stat::NFS4_OK);
}

TEST(Nfs4Lock, CloseWithLocksHeld) {
    LockTestFixture f;
    Nfs4LockOwner owner1{f.clientid, {10}};
    Nfs4StateId lock_sid;
    Nfs4LockDenied denied;

    // Take a lock
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner1, 0, f.fh, WRITE_LT, 0, 100,
                              lock_sid, denied), Nfs4Stat::NFS4_OK);

    // CLOSE should fail with LOCKS_HELD
    Nfs4StateId closed_sid;
    EXPECT_EQ(f.mgr.close_file(f.open_stateid, f.next_open_seqid,
                                closed_sid), Nfs4Stat::NFS4ERR_LOCKS_HELD);

    // Unlock
    Nfs4StateId unlocked_sid;
    EXPECT_EQ(f.mgr.lock_unlock(lock_sid, 1, 0, 100, unlocked_sid), Nfs4Stat::NFS4_OK);

    // Now CLOSE succeeds
    EXPECT_EQ(f.mgr.close_file(f.open_stateid, f.next_open_seqid,
                                closed_sid), Nfs4Stat::NFS4_OK);
}

TEST(Nfs4Lock, RangeSplit) {
    LockTestFixture f;
    Nfs4LockOwner owner1{f.clientid, {10}};
    Nfs4LockOwner owner2{f.clientid, {20}};
    Nfs4LockOwner owner3{f.clientid, {30}};
    Nfs4StateId lock_sid;
    Nfs4LockDenied denied;

    // Owner1 WRITE lock [0, 1000)
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner1, 0, f.fh, WRITE_LT, 0, 1000,
                              lock_sid, denied), Nfs4Stat::NFS4_OK);

    // Unlock middle [300, 600) — splits into [0,300) and [600,1000)
    Nfs4StateId unlocked_sid;
    EXPECT_EQ(f.mgr.lock_unlock(lock_sid, 1, 300, 300, unlocked_sid), Nfs4Stat::NFS4_OK);

    // Owner2 can lock the gap [300, 600)
    Nfs4StateId lock_sid2;
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner2, 0, f.fh, WRITE_LT, 300, 300,
                              lock_sid2, denied), Nfs4Stat::NFS4_OK);

    // Owner3 cannot lock [0, 100) — still held by owner1
    Nfs4StateId lock_sid3;
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner3, 0, f.fh, WRITE_LT, 0, 100,
                              lock_sid3, denied), Nfs4Stat::NFS4ERR_DENIED);

    // Owner3 cannot lock [600, 700) — still held by owner1
    Nfs4StateId lock_sid4;
    EXPECT_EQ(f.mgr.lock_new(f.clientid, f.open_stateid, f.next_open_seqid++,
                              owner3, 0, f.fh, WRITE_LT, 600, 100,
                              lock_sid4, denied), Nfs4Stat::NFS4ERR_DENIED);
}

// --- Callback tests ---

TEST(Nfs4Callback, ParseUniversalAddr) {
    std::string host;
    uint16_t port;
    EXPECT_TRUE(parse_universal_addr("192.168.1.1.8.1", host, port));
    EXPECT_EQ(host, "192.168.1.1");
    EXPECT_EQ(port, 8u * 256 + 1);  // 2049
}

TEST(Nfs4Callback, ParseUniversalAddrZeroPort) {
    std::string host;
    uint16_t port;
    EXPECT_TRUE(parse_universal_addr("10.0.0.1.0.0", host, port));
    EXPECT_EQ(host, "10.0.0.1");
    EXPECT_EQ(port, 0u);
}

TEST(Nfs4Callback, ParseUniversalAddrBad) {
    std::string host;
    uint16_t port;
    EXPECT_FALSE(parse_universal_addr("192.168.1.1.8", host, port));     // too short
    EXPECT_FALSE(parse_universal_addr("192.168.1.1.8.1.2", host, port)); // too long
    EXPECT_FALSE(parse_universal_addr("192.168.1.1.256.0", host, port)); // overflow
    EXPECT_FALSE(parse_universal_addr("", host, port));                   // empty
}

// --- Delegation tests ---

// Helper: create a client with valid callback info
static uint64_t setup_client_with_cb(Nfs4StateManager& mgr) {
    uint8_t verifier[8] = {1};
    std::vector<uint8_t> cid = {1};
    Nfs4CallbackInfo cb;
    cb.cb_program = NFS4_CALLBACK;
    cb.r_netid = "tcp";
    cb.r_addr = "127.0.0.1.8.1";
    cb.callback_ident = 1;
    cb.valid = true;
    auto [clientid, confirm] = mgr.set_clientid(verifier, cid, cb);
    mgr.confirm_clientid(clientid, confirm.data());
    return clientid;
}

static uint64_t setup_client_no_cb(Nfs4StateManager& mgr,
                                    std::vector<uint8_t> cid_bytes = {2}) {
    uint8_t verifier[8] = {2};
    Nfs4CallbackInfo cb;  // cb.valid = false
    auto [clientid, confirm] = mgr.set_clientid(verifier, cid_bytes, cb);
    mgr.confirm_clientid(clientid, confirm.data());
    return clientid;
}

TEST(Nfs4Deleg, GrantReadDelegation) {
    Nfs4StateManager mgr;
    mgr.end_grace_period();
    uint64_t clientid = setup_client_with_cb(mgr);

    FileHandle fh; fh.len = 16; fh.data[0] = 1;
    std::vector<uint8_t> owner = {1};
    Nfs4StateId open_sid, deleg_sid;
    bool needs_confirm;
    uint32_t deleg_type;
    Nfs4CallbackInfo recall_cb;
    Nfs4StateId recall_sid;
    FileHandle recall_fh;

    EXPECT_EQ(mgr.open_file(clientid, owner, 1, fh,
                             OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE,
                             open_sid, needs_confirm,
                             deleg_type, deleg_sid,
                             recall_cb, recall_sid, recall_fh),
              Nfs4Stat::NFS4_OK);
    EXPECT_EQ(deleg_type, OPEN_DELEGATE_READ);
    EXPECT_NE(deleg_sid.seqid, 0u);
}

TEST(Nfs4Deleg, GrantWriteDelegation) {
    Nfs4StateManager mgr;
    mgr.end_grace_period();
    uint64_t clientid = setup_client_with_cb(mgr);

    FileHandle fh; fh.len = 16; fh.data[0] = 1;
    std::vector<uint8_t> owner = {1};
    Nfs4StateId open_sid, deleg_sid;
    bool needs_confirm;
    uint32_t deleg_type;
    Nfs4CallbackInfo recall_cb;
    Nfs4StateId recall_sid;
    FileHandle recall_fh;

    EXPECT_EQ(mgr.open_file(clientid, owner, 1, fh,
                             OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_NONE,
                             open_sid, needs_confirm,
                             deleg_type, deleg_sid,
                             recall_cb, recall_sid, recall_fh),
              Nfs4Stat::NFS4_OK);
    EXPECT_EQ(deleg_type, OPEN_DELEGATE_WRITE);
}

TEST(Nfs4Deleg, NoGrantWithoutCallback) {
    Nfs4StateManager mgr;
    mgr.end_grace_period();
    uint64_t clientid = setup_client_no_cb(mgr, {1});

    FileHandle fh; fh.len = 16; fh.data[0] = 1;
    std::vector<uint8_t> owner = {1};
    Nfs4StateId open_sid, deleg_sid;
    bool needs_confirm;
    uint32_t deleg_type;
    Nfs4CallbackInfo recall_cb;
    Nfs4StateId recall_sid;
    FileHandle recall_fh;

    mgr.open_file(clientid, owner, 1, fh,
                  OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE,
                  open_sid, needs_confirm,
                  deleg_type, deleg_sid,
                  recall_cb, recall_sid, recall_fh);
    EXPECT_EQ(deleg_type, OPEN_DELEGATE_NONE);
}

TEST(Nfs4Deleg, NoGrantOtherClientOpen) {
    Nfs4StateManager mgr;
    mgr.end_grace_period();
    uint64_t client1 = setup_client_with_cb(mgr);
    uint64_t client2 = setup_client_no_cb(mgr, {2});

    FileHandle fh; fh.len = 16; fh.data[0] = 1;
    Nfs4StateId open_sid, deleg_sid;
    bool needs_confirm;
    uint32_t deleg_type;
    Nfs4CallbackInfo recall_cb;
    Nfs4StateId recall_sid;
    FileHandle recall_fh;

    // Client2 opens first (no delegation, no cb)
    std::vector<uint8_t> owner2 = {2};
    mgr.open_file(client2, owner2, 1, fh,
                  OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE,
                  open_sid, needs_confirm,
                  deleg_type, deleg_sid,
                  recall_cb, recall_sid, recall_fh);

    // Client1 opens — should not get delegation since client2 has file open
    std::vector<uint8_t> owner1 = {1};
    mgr.open_file(client1, owner1, 1, fh,
                  OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE,
                  open_sid, needs_confirm,
                  deleg_type, deleg_sid,
                  recall_cb, recall_sid, recall_fh);
    EXPECT_EQ(deleg_type, OPEN_DELEGATE_NONE);
}

TEST(Nfs4Deleg, DelegReturn) {
    Nfs4StateManager mgr;
    mgr.end_grace_period();
    uint64_t clientid = setup_client_with_cb(mgr);

    FileHandle fh; fh.len = 16; fh.data[0] = 1;
    std::vector<uint8_t> owner = {1};
    Nfs4StateId open_sid, deleg_sid;
    bool needs_confirm;
    uint32_t deleg_type;
    Nfs4CallbackInfo recall_cb;
    Nfs4StateId recall_sid;
    FileHandle recall_fh;

    mgr.open_file(clientid, owner, 1, fh,
                  OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE,
                  open_sid, needs_confirm,
                  deleg_type, deleg_sid,
                  recall_cb, recall_sid, recall_fh);
    ASSERT_EQ(deleg_type, OPEN_DELEGATE_READ);

    // DELEGRETURN
    EXPECT_EQ(mgr.delegreturn(deleg_sid), Nfs4Stat::NFS4_OK);

    // Delegation stateid should now be invalid
    EXPECT_EQ(mgr.validate_stateid(deleg_sid, OPEN4_SHARE_ACCESS_READ),
              Nfs4Stat::NFS4ERR_BAD_STATEID);
}

TEST(Nfs4Deleg, DelegPurge) {
    Nfs4StateManager mgr;
    mgr.end_grace_period();
    uint64_t clientid = setup_client_with_cb(mgr);

    FileHandle fh; fh.len = 16; fh.data[0] = 1;
    std::vector<uint8_t> owner = {1};
    Nfs4StateId open_sid, deleg_sid;
    bool needs_confirm;
    uint32_t deleg_type;
    Nfs4CallbackInfo recall_cb;
    Nfs4StateId recall_sid;
    FileHandle recall_fh;

    mgr.open_file(clientid, owner, 1, fh,
                  OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE,
                  open_sid, needs_confirm,
                  deleg_type, deleg_sid,
                  recall_cb, recall_sid, recall_fh);
    ASSERT_EQ(deleg_type, OPEN_DELEGATE_READ);

    // DELEGPURGE removes all delegations for client
    EXPECT_EQ(mgr.delegpurge(clientid), Nfs4Stat::NFS4_OK);
    EXPECT_EQ(mgr.validate_stateid(deleg_sid, OPEN4_SHARE_ACCESS_READ),
              Nfs4Stat::NFS4ERR_BAD_STATEID);
}

TEST(Nfs4Deleg, ConflictTriggerDelay) {
    Nfs4StateManager mgr;
    mgr.end_grace_period();
    uint64_t client1 = setup_client_with_cb(mgr);
    uint64_t client2 = setup_client_no_cb(mgr, {2});

    FileHandle fh; fh.len = 16; fh.data[0] = 1;
    Nfs4StateId open_sid, deleg_sid;
    bool needs_confirm;
    uint32_t deleg_type;
    Nfs4CallbackInfo recall_cb;
    Nfs4StateId recall_sid;
    FileHandle recall_fh;

    // Client1 opens and gets write delegation
    std::vector<uint8_t> owner1 = {1};
    EXPECT_EQ(mgr.open_file(client1, owner1, 1, fh,
                             OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_NONE,
                             open_sid, needs_confirm,
                             deleg_type, deleg_sid,
                             recall_cb, recall_sid, recall_fh),
              Nfs4Stat::NFS4_OK);
    ASSERT_EQ(deleg_type, OPEN_DELEGATE_WRITE);

    // Client2 opens same file — conflicts with delegation → NFS4ERR_DELAY
    std::vector<uint8_t> owner2 = {2};
    Nfs4StateId open_sid2, deleg_sid2;
    EXPECT_EQ(mgr.open_file(client2, owner2, 1, fh,
                             OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE,
                             open_sid2, needs_confirm,
                             deleg_type, deleg_sid2,
                             recall_cb, recall_sid, recall_fh),
              Nfs4Stat::NFS4ERR_DELAY);

    // Simulate DELEGRETURN from client1
    EXPECT_EQ(mgr.delegreturn(deleg_sid), Nfs4Stat::NFS4_OK);

    // Client2 retries — should succeed now
    EXPECT_EQ(mgr.open_file(client2, owner2, 1, fh,
                             OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE,
                             open_sid2, needs_confirm,
                             deleg_type, deleg_sid2,
                             recall_cb, recall_sid, recall_fh),
              Nfs4Stat::NFS4_OK);
}

TEST(Nfs4Deleg, ValidateDelegStateid) {
    Nfs4StateManager mgr;
    mgr.end_grace_period();
    uint64_t clientid = setup_client_with_cb(mgr);

    FileHandle fh; fh.len = 16; fh.data[0] = 1;
    std::vector<uint8_t> owner = {1};
    Nfs4StateId open_sid, deleg_sid;
    bool needs_confirm;
    uint32_t deleg_type;
    Nfs4CallbackInfo recall_cb;
    Nfs4StateId recall_sid;
    FileHandle recall_fh;

    // Get read delegation
    mgr.open_file(clientid, owner, 1, fh,
                  OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE,
                  open_sid, needs_confirm,
                  deleg_type, deleg_sid,
                  recall_cb, recall_sid, recall_fh);
    ASSERT_EQ(deleg_type, OPEN_DELEGATE_READ);

    // Read delegation validates for read
    EXPECT_EQ(mgr.validate_stateid(deleg_sid, OPEN4_SHARE_ACCESS_READ),
              Nfs4Stat::NFS4_OK);
    // Read delegation does NOT validate for write
    EXPECT_EQ(mgr.validate_stateid(deleg_sid, OPEN4_SHARE_ACCESS_WRITE),
              Nfs4Stat::NFS4ERR_ACCESS);
}

TEST(Nfs4Deleg, InvalidateClientCallback) {
    Nfs4StateManager mgr;
    mgr.end_grace_period();
    uint64_t clientid = setup_client_with_cb(mgr);

    // Invalidate callback
    mgr.invalidate_client_callback(clientid);

    // Now open should NOT grant delegation
    FileHandle fh; fh.len = 16; fh.data[0] = 1;
    std::vector<uint8_t> owner = {1};
    Nfs4StateId open_sid, deleg_sid;
    bool needs_confirm;
    uint32_t deleg_type;
    Nfs4CallbackInfo recall_cb;
    Nfs4StateId recall_sid;
    FileHandle recall_fh;

    mgr.open_file(clientid, owner, 1, fh,
                  OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE,
                  open_sid, needs_confirm,
                  deleg_type, deleg_sid,
                  recall_cb, recall_sid, recall_fh);
    EXPECT_EQ(deleg_type, OPEN_DELEGATE_NONE);
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

// --- Grace period tests ---

TEST(Nfs4Grace, GracePeriodActive) {
    Nfs4StateManager mgr;
    EXPECT_TRUE(mgr.in_grace_period());
}

TEST(Nfs4Grace, EndGracePeriod) {
    Nfs4StateManager mgr;
    EXPECT_TRUE(mgr.in_grace_period());
    mgr.end_grace_period();
    EXPECT_FALSE(mgr.in_grace_period());
}

TEST(Nfs4Grace, ClaimNullDuringGrace) {
    // During grace period, open_file (CLAIM_NULL semantics) should still succeed
    // at the state manager level — the CLAIM_NULL → NFS4ERR_GRACE check is in op_open.
    // But we can verify the state manager starts in grace period.
    Nfs4StateManager mgr;
    EXPECT_TRUE(mgr.in_grace_period());

    // After ending grace, open should work normally
    mgr.end_grace_period();
    uint8_t verifier[8] = {1};
    std::vector<uint8_t> cid = {1};
    auto [clientid, confirm] = mgr.set_clientid(verifier, cid);
    mgr.confirm_clientid(clientid, confirm.data());

    FileHandle fh; fh.len = 16; fh.data[0] = 1;
    std::vector<uint8_t> owner = {1};
    Nfs4StateId stateid;
    bool needs_confirm;
    uint32_t deleg_type;
    Nfs4StateId deleg_sid;
    Nfs4CallbackInfo recall_cb;
    Nfs4StateId recall_sid;
    FileHandle recall_fh;

    EXPECT_EQ(mgr.open_file(clientid, owner, 1, fh,
                             OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE,
                             stateid, needs_confirm,
                             deleg_type, deleg_sid,
                             recall_cb, recall_sid, recall_fh),
              Nfs4Stat::NFS4_OK);
}

TEST(Nfs4Grace, ClaimPreviousDuringGrace) {
    // During grace period, CLAIM_PREVIOUS should be allowed.
    // The state manager open_file doesn't know about claim types —
    // the server checks grace period and calls open_file.
    // Here we verify the grace period flag works correctly.
    Nfs4StateManager mgr;
    EXPECT_TRUE(mgr.in_grace_period());

    // Set up client during grace (SETCLIENTID is allowed during grace)
    uint8_t verifier[8] = {1};
    std::vector<uint8_t> cid = {1};
    auto [clientid, confirm] = mgr.set_clientid(verifier, cid);
    mgr.confirm_clientid(clientid, confirm.data());

    // open_file works at state manager level even during grace
    // (the grace check is at the server level per claim type)
    FileHandle fh; fh.len = 16; fh.data[0] = 1;
    std::vector<uint8_t> owner = {1};
    Nfs4StateId stateid;
    bool needs_confirm;
    uint32_t deleg_type;
    Nfs4StateId deleg_sid;
    Nfs4CallbackInfo recall_cb;
    Nfs4StateId recall_sid;
    FileHandle recall_fh;

    EXPECT_EQ(mgr.open_file(clientid, owner, 1, fh,
                             OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE,
                             stateid, needs_confirm,
                             deleg_type, deleg_sid,
                             recall_cb, recall_sid, recall_fh),
              Nfs4Stat::NFS4_OK);
}

TEST(Nfs4Grace, ClaimPreviousAfterGrace) {
    // After grace period ends, in_grace_period() returns false
    Nfs4StateManager mgr;
    mgr.end_grace_period();
    EXPECT_FALSE(mgr.in_grace_period());
}

TEST(Nfs4Grace, SetclientidDuringGrace) {
    // SETCLIENTID and CONFIRM should work during grace period
    Nfs4StateManager mgr;
    EXPECT_TRUE(mgr.in_grace_period());

    uint8_t verifier[8] = {1};
    std::vector<uint8_t> cid = {1};
    auto [clientid, confirm] = mgr.set_clientid(verifier, cid);
    EXPECT_EQ(mgr.confirm_clientid(clientid, confirm.data()), Nfs4Stat::NFS4_OK);
}

TEST(Nfs4Grace, RenewDuringGrace) {
    // RENEW should work during grace period
    Nfs4StateManager mgr;
    EXPECT_TRUE(mgr.in_grace_period());

    uint8_t verifier[8] = {1};
    std::vector<uint8_t> cid = {1};
    auto [clientid, confirm] = mgr.set_clientid(verifier, cid);
    mgr.confirm_clientid(clientid, confirm.data());

    EXPECT_EQ(mgr.renew(clientid), Nfs4Stat::NFS4_OK);
}

// --- SECINFO tests ---

TEST(Nfs4Ops, SecinfoOpcode) {
    // Verify OP_SECINFO is defined with the correct opcode value (33)
    EXPECT_EQ(static_cast<uint32_t>(Nfs4Op::OP_SECINFO), 33u);
}
