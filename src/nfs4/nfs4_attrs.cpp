#include "nfs4/nfs4_attrs.h"
#include <pwd.h>
#include <grp.h>
#include <string>

// RFC 7530 §5.8.2.2 - owner/owner_group as "user@domain" strings
static const std::string nfs4_domain = "localdomain";

static std::string uid_to_owner(uint32_t uid) {
    struct passwd* pw = getpwuid(uid);
    if (pw)
        return std::string(pw->pw_name) + "@" + nfs4_domain;
    return std::to_string(uid);
}

static std::string gid_to_group(uint32_t gid) {
    struct group* gr = getgrgid(gid);
    if (gr)
        return std::string(gr->gr_name) + "@" + nfs4_domain;
    return std::to_string(gid);
}

static uint32_t owner_to_uid(const std::string& owner_str) {
    // Strip @domain if present
    std::string name = owner_str;
    auto at = name.find('@');
    if (at != std::string::npos)
        name = name.substr(0, at);

    // Try numeric first
    try { return static_cast<uint32_t>(std::stoul(name)); } catch (...) {}

    // Try passwd lookup
    struct passwd* pw = getpwnam(name.c_str());
    if (pw) return pw->pw_uid;
    return UINT32_MAX;
}

static uint32_t group_to_gid(const std::string& group_str) {
    std::string name = group_str;
    auto at = name.find('@');
    if (at != std::string::npos)
        name = name.substr(0, at);

    try { return static_cast<uint32_t>(std::stoul(name)); } catch (...) {}

    struct group* gr = getgrnam(name.c_str());
    if (gr) return gr->gr_gid;
    return UINT32_MAX;
}

// RFC 7530 §5.8 - NFSv4 bitmap-based attribute encoding

std::vector<uint32_t> decode_bitmap(XdrDecoder& dec) {
    uint32_t count = dec.decode_uint32();
    std::vector<uint32_t> bm(count);
    for (uint32_t i = 0; i < count; i++)
        bm[i] = dec.decode_uint32();
    return bm;
}

void encode_bitmap(XdrEncoder& enc, const std::vector<uint32_t>& bm) {
    // Trim trailing zero words
    size_t len = bm.size();
    while (len > 0 && bm[len - 1] == 0) len--;
    enc.encode_uint32(static_cast<uint32_t>(len));
    for (size_t i = 0; i < len; i++)
        enc.encode_uint32(bm[i]);
}

std::vector<uint32_t> get_supported_bitmap() {
    std::vector<uint32_t> bm(2, 0);

    // Word 0 attributes (bits 0-31)
    bitmap_set(bm, FATTR4_SUPPORTED_ATTRS);  // 0
    bitmap_set(bm, FATTR4_TYPE);             // 1
    bitmap_set(bm, FATTR4_FH_EXPIRE_TYPE);   // 2
    bitmap_set(bm, FATTR4_CHANGE);           // 3
    bitmap_set(bm, FATTR4_SIZE);             // 4
    bitmap_set(bm, FATTR4_LINK_SUPPORT);     // 5
    bitmap_set(bm, FATTR4_SYMLINK_SUPPORT);  // 6
    bitmap_set(bm, FATTR4_NAMED_ATTR);       // 7
    bitmap_set(bm, FATTR4_FSID);             // 8
    bitmap_set(bm, FATTR4_UNIQUE_HANDLES);   // 9
    bitmap_set(bm, FATTR4_LEASE_TIME);       // 10
    bitmap_set(bm, FATTR4_RDATTR_ERROR);     // 11
    bitmap_set(bm, FATTR4_ACL);             // 12
    bitmap_set(bm, FATTR4_ACLSUPPORT);     // 13
    bitmap_set(bm, FATTR4_CANSETTIME);       // 15
    bitmap_set(bm, FATTR4_CASE_INSENSITIVE); // 16
    bitmap_set(bm, FATTR4_CASE_PRESERVING);  // 17
    bitmap_set(bm, FATTR4_CHOWN_RESTRICTED); // 18
    bitmap_set(bm, FATTR4_FILEHANDLE);       // 19
    bitmap_set(bm, FATTR4_FILEID);           // 20
    bitmap_set(bm, FATTR4_FILES_AVAIL);      // 21
    bitmap_set(bm, FATTR4_FILES_FREE);       // 22
    bitmap_set(bm, FATTR4_FILES_TOTAL);      // 23
    bitmap_set(bm, FATTR4_HOMOGENEOUS);      // 26
    bitmap_set(bm, FATTR4_MAXFILESIZE);      // 27
    bitmap_set(bm, FATTR4_MAXLINK);          // 28
    bitmap_set(bm, FATTR4_MAXNAME);          // 29
    bitmap_set(bm, FATTR4_MAXREAD);          // 30
    bitmap_set(bm, FATTR4_MAXWRITE);         // 31

    // Word 1 attributes (bits 32-63)
    bitmap_set(bm, FATTR4_MODE);             // 33
    bitmap_set(bm, FATTR4_NO_TRUNC);         // 34
    bitmap_set(bm, FATTR4_NUMLINKS);         // 35
    bitmap_set(bm, FATTR4_OWNER);            // 36
    bitmap_set(bm, FATTR4_OWNER_GROUP);      // 37
    bitmap_set(bm, FATTR4_RAWDEV);           // 41
    bitmap_set(bm, FATTR4_SPACE_AVAIL);      // 42
    bitmap_set(bm, FATTR4_SPACE_FREE);       // 43
    bitmap_set(bm, FATTR4_SPACE_TOTAL);      // 44
    bitmap_set(bm, FATTR4_SPACE_USED);       // 45
    bitmap_set(bm, FATTR4_TIME_ACCESS);      // 47
    bitmap_set(bm, FATTR4_TIME_DELTA);       // 51
    bitmap_set(bm, FATTR4_TIME_METADATA);    // 52
    bitmap_set(bm, FATTR4_TIME_MODIFY);      // 53
    bitmap_set(bm, FATTR4_MOUNTED_ON_FILEID);// 55

    return bm;
}

// Helper: encode nfstime4 (int64 seconds + uint32 nseconds)
static void encode_nfstime4(XdrEncoder& enc, const NfsTime3& t) {
    enc.encode_int64(static_cast<int64_t>(t.seconds));
    enc.encode_uint32(t.nseconds);
}

// RFC 7530 §6.4.1 - Synthesize NFSv4 ACEs from POSIX mode bits
std::vector<Nfsace4> mode_to_acl(uint32_t mode, bool is_dir) {
    const uint32_t read_mask = ACE4_READ_NAMED_ATTRS | ACE4_READ_ATTRIBUTES | ACE4_READ_ACL
                             | (is_dir ? ACE4_LIST_DIRECTORY : ACE4_READ_DATA);
    const uint32_t write_mask = ACE4_WRITE_NAMED_ATTRS | ACE4_WRITE_ATTRIBUTES
                              | (is_dir ? (ACE4_ADD_FILE | ACE4_ADD_SUBDIRECTORY)
                                        : (ACE4_WRITE_DATA | ACE4_APPEND_DATA));
    const uint32_t exec_mask = ACE4_EXECUTE;

    std::vector<Nfsace4> aces;

    auto add_ace = [&](const char* who, uint32_t bits,
                       bool add_owner_perms, bool add_sync) {
        uint32_t mask = 0;
        if (bits & 04) mask |= read_mask;
        if (bits & 02) mask |= write_mask;
        if (bits & 01) mask |= exec_mask;
        if (add_owner_perms) mask |= ACE4_WRITE_ACL | ACE4_WRITE_OWNER;
        if (add_sync) mask |= ACE4_SYNCHRONIZE;
        if (mask == 0) return;
        aces.push_back({ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, mask, who});
    };

    add_ace("OWNER@",    (mode >> 6) & 07, true,  false);
    add_ace("GROUP@",    (mode >> 3) & 07, false, false);
    add_ace("EVERYONE@", (mode >> 0) & 07, false, true);

    return aces;
}

void encode_acl4(XdrEncoder& enc, const std::vector<Nfsace4>& acl) {
    enc.encode_uint32(static_cast<uint32_t>(acl.size()));
    for (const auto& ace : acl) {
        enc.encode_uint32(ace.type);
        enc.encode_uint32(ace.flag);
        enc.encode_uint32(ace.access_mask);
        enc.encode_string(ace.who);
    }
}

uint32_t decode_acl4_to_mode(XdrDecoder& dec) {
    uint32_t count = dec.decode_uint32();
    uint32_t owner_bits = 0, group_bits = 0, other_bits = 0;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t type = dec.decode_uint32();
        dec.decode_uint32();  // flag
        uint32_t access_mask = dec.decode_uint32();
        std::string who = dec.decode_string();

        if (type != ACE4_ACCESS_ALLOWED_ACE_TYPE) continue;

        uint32_t bits = 0;
        if (access_mask & ACE4_READ_DATA)  bits |= 04;
        if (access_mask & ACE4_WRITE_DATA) bits |= 02;
        if (access_mask & ACE4_EXECUTE)    bits |= 01;

        if      (who == "OWNER@")    owner_bits = bits;
        else if (who == "GROUP@")    group_bits = bits;
        else if (who == "EVERYONE@") other_bits = bits;
    }

    return (owner_bits << 6) | (group_bits << 3) | other_bits;
}

void encode_fattr4(XdrEncoder& enc,
                   const std::vector<uint32_t>& requested,
                   const Fattr3& attr,
                   const FileHandle& fh) {
    // Compute result bitmap = requested AND supported
    auto supported = get_supported_bitmap();
    std::vector<uint32_t> result(std::max(requested.size(), supported.size()), 0);
    for (size_t i = 0; i < result.size(); i++) {
        uint32_t r = (i < requested.size()) ? requested[i] : 0;
        uint32_t s = (i < supported.size()) ? supported[i] : 0;
        result[i] = r & s;
    }

    // Encode result bitmap
    encode_bitmap(enc, result);

    // Encode attribute values into a temporary buffer, then write as opaque.
    // MUST be encoded in strict bit order (RFC 7530 §5.1).
    XdrEncoder attr_data;

    // Word 0 attributes (bits 0-31)
    if (bitmap_isset(result, FATTR4_SUPPORTED_ATTRS)) {  // 0
        encode_bitmap(attr_data, supported);
    }
    if (bitmap_isset(result, FATTR4_TYPE)) {              // 1
        attr_data.encode_uint32(static_cast<uint32_t>(ftype3_to_nfs4type(attr.type)));
    }
    if (bitmap_isset(result, FATTR4_FH_EXPIRE_TYPE)) {    // 2
        attr_data.encode_uint32(FH4_PERSISTENT);
    }
    if (bitmap_isset(result, FATTR4_CHANGE)) {            // 3
        uint64_t change = (static_cast<uint64_t>(attr.mtime.seconds) << 32) |
                          attr.mtime.nseconds;
        attr_data.encode_uint64(change);
    }
    if (bitmap_isset(result, FATTR4_SIZE)) {              // 4
        attr_data.encode_uint64(attr.size);
    }
    if (bitmap_isset(result, FATTR4_LINK_SUPPORT)) {      // 5
        attr_data.encode_bool(true);
    }
    if (bitmap_isset(result, FATTR4_SYMLINK_SUPPORT)) {   // 6
        attr_data.encode_bool(true);
    }
    if (bitmap_isset(result, FATTR4_NAMED_ATTR)) {        // 7
        attr_data.encode_bool(false);
    }
    if (bitmap_isset(result, FATTR4_FSID)) {              // 8
        attr_data.encode_uint64(attr.fsid);  // major
        attr_data.encode_uint64(0);          // minor
    }
    if (bitmap_isset(result, FATTR4_UNIQUE_HANDLES)) {    // 9
        attr_data.encode_bool(true);
    }
    if (bitmap_isset(result, FATTR4_LEASE_TIME)) {        // 10
        attr_data.encode_uint32(NFS4_LEASE_TIME);
    }
    if (bitmap_isset(result, FATTR4_RDATTR_ERROR)) {      // 11
        attr_data.encode_uint32(0); // NFS4_OK
    }
    if (bitmap_isset(result, FATTR4_ACL)) {           // 12
        bool is_dir = (attr.type == Ftype3::NF3DIR);
        auto acl = mode_to_acl(attr.mode & 07777, is_dir);
        encode_acl4(attr_data, acl);
    }
    if (bitmap_isset(result, FATTR4_ACLSUPPORT)) {    // 13
        attr_data.encode_uint32(ACL4_SUPPORT_ALLOW_ACL);
    }
    // 14 ARCHIVE - not supported
    if (bitmap_isset(result, FATTR4_CANSETTIME)) {        // 15
        attr_data.encode_bool(true);
    }
    if (bitmap_isset(result, FATTR4_CASE_INSENSITIVE)) {  // 16
        attr_data.encode_bool(false);
    }
    if (bitmap_isset(result, FATTR4_CASE_PRESERVING)) {   // 17
        attr_data.encode_bool(true);
    }
    if (bitmap_isset(result, FATTR4_CHOWN_RESTRICTED)) {  // 18
        attr_data.encode_bool(true);
    }
    if (bitmap_isset(result, FATTR4_FILEHANDLE)) {        // 19
        attr_data.encode_opaque(fh.data, fh.len);
    }
    if (bitmap_isset(result, FATTR4_FILEID)) {            // 20
        attr_data.encode_uint64(attr.fileid);
    }
    if (bitmap_isset(result, FATTR4_FILES_AVAIL)) {       // 21
        attr_data.encode_uint64(0);
    }
    if (bitmap_isset(result, FATTR4_FILES_FREE)) {        // 22
        attr_data.encode_uint64(0);
    }
    if (bitmap_isset(result, FATTR4_FILES_TOTAL)) {       // 23
        attr_data.encode_uint64(0);
    }
    // 24 FS_LOCATIONS - not supported
    // 25 HIDDEN - not supported
    if (bitmap_isset(result, FATTR4_HOMOGENEOUS)) {       // 26
        attr_data.encode_bool(true);
    }
    if (bitmap_isset(result, FATTR4_MAXFILESIZE)) {       // 27
        attr_data.encode_uint64(0x7FFFFFFFFFFFFFFF);
    }
    if (bitmap_isset(result, FATTR4_MAXLINK)) {           // 28
        attr_data.encode_uint32(32000);
    }
    if (bitmap_isset(result, FATTR4_MAXNAME)) {           // 29
        attr_data.encode_uint32(255);
    }
    if (bitmap_isset(result, FATTR4_MAXREAD)) {           // 30
        attr_data.encode_uint64(1048576);
    }
    if (bitmap_isset(result, FATTR4_MAXWRITE)) {          // 31
        attr_data.encode_uint64(1048576);
    }

    // Word 1 attributes (bits 32-63)
    // 32 MIMETYPE - not supported
    if (bitmap_isset(result, FATTR4_MODE)) {              // 33
        attr_data.encode_uint32(attr.mode & 07777);
    }
    if (bitmap_isset(result, FATTR4_NO_TRUNC)) {          // 34
        attr_data.encode_bool(true);
    }
    if (bitmap_isset(result, FATTR4_NUMLINKS)) {          // 35
        attr_data.encode_uint32(attr.nlink);
    }
    if (bitmap_isset(result, FATTR4_OWNER)) {             // 36
        attr_data.encode_string(uid_to_owner(attr.uid));
    }
    if (bitmap_isset(result, FATTR4_OWNER_GROUP)) {       // 37
        attr_data.encode_string(gid_to_group(attr.gid));
    }
    // 38 QUOTA_AVAIL_HARD - not supported
    // 39 QUOTA_AVAIL_SOFT - not supported
    // 40 QUOTA_USED - not supported
    if (bitmap_isset(result, FATTR4_RAWDEV)) {            // 41
        attr_data.encode_uint32(attr.rdev_major);
        attr_data.encode_uint32(attr.rdev_minor);
    }
    if (bitmap_isset(result, FATTR4_SPACE_AVAIL)) {       // 42
        attr_data.encode_uint64(0);
    }
    if (bitmap_isset(result, FATTR4_SPACE_FREE)) {        // 43
        attr_data.encode_uint64(0);
    }
    if (bitmap_isset(result, FATTR4_SPACE_TOTAL)) {       // 44
        attr_data.encode_uint64(0);
    }
    if (bitmap_isset(result, FATTR4_SPACE_USED)) {        // 45
        attr_data.encode_uint64(attr.used);
    }
    // 46 SYSTEM - not supported
    if (bitmap_isset(result, FATTR4_TIME_ACCESS)) {       // 47
        encode_nfstime4(attr_data, attr.atime);
    }
    // 48 TIME_ACCESS_SET - not in GETATTR
    // 49 TIME_BACKUP - not supported
    // 50 TIME_CREATE - not supported
    if (bitmap_isset(result, FATTR4_TIME_DELTA)) {        // 51
        // time_delta: nfstime4 representing server time granularity
        attr_data.encode_int64(0);    // seconds
        attr_data.encode_uint32(1);   // 1 nsecond granularity
    }
    if (bitmap_isset(result, FATTR4_TIME_METADATA)) {     // 52
        encode_nfstime4(attr_data, attr.ctime);
    }
    if (bitmap_isset(result, FATTR4_TIME_MODIFY)) {       // 53
        encode_nfstime4(attr_data, attr.mtime);
    }
    // 54 TIME_MODIFY_SET - not in GETATTR
    if (bitmap_isset(result, FATTR4_MOUNTED_ON_FILEID)) { // 55
        attr_data.encode_uint64(attr.fileid);
    }

    // Write attribute data as variable-length opaque
    enc.encode_opaque(attr_data.data().data(), attr_data.size());
}

Nfs4SetAttr decode_fattr4_setattr(XdrDecoder& dec) {
    Nfs4SetAttr sa;
    auto bm = decode_bitmap(dec);

    // Decode the attribute data opaque
    auto attr_bytes = dec.decode_opaque();
    XdrDecoder attr_dec(attr_bytes.data(), attr_bytes.size());

    // Decode in bitmap order (only the ones we support for SETATTR)
    if (bitmap_isset(bm, FATTR4_SIZE)) {
        sa.size = attr_dec.decode_uint64();
    }
    if (bitmap_isset(bm, FATTR4_ACL)) {               // 12
        sa.mode = decode_acl4_to_mode(attr_dec);
        sa.has_acl = true;
    }
    if (bitmap_isset(bm, FATTR4_MODE)) {
        sa.mode = attr_dec.decode_uint32();
    }
    if (bitmap_isset(bm, FATTR4_OWNER)) {
        std::string owner_str = attr_dec.decode_string();
        sa.uid = owner_to_uid(owner_str);
    }
    if (bitmap_isset(bm, FATTR4_OWNER_GROUP)) {
        std::string group_str = attr_dec.decode_string();
        sa.gid = group_to_gid(group_str);
    }
    if (bitmap_isset(bm, FATTR4_TIME_ACCESS_SET)) {
        // set_atime4: 0=SET_TO_SERVER_TIME4, 1=SET_TO_CLIENT_TIME4
        uint32_t how = attr_dec.decode_uint32();
        if (how == 1) {
            sa.atime.how = NfsTimeSet::How::SET_TO_CLIENT_TIME;
            sa.atime.time.seconds = static_cast<uint32_t>(attr_dec.decode_int64());
            sa.atime.time.nseconds = attr_dec.decode_uint32();
        } else {
            sa.atime.how = NfsTimeSet::How::SET_TO_SERVER_TIME;
        }
    }
    if (bitmap_isset(bm, FATTR4_TIME_MODIFY_SET)) {
        uint32_t how = attr_dec.decode_uint32();
        if (how == 1) {
            sa.mtime.how = NfsTimeSet::How::SET_TO_CLIENT_TIME;
            sa.mtime.time.seconds = static_cast<uint32_t>(attr_dec.decode_int64());
            sa.mtime.time.nseconds = attr_dec.decode_uint32();
        } else {
            sa.mtime.how = NfsTimeSet::How::SET_TO_SERVER_TIME;
        }
    }

    return sa;
}
