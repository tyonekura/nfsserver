#pragma once

#include <cstdint>

// RFC 1813 Appendix I - MOUNT v3 procedure numbers
constexpr uint32_t MOUNTPROC3_NULL   = 0;  // RFC 1813 §A.5.1 - Procedure 0: Null
constexpr uint32_t MOUNTPROC3_MNT    = 1;  // RFC 1813 §A.5.2 - Procedure 1: MNT
constexpr uint32_t MOUNTPROC3_DUMP   = 2;  // RFC 1813 §A.5.3 - Procedure 2: DUMP
constexpr uint32_t MOUNTPROC3_UMNT   = 3;  // RFC 1813 §A.5.4 - Procedure 3: UMNT
constexpr uint32_t MOUNTPROC3_UMNTALL = 4; // RFC 1813 §A.5.5 - Procedure 4: UMNTALL
constexpr uint32_t MOUNTPROC3_EXPORT = 5;  // RFC 1813 §A.5.6 - Procedure 5: EXPORT

// RFC 1813 Appendix I - mountstat3
enum class MountStat3 : uint32_t {
    MNT3_OK             = 0,
    MNT3ERR_PERM        = 1,
    MNT3ERR_NOENT       = 2,
    MNT3ERR_IO          = 5,
    MNT3ERR_ACCES       = 13,
    MNT3ERR_NOTDIR      = 20,
    MNT3ERR_INVAL       = 22,
    MNT3ERR_NAMETOOLONG = 63,
    MNT3ERR_NOTSUPP     = 10004,
    MNT3ERR_SERVERFAULT = 10006,
};
