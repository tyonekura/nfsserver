#pragma once

#include <cstdint>

// MOUNT v3 protocol constants per RFC 1813 Appendix I
constexpr uint32_t MOUNTPROC3_NULL   = 0;
constexpr uint32_t MOUNTPROC3_MNT    = 1;
constexpr uint32_t MOUNTPROC3_DUMP   = 2;
constexpr uint32_t MOUNTPROC3_UMNT   = 3;
constexpr uint32_t MOUNTPROC3_UMNTALL = 4;
constexpr uint32_t MOUNTPROC3_EXPORT = 5;

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
