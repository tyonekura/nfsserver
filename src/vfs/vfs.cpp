#include "vfs/vfs.h"
#include <cstring>

bool FileHandle::operator==(const FileHandle& o) const {
    return len == o.len && std::memcmp(data, o.data, len) == 0;
}

bool FileHandle::operator<(const FileHandle& o) const {
    if (len != o.len) return len < o.len;
    return std::memcmp(data, o.data, len) < 0;
}
