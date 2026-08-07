/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "resource_decompress.h"

#include <filesystem>
#include <fstream>

#include <zlib.h>

#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ResourceDecompress"

namespace OHOS {
namespace MMI {

namespace {
constexpr size_t CHUNK = 16 * 1024;
constexpr size_t MAX_TOTAL_SIZE = 4 * 1024 * 1024;

uint16_t ReadLE16(const uint8_t *p)
{
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t ReadLE32(const uint8_t *p)
{
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

bool DecompressGzip(const std::string &compressed, std::string &output)
{
    z_stream strm {};
    strm.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(compressed.data()));
    strm.avail_in = static_cast<uInt>(compressed.size());

    if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
        MMI_HILOGE("inflateInit2 failed");
        return false;
    }

    char buf[CHUNK];
    int ret = Z_OK;
    do {
        strm.next_out = reinterpret_cast<Bytef *>(buf);
        strm.avail_out = CHUNK;
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            MMI_HILOGE("inflate failed, ret:%{public}d", ret);
            inflateEnd(&strm);
            return false;
        }
        size_t have = CHUNK - strm.avail_out;
        output.append(buf, have);
        if (output.size() > MAX_TOTAL_SIZE) {
            MMI_HILOGE("Decompressed data exceeds %{public}zu bytes", MAX_TOTAL_SIZE);
            inflateEnd(&strm);
            return false;
        }
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);
    return true;
}

bool WriteFileToDisk(const std::string &dir, const std::string &name, const char *data, size_t len)
{
    namespace fs = std::filesystem;
    fs::path basePath = fs::path(dir).lexically_normal();
    fs::path filePath = (basePath / name).lexically_normal();

    fs::path rel = filePath.lexically_relative(basePath);
    if (rel.empty() || *rel.begin() == "..") {
        MMI_HILOGE("Path escapes base directory: %{public}s", name.c_str());
        return false;
    }

    std::ofstream ofs(filePath, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        MMI_HILOGE("Cannot create file: %{public}s", filePath.c_str());
        return false;
    }
    ofs.write(data, static_cast<std::streamsize>(len));
    if (!ofs) {
        MMI_HILOGE("Write failed: %{public}s", filePath.c_str());
        return false;
    }
    return true;
}
} // namespace

int32_t DecompressToDisk(const std::string &datPath, const std::string &destDir)
{
    namespace fs = std::filesystem;
    fs::path normalizedDatPath = fs::path(datPath).lexically_normal();
    fs::path normalizedDestDir = fs::path(destDir).lexically_normal();

    std::ifstream ifs(normalizedDatPath, std::ios::binary);
    if (!ifs.is_open()) {
        MMI_HILOGE("Cannot open dat file: %{public}s", normalizedDatPath.c_str());
        return -1;
    }
    std::string compressed((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();

    std::string decompressed;
    if (!DecompressGzip(compressed, decompressed)) {
        MMI_HILOGE("Decompress failed for: %{public}s", normalizedDatPath.c_str());
        return -1;
    }

    CleanupDirectory(normalizedDestDir.string());
    std::error_code ec;
    fs::create_directories(normalizedDestDir, ec);
    if (ec) {
        MMI_HILOGE("create_directories failed: %{public}s", ec.message().c_str());
        return -1;
    }

    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(decompressed.data());
    const uint8_t *end = ptr + decompressed.size();

    if (end - ptr < static_cast<ptrdiff_t>(sizeof(uint32_t))) {
        MMI_HILOGE("Dat file too small for header");
        return -1;
    }
    uint32_t fileCount = ReadLE32(ptr);
    ptr += sizeof(uint32_t);

    int32_t written = 0;
    for (uint32_t i = 0; i < fileCount; ++i) {
        if (end - ptr < static_cast<ptrdiff_t>(sizeof(uint16_t))) {
            MMI_HILOGE("Truncated name length at file %{public}u", i);
            return -1;
        }
        uint16_t nameLen = ReadLE16(ptr);
        ptr += sizeof(uint16_t);
        if (end - ptr < nameLen) {
            MMI_HILOGE("Truncated name at file %{public}u", i);
            return -1;
        }
        std::string name(reinterpret_cast<const char *>(ptr), nameLen);
        ptr += nameLen;

        if (end - ptr < static_cast<ptrdiff_t>(sizeof(uint32_t))) {
            MMI_HILOGE("Truncated data length at file %{public}u", i);
            return -1;
        }
        uint32_t dataLen = ReadLE32(ptr);
        ptr += sizeof(uint32_t);
        if (static_cast<size_t>(end - ptr) < dataLen) {
            MMI_HILOGE("Truncated data at file %{public}u", i);
            return -1;
        }
        if (!WriteFileToDisk(normalizedDestDir.string(), name, reinterpret_cast<const char *>(ptr), dataLen)) {
            MMI_HILOGE("Write failed: %{public}s", name.c_str());
        } else {
            ++written;
        }
        ptr += dataLen;
    }

    MMI_HILOGI("Decompressed %{public}d/%{public}u files to %{public}s", written, fileCount,
        normalizedDestDir.c_str());
    return written;
}

void CleanupDirectory(const std::string &dirPath)
{
    std::error_code ec;
    if (std::filesystem::exists(dirPath, ec)) {
        std::filesystem::remove_all(dirPath, ec);
        if (ec) {
            MMI_HILOGW("remove_all failed: %{public}s, err: %{public}s",
                dirPath.c_str(), ec.message().c_str());
        }
    }
}

} // namespace MMI
} // namespace OHOS
