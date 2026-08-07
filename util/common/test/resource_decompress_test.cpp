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

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <zlib.h>

namespace OHOS {
namespace MMI {
namespace {

using namespace testing;
using namespace testing::ext;

constexpr const char *TEST_BASE_DIR = "/data/local/tmp/mmi_res_decompress_test";

void WriteFile(const std::string &path, const std::string &content)
{
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) {
        return;
    }
    ofs << content;
    ofs.close();
}

std::string ReadFile(const std::string &path)
{
    std::ifstream ifs(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}

std::string GzipRaw(const std::string &raw)
{
    z_stream strm {};
    strm.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(raw.data()));
    strm.avail_in = static_cast<uInt>(raw.size());
    deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
        16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY);

    std::string out;
    char tmp[4096];
    int ret = Z_OK;
    do {
        strm.next_out = reinterpret_cast<Bytef *>(tmp);
        strm.avail_out = sizeof(tmp);
        ret = deflate(&strm, Z_FINISH);
        out.append(tmp, sizeof(tmp) - strm.avail_out);
    } while (ret != Z_STREAM_END);
    deflateEnd(&strm);
    return out;
}

std::string BuildRawBinary(const std::vector<std::pair<std::string, std::string>> &files)
{
    std::string buf;
    uint32_t count = static_cast<uint32_t>(files.size());
    buf.append(reinterpret_cast<const char *>(&count), sizeof(uint32_t));
    for (const auto &[name, data] : files) {
        uint16_t nameLen = static_cast<uint16_t>(name.size());
        buf.append(reinterpret_cast<const char *>(&nameLen), sizeof(uint16_t));
        buf.append(name);
        uint32_t dataLen = static_cast<uint32_t>(data.size());
        buf.append(reinterpret_cast<const char *>(&dataLen), sizeof(uint32_t));
        buf.append(data);
    }
    return buf;
}

void CreateDatFile(const std::string &datPath,
                   const std::vector<std::pair<std::string, std::string>> &files)
{
    std::filesystem::create_directories(std::filesystem::path(datPath).parent_path());
    std::string compressed = GzipRaw(BuildRawBinary(files));
    WriteFile(datPath, compressed);
}

void CreateDatFromRaw(const std::string &datPath, const std::string &raw)
{
    std::filesystem::create_directories(std::filesystem::path(datPath).parent_path());
    WriteFile(datPath, GzipRaw(raw));
}

} // namespace

class ResourceDecompressTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp() override
    {
        std::filesystem::remove_all(TEST_BASE_DIR);
        std::filesystem::create_directories(TEST_BASE_DIR);
    }
    void TearDown() override
    {
        std::filesystem::remove_all(TEST_BASE_DIR);
    }
};

/**
 * @tc.name: ResourceDecompress_Normal_001
 * @tc.desc: Decompress a valid .dat with multiple files
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_Normal_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/test.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output";
    CreateDatFile(datPath, {
        {"Default.svg", "<svg/>"},
        {"Cross.svg", "<svg>cross</svg>"},
    });

    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, 2);
    EXPECT_TRUE(std::filesystem::exists(destDir + "/Default.svg"));
    EXPECT_TRUE(std::filesystem::exists(destDir + "/Cross.svg"));
    EXPECT_EQ(ReadFile(destDir + "/Default.svg"), "<svg/>");
    EXPECT_EQ(ReadFile(destDir + "/Cross.svg"), "<svg>cross</svg>");
}

/**
 * @tc.name: ResourceDecompress_EmptyFile_001
 * @tc.desc: Decompress a .dat containing a file with empty content
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_EmptyFile_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/test.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output";
    CreateDatFile(datPath, {
        {"empty.json", ""},
    });

    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, 1);
    EXPECT_TRUE(std::filesystem::exists(destDir + "/empty.json"));
    EXPECT_EQ(ReadFile(destDir + "/empty.json"), "");
}

/**
 * @tc.name: ResourceDecompress_NoFile_001
 * @tc.desc: Decompress a .dat with zero files (fileCount=0, loop body never enters)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_NoFile_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/test.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output";
    CreateDatFile(datPath, {});

    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: ResourceDecompress_FileNotExist_001
 * @tc.desc: DecompressToDisk returns -1 when .dat does not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_FileNotExist_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/nonexistent.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output";
    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: ResourceDecompress_Corrupted_001
 * @tc.desc: DecompressToDisk returns -1 when .dat is not valid gzip
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_Corrupted_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/corrupt.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output";
    WriteFile(datPath, "this is not gzip data");

    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: ResourceDecompress_TruncatedHeader_001
 * @tc.desc: Decompressed data too small for uint32 header
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_TruncatedHeader_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/truncated.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output";
    std::string raw = BuildRawBinary({{"a.svg", "b"}});
    CreateDatFromRaw(datPath, raw.substr(0, 2));

    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: ResourceDecompress_TruncatedNameLen_001
 * @tc.desc: Has fileCount=1 but no name length bytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_TruncatedNameLen_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/truncated.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output";
    std::string raw = BuildRawBinary({{"a.svg", "b"}});
    CreateDatFromRaw(datPath, raw.substr(0, 4));

    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: ResourceDecompress_TruncatedName_001
 * @tc.desc: Has nameLen but not enough name bytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_TruncatedName_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/truncated.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output";
    std::string raw = BuildRawBinary({{"abcde", "x"}});
    CreateDatFromRaw(datPath, raw.substr(0, 7));

    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: ResourceDecompress_TruncatedDataLen_001
 * @tc.desc: Has name but no data length bytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_TruncatedDataLen_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/truncated.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output";
    std::string raw = BuildRawBinary({{"a.svg", "b"}});
    CreateDatFromRaw(datPath, raw.substr(0, 11));

    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: ResourceDecompress_TruncatedData_001
 * @tc.desc: Has dataLen but not enough data bytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_TruncatedData_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/truncated.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output";
    std::string raw = BuildRawBinary({{"a.svg", "bbbbb"}});
    CreateDatFromRaw(datPath, raw.substr(0, 15));

    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: ResourceDecompress_PathTraversal_Parent_001
 * @tc.desc: Filename with ../ escapes base directory
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_PathTraversal_Parent_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/test.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output";
    CreateDatFile(datPath, {
        {"../escape.svg", "bad"},
    });

    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, 0);
    EXPECT_FALSE(std::filesystem::exists(std::string(TEST_BASE_DIR) + "/escape.svg"));
}

/**
 * @tc.name: ResourceDecompress_PathTraversal_DeepParent_001
 * @tc.desc: Filename with ../../ escapes base directory
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_PathTraversal_DeepParent_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/test.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output/sub";
    std::filesystem::create_directories(destDir);
    CreateDatFile(datPath, {
        {"../../escape.svg", "bad"},
    });

    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, 0);
    EXPECT_FALSE(std::filesystem::exists(std::string(TEST_BASE_DIR) + "/escape.svg"));
}

/**
 * @tc.name: ResourceDecompress_PathTraversal_Normalized_001
 * @tc.desc: Filename with sub/../normal.svg normalizes safely and is accepted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_PathTraversal_Normalized_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/test.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output";
    CreateDatFile(datPath, {
        {"sub/../normal.svg", "ok"},
    });

    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, 1);
    EXPECT_TRUE(std::filesystem::exists(destDir + "/normal.svg"));
}

/**
 * @tc.name: ResourceDecompress_OverwriteExisting_001
 * @tc.desc: DecompressToDisk cleans destination directory before writing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_OverwriteExisting_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/test.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output";
    std::filesystem::create_directories(destDir);
    WriteFile(destDir + "/stale.txt", "old content");

    CreateDatFile(datPath, {{"new.svg", "new content"}});
    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, 1);
    EXPECT_FALSE(std::filesystem::exists(destDir + "/stale.txt"));
    EXPECT_TRUE(std::filesystem::exists(destDir + "/new.svg"));
}

/**
 * @tc.name: ResourceDecompress_PartialWrite_001
 * @tc.desc: Valid files mixed with rejected filenames: written count reflects only successes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, ResourceDecompress_PartialWrite_001, TestSize.Level1)
{
    std::string datPath = std::string(TEST_BASE_DIR) + "/test.dat";
    std::string destDir = std::string(TEST_BASE_DIR) + "/output";
    CreateDatFile(datPath, {
        {"good.svg", "ok"},
        {"../bad.svg", "no"},
    });

    int32_t ret = DecompressToDisk(datPath, destDir);
    EXPECT_EQ(ret, 1);
    EXPECT_TRUE(std::filesystem::exists(destDir + "/good.svg"));
    EXPECT_FALSE(std::filesystem::exists(std::string(TEST_BASE_DIR) + "/bad.svg"));
}

/**
 * @tc.name: CleanupDirectory_Normal_001
 * @tc.desc: CleanupDirectory removes existing directory tree with files and subdirs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, CleanupDirectory_Normal_001, TestSize.Level1)
{
    std::string dir = std::string(TEST_BASE_DIR) + "/toclean";
    std::filesystem::create_directories(dir + "/sub");
    WriteFile(dir + "/a.txt", "a");
    WriteFile(dir + "/sub/b.txt", "b");
    EXPECT_TRUE(std::filesystem::exists(dir));

    CleanupDirectory(dir);
    EXPECT_FALSE(std::filesystem::exists(dir));
}

/**
 * @tc.name: CleanupDirectory_NotExist_001
 * @tc.desc: CleanupDirectory on non-existent directory is a no-op
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, CleanupDirectory_NotExist_001, TestSize.Level1)
{
    std::string dir = std::string(TEST_BASE_DIR) + "/nonexistent";
    EXPECT_FALSE(std::filesystem::exists(dir));
    CleanupDirectory(dir);
    EXPECT_FALSE(std::filesystem::exists(dir));
}

/**
 * @tc.name: CleanupDirectory_EmptyDir_001
 * @tc.desc: CleanupDirectory handles empty directory
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ResourceDecompressTest, CleanupDirectory_EmptyDir_001, TestSize.Level1)
{
    std::string dir = std::string(TEST_BASE_DIR) + "/empty";
    std::filesystem::create_directories(dir);
    EXPECT_TRUE(std::filesystem::exists(dir));

    CleanupDirectory(dir);
    EXPECT_FALSE(std::filesystem::exists(dir));
}

} // namespace MMI
} // namespace OHOS
