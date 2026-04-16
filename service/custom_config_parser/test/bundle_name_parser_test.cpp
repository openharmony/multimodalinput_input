/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <cerrno>
#include <cstring>

#include "bundle_name_parser.h"
#include "json_parser.h"

namespace OHOS {
namespace MMI {
namespace {

using namespace testing;
using namespace testing::ext;

constexpr int32_t MAX_JSON_ARRAY_SIZE = 100;
constexpr int32_t EXCEED_MAX_ARRAY_SIZE = 150;
constexpr int32_t RET_OK_VALUE = 0;
constexpr int32_t RET_ERR_VALUE = -1;
constexpr int32_t FIVE_ITEMS_ARRAY_SIZE = 5;
constexpr mode_t K_DIRECTORY_PERMISSIONS = 0755;

static std::string GetTestConfigDir()
{
    const char* tmpDir = getenv("TEST_TMP_DIR");
    if (tmpDir != nullptr && strlen(tmpDir) > 0) {
        return std::string(tmpDir);
    }
    return "/data/local/tmp/test_multimodalinput";
}

static bool CreateDirectoryRecursive(const std::string& path)
{
    if (path.empty()) {
        return false;
    }
    std::string::size_type pos = 0;
    do {
        pos = path.find('/', pos + 1);
        std::string parent = (pos == std::string::npos) ? path : path.substr(0, pos);
        if (parent.empty()) {
            continue;
        }
        struct stat st;
        if (stat(parent.c_str(), &st) != 0) {
            if (mkdir(parent.c_str(), K_DIRECTORY_PERMISSIONS) != 0 && errno != EEXIST) {
                return false;
            }
        }
    } while (pos != std::string::npos);
    return true;
}

class ScopedFileRestorer {
public:
    explicit ScopedFileRestorer(const std::string& filePath)
        : filePath_(filePath), fileExists_(false) {
        std::ifstream inFile(filePath_);
        if (inFile.good()) {
            fileExists_ = true;
            std::stringstream buffer;
            buffer << inFile.rdbuf();
            if (!inFile.fail() && !inFile.bad()) {
                originalContent_ = buffer.str();
            }
        }
        inFile.close();
    }

    ~ScopedFileRestorer() {
        if (fileExists_) {
            std::ofstream restoreFile(filePath_);
            if (restoreFile.good()) {
                restoreFile << originalContent_;
            }
            restoreFile.close();
            if (restoreFile.fail()) {
                GTEST_LOG_(ERROR) << "Failed to restore config file: " << filePath_;
            }
        } else {
            if (remove(filePath_.c_str()) != 0) {
                GTEST_LOG_(ERROR) << "Failed to remove config file: " << filePath_;
            }
        }
    }

    ScopedFileRestorer(const ScopedFileRestorer&) = delete;
    ScopedFileRestorer& operator=(const ScopedFileRestorer&) = delete;

private:
    std::string filePath_;
    bool fileExists_;
    std::string originalContent_;
};

class BundleNameParserTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;

private:
    void ResetSingletonState();
};

void BundleNameParserTest::SetUpTestCase(void)
{
}

void BundleNameParserTest::TearDownTestCase(void)
{
}

void BundleNameParserTest::SetUp(void)
{
    ResetSingletonState();
}

void BundleNameParserTest::TearDown(void)
{
    ResetSingletonState();
}

void BundleNameParserTest::ResetSingletonState()
{
}

} // namespace

/**
 * @tc.name: BundleNameParser_GetInstance_001
 * @tc.desc: Test GetInstance returns reference to singleton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_GetInstance_001, TestSize.Level1)
{
    BundleNameParser& instance1 = BundleNameParser::GetInstance();
    BundleNameParser& instance2 = BundleNameParser::GetInstance();

    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: BundleNameParser_GetBundleName_001
 * @tc.desc: Test GetBundleName returns empty when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_GetBundleName_001, TestSize.Level1)
{
    BundleNameParser& parser = BundleNameParser::GetInstance();
    EXPECT_NE(&parser, nullptr);
}

HWTEST_F(BundleNameParserTest, BundleNameParser_GetBundleName_002, TestSize.Level1)
{
    BundleNameParser& parser = BundleNameParser::GetInstance();
    std::string result = parser.GetBundleName("non_existent");
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: BundleNameParser_Init_001
 * @tc.desc: Test Init with empty JSON file path returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_Init_001, TestSize.Level1)
{
    BundleNameParser& parser = BundleNameParser::GetInstance();
    int32_t initResult = parser.Init();

    EXPECT_EQ(initResult, RET_ERR_VALUE);
}

/**
 * @tc.name: BundleNameParser_Init_002
 * @tc.desc: Test Init can be called multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_Init_002, TestSize.Level1)
{
    BundleNameParser& parser = BundleNameParser::GetInstance();
    int32_t initResult1 = parser.Init();
    int32_t initResult2 = parser.Init();

    EXPECT_EQ(initResult1, initResult2);
}

/**
 * @tc.name: BundleNameParser_JsonValid_001
 * @tc.desc: Test JSON parser with valid single item JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonValid_001, TestSize.Level1)
{
    const std::string validJson =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"placeholder1\",\"bundle_name\":\"com.example.app1\"}"
        "]}";

    JsonParser parser(validJson.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
}

/**
 * @tc.name: BundleNameParser_JsonValid_002
 * @tc.desc: Test JSON parser with valid two items JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonValid_002, TestSize.Level1)
{
    const std::string validJson =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"placeholder1\",\"bundle_name\":\"com.example.app1\"},"
        "{\"placeholder\":\"placeholder2\",\"bundle_name\":\"com.example.app2\"}"
        "]}";

    JsonParser parser(validJson.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
}

/**
 * @tc.name: BundleNameParser_JsonValid_003
 * @tc.desc: Test JSON parser with valid three items JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonValid_003, TestSize.Level1)
{
    const std::string validJson =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"placeholder1\",\"bundle_name\":\"com.example.app1\"},"
        "{\"placeholder\":\"placeholder2\",\"bundle_name\":\"com.example.app2\"},"
        "{\"placeholder\":\"placeholder3\",\"bundle_name\":\"com.example.app3\"}"
        "]}";

    JsonParser parser(validJson.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
}

/**
 * @tc.name: BundleNameParser_JsonValid_004
 * @tc.desc: Test JSON parser with five items
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonValid_004, TestSize.Level1)
{
    const std::string validJson =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"placeholder1\",\"bundle_name\":\"com.example.app1\"},"
        "{\"placeholder\":\"placeholder2\",\"bundle_name\":\"com.example.app2\"},"
        "{\"placeholder\":\"placeholder3\",\"bundle_name\":\"com.example.app3\"},"
        "{\"placeholder\":\"placeholder4\",\"bundle_name\":\"com.example.app4\"},"
        "{\"placeholder\":\"placeholder5\",\"bundle_name\":\"com.example.app5\"}"
        "]}";

    JsonParser parser(validJson.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
}

/**
 * @tc.name: BundleNameParser_JsonInvalid_001
 * @tc.desc: Test JSON parser with invalid JSON not object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonInvalid_001, TestSize.Level1)
{
    const std::string invalidJson = "[\"test\"]";
    JsonParser parser(invalidJson.c_str());
    EXPECT_FALSE(cJSON_IsObject(parser.Get()));
}

/**
 * @tc.name: BundleNameParser_JsonInvalid_002
 * @tc.desc: Test JSON parser with empty string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonInvalid_002, TestSize.Level1)
{
    const std::string emptyJson = "";
    JsonParser parser(emptyJson.c_str());
    EXPECT_FALSE(cJSON_IsObject(parser.Get()));
}

/**
 * @tc.name: BundleNameParser_JsonInvalid_003
 * @tc.desc: Test JSON parser with null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonInvalid_003, TestSize.Level1)
{
    const std::string nullJson = "null";
    JsonParser parser(nullJson.c_str());
    EXPECT_FALSE(cJSON_IsObject(parser.Get()));
}

/**
 * @tc.name: BundleNameParser_JsonInvalid_004
 * @tc.desc: Test JSON parser with malformed JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonInvalid_004, TestSize.Level1)
{
    const std::string malformedJson = "{bundle_name_map:";
    JsonParser parser(malformedJson.c_str());
    EXPECT_FALSE(cJSON_IsObject(parser.Get()));
}

/**
 * @tc.name: BundleNameParser_JsonInvalid_005
 * @tc.desc: Test JSON parser with incomplete JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonInvalid_005, TestSize.Level1)
{
    const std::string incompleteJson = "{\"bundle_name_map\":[{\"placehold";
    JsonParser parser(incompleteJson.c_str());
    EXPECT_FALSE(cJSON_IsObject(parser.Get()));
}

/**
 * @tc.name: BundleNameParser_JsonInvalid_006
 * @tc.desc: Test JSON parser with whitespace only
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonInvalid_006, TestSize.Level1)
{
    const std::string whitespaceJson = "   ";
    JsonParser parser(whitespaceJson.c_str());
    EXPECT_FALSE(cJSON_IsObject(parser.Get()));
}

/**
 * @tc.name: BundleNameParser_JsonStructure_001
 * @tc.desc: Test JSON with missing bundle_name_map key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonStructure_001, TestSize.Level1)
{
    const std::string jsonWithOtherKeys =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"placeholder1\",\"bundle_name\":\"com.example.app1\"}"
        "],"
        "\"extra_key\":\"extra_value\""
        "}";

    JsonParser parser(jsonWithOtherKeys.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));

    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_NE(bundleNameMap, nullptr);
}

/**
 * @tc.name: BundleNameParser_JsonStructure_002
 * @tc.desc: Test JSON with nested objects
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonStructure_002, TestSize.Level1)
{
    const std::string jsonWithNested =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"placeholder1\","
        "\"bundle_name\":\"com.example.app1\","
        "\"extra_field\":{\"nested\":\"value\"}}"
        "]"
        "}";

    JsonParser parser(jsonWithNested.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
}

/**
 * @tc.name: BundleNameParser_JsonStructure_003
 * @tc.desc: Test JSON with empty array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonStructure_003, TestSize.Level1)
{
    const std::string emptyArrayJson = "{\"bundle_name_map\":[]}";

    JsonParser parser(emptyArrayJson.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));

    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_TRUE(cJSON_IsArray(bundleNameMap));
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), 0);
}

/**
 * @tc.name: BundleNameParser_JsonArray_001
 * @tc.desc: Test JSON array with single item
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonArray_001, TestSize.Level1)
{
    const std::string json =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"placeholder1\",\"bundle_name\":\"com.example.app1\"}"
        "]}";

    JsonParser parser(json.c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_TRUE(cJSON_IsArray(bundleNameMap));
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), 1);
}

/**
 * @tc.name: BundleNameParser_JsonArray_002
 * @tc.desc: Test JSON array with two items
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonArray_002, TestSize.Level1)
{
    const std::string json =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"placeholder1\",\"bundle_name\":\"com.example.app1\"},"
        "{\"placeholder\":\"placeholder2\",\"bundle_name\":\"com.example.app2\"}"
        "]}";

    JsonParser parser(json.c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_TRUE(cJSON_IsArray(bundleNameMap));
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), 2);
}

/**
 * @tc.name: BundleNameParser_JsonArray_003
 * @tc.desc: Test JSON array with three items
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonArray_003, TestSize.Level1)
{
    const std::string json =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"placeholder1\",\"bundle_name\":\"com.example.app1\"},"
        "{\"placeholder\":\"placeholder2\",\"bundle_name\":\"com.example.app2\"},"
        "{\"placeholder\":\"placeholder3\",\"bundle_name\":\"com.example.app3\"}"
        "]}";

    JsonParser parser(json.c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_TRUE(cJSON_IsArray(bundleNameMap));
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), 3);
}

/**
 * @tc.name: BundleNameParser_JsonArray_004
 * @tc.desc: Test JSON array boundary at max size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonArray_004, TestSize.Level1)
{
    std::ostringstream json;
    json << "{\"bundle_name_map\":[";
    for (size_t i = 0; i < MAX_JSON_ARRAY_SIZE; ++i) {
        if (i > 0) {
            json << ",";
        }
        json << "{\"placeholder\":\"key" << i << "\",\"bundle_name\":\"bundle" << i << "\"}";
    }
    json << "]}";

    JsonParser parser(json.str().c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_TRUE(cJSON_IsArray(bundleNameMap));
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), MAX_JSON_ARRAY_SIZE);
}

/**
 * @tc.name: BundleNameParser_JsonArray_005
 * @tc.desc: Test JSON array exceeding max size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonArray_005, TestSize.Level1)
{
    std::ostringstream json;
    json << "{\"bundle_name_map\":[";
    for (size_t i = 0; i < EXCEED_MAX_ARRAY_SIZE; ++i) {
        if (i > 0) {
            json << ",";
        }
        json << "{\"placeholder\":\"key" << i << "\",\"bundle_name\":\"bundle" << i << "\"}";
    }
    json << "]}";

    JsonParser parser(json.str().c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_TRUE(cJSON_IsArray(bundleNameMap));
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), EXCEED_MAX_ARRAY_SIZE);
}

/**
 * @tc.name: BundleNameParser_JsonItem_001
 * @tc.desc: Test JSON item with valid placeholder and bundle_name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonItem_001, TestSize.Level1)
{
    const std::string json =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"test_placeholder\",\"bundle_name\":\"test.bundle.name\"}"
        "]}";

    JsonParser parser(json.c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    cJSON* item = cJSON_GetArrayItem(bundleNameMap, 0);

    cJSON* placeholder = cJSON_GetObjectItemCaseSensitive(item, "placeholder");
    cJSON* bundleName = cJSON_GetObjectItemCaseSensitive(item, "bundle_name");

    EXPECT_NE(placeholder, nullptr);
    EXPECT_NE(bundleName, nullptr);
    EXPECT_STREQ(cJSON_GetStringValue(placeholder), "test_placeholder");
    EXPECT_STREQ(cJSON_GetStringValue(bundleName), "test.bundle.name");
}

/**
 * @tc.name: BundleNameParser_JsonItem_002
 * @tc.desc: Test JSON item with special characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonItem_002, TestSize.Level1)
{
    const std::string json =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"special.characters_123\",\"bundle_name\":\"com.special.app\"}"
        "]}";

    JsonParser parser(json.c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    cJSON* item = cJSON_GetArrayItem(bundleNameMap, 0);

    cJSON* placeholder = cJSON_GetObjectItemCaseSensitive(item, "placeholder");
    ASSERT_NE(placeholder, nullptr);
    EXPECT_STREQ(cJSON_GetStringValue(placeholder), "special.characters_123");
}

/**
 * @tc.name: BundleNameParser_JsonItem_003
 * @tc.desc: Test JSON item with long strings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonItem_003, TestSize.Level1)
{
    std::string longPlaceholder(256, 'a');
    std::string json =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"" + longPlaceholder + "\",\"bundle_name\":\"com.long.bundle.name\"}"
        "]}";

    JsonParser parser(json.c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    cJSON* item = cJSON_GetArrayItem(bundleNameMap, 0);

    cJSON* placeholder = cJSON_GetObjectItemCaseSensitive(item, "placeholder");
    EXPECT_NE(placeholder, nullptr);
}

/**
 * @tc.name: BundleNameParser_JsonItem_004
 * @tc.desc: Test JSON item with missing placeholder field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonItem_004, TestSize.Level1)
{
    const std::string json =
        "{\"bundle_name_map\":["
        "{\"bundle_name\":\"test\"}"
        "]}";

    JsonParser parser(json.c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    cJSON* item = cJSON_GetArrayItem(bundleNameMap, 0);

    cJSON* placeholder = cJSON_GetObjectItemCaseSensitive(item, "placeholder");
    EXPECT_EQ(placeholder, nullptr);
}

/**
 * @tc.name: BundleNameParser_JsonItem_005
 * @tc.desc: Test JSON item with missing bundle_name field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonItem_005, TestSize.Level1)
{
    const std::string json =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"test\"}"
        "]}";

    JsonParser parser(json.c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    cJSON* item = cJSON_GetArrayItem(bundleNameMap, 0);

    cJSON* bundleName = cJSON_GetObjectItemCaseSensitive(item, "bundle_name");
    EXPECT_EQ(bundleName, nullptr);
}

/**
 * @tc.name: BundleNameParser_JsonItem_006
 * @tc.desc: Test JSON item with empty string values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonItem_006, TestSize.Level1)
{
    const std::string json =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"\",\"bundle_name\":\"\"}"
        "]}";

    JsonParser parser(json.c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    cJSON* item = cJSON_GetArrayItem(bundleNameMap, 0);

    cJSON* placeholder = cJSON_GetObjectItemCaseSensitive(item, "placeholder");
    cJSON* bundleName = cJSON_GetObjectItemCaseSensitive(item, "bundle_name");

    EXPECT_NE(placeholder, nullptr);
    EXPECT_NE(bundleName, nullptr);
}

/**
 * @tc.name: BundleNameParser_JsonItem_007
 * @tc.desc: Test JSON item with numeric placeholder
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonItem_007, TestSize.Level1)
{
    const std::string json =
        "{\"bundle_name_map\":["
        "{\"placeholder\":12345,\"bundle_name\":\"com.example.app1\"}"
        "]}";

    JsonParser parser(json.c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    cJSON* item = cJSON_GetArrayItem(bundleNameMap, 0);

    cJSON* placeholder = cJSON_GetObjectItemCaseSensitive(item, "placeholder");
    EXPECT_NE(placeholder, nullptr);
    EXPECT_TRUE(cJSON_IsNumber(placeholder));
}

/**
 * @tc.name: BundleNameParser_JsonItem_008
 * @tc.desc: Test JSON item with boolean bundle_name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonItem_008, TestSize.Level1)
{
    const std::string json =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"placeholder1\",\"bundle_name\":true}"
        "]}";

    JsonParser parser(json.c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    cJSON* item = cJSON_GetArrayItem(bundleNameMap, 0);

    cJSON* bundleName = cJSON_GetObjectItemCaseSensitive(item, "bundle_name");
    EXPECT_NE(bundleName, nullptr);
}

/**
 * @tc.name: BundleNameParser_JsonDuplicate_001
 * @tc.desc: Test JSON with duplicate placeholder keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_JsonDuplicate_001, TestSize.Level1)
{
    const std::string json =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"placeholder1\",\"bundle_name\":\"com.example.app1\"},"
        "{\"placeholder\":\"placeholder1\",\"bundle_name\":\"com.example.app2\"}"
        "]}";

    JsonParser parser(json.c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), 2);
}

/**
 * @tc.name: BundleNameParser_ParserClass_001
 * @tc.desc: Test JsonParser constructor with valid JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_ParserClass_001, TestSize.Level1)
{
    const std::string validJson = "{\"key\":\"value\"}";
    JsonParser parser(validJson.c_str());

    EXPECT_NE(parser.Get(), nullptr);
}

/**
 * @tc.name: BundleNameParser_ParserClass_002
 * @tc.desc: Test JsonParser constructor with empty string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_ParserClass_002, TestSize.Level1)
{
    const std::string emptyJson = "";
    JsonParser parser(emptyJson.c_str());

    EXPECT_EQ(parser.Get(), nullptr);
}

/**
 * @tc.name: BundleNameParser_MultipleInstances_001
 * @tc.desc: Test creating multiple JsonParser instances
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_MultipleInstances_001, TestSize.Level1)
{
    const std::string json1 = "{\"key1\":\"value1\"}";
    const std::string json2 = "{\"key2\":\"value2\"}";

    JsonParser parser1(json1.c_str());
    JsonParser parser2(json2.c_str());

    EXPECT_NE(parser1.Get(), nullptr);
    EXPECT_NE(parser2.Get(), nullptr);
}

/**
 * @tc.name: BundleNameParser_Integration_001
 * @tc.desc: Integration test - parse JSON and check structure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_Integration_001, TestSize.Level1)
{
    const std::string validJson =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"placeholder1\",\"bundle_name\":\"com.example.app1\"},"
        "{\"placeholder\":\"placeholder2\",\"bundle_name\":\"com.example.app2\"}"
        "]}";

    JsonParser parser(validJson.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));

    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_TRUE(cJSON_IsArray(bundleNameMap));
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), 2);

    cJSON* item0 = cJSON_GetArrayItem(bundleNameMap, 0);
    cJSON* item1 = cJSON_GetArrayItem(bundleNameMap, 1);

    EXPECT_NE(item0, nullptr);
    EXPECT_NE(item1, nullptr);
}

/**
 * @tc.name: BundleNameParser_Integration_002
 * @tc.desc: Integration test - verify all items in array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_Integration_002, TestSize.Level1)
{
    const std::string validJson =
        "{\"bundle_name_map\":["
        "{\"placeholder\":\"placeholder1\",\"bundle_name\":\"com.example.app1\"},"
        "{\"placeholder\":\"placeholder2\",\"bundle_name\":\"com.example.app2\"},"
        "{\"placeholder\":\"placeholder3\",\"bundle_name\":\"com.example.app3\"}"
        "]}";

    JsonParser parser(validJson.c_str());
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");

    for (int32_t i = 0; i < 3; ++i) {
        cJSON* item = cJSON_GetArrayItem(bundleNameMap, i);
        EXPECT_NE(item, nullptr);

        cJSON* placeholder = cJSON_GetObjectItemCaseSensitive(item, "placeholder");
        cJSON* bundleName = cJSON_GetObjectItemCaseSensitive(item, "bundle_name");

        EXPECT_NE(placeholder, nullptr);
        EXPECT_NE(bundleName, nullptr);
    }
}

/**
 * @tc.name: BundleNameParser_Integration_004
 * @tc.desc: Integration test - verify singleton behavior
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_Integration_004, TestSize.Level1)
{
    BundleNameParser& instance1 = BundleNameParser::GetInstance();
    BundleNameParser& instance2 = BundleNameParser::GetInstance();

    EXPECT_EQ(&instance1, &instance2);

    std::string result1 = instance1.GetBundleName("test_key");
    std::string result2 = instance2.GetBundleName("test_key");

    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_ValidConfig_001
 * @tc.desc: Test JSON parsing logic with valid configuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_ValidConfig_001, TestSize.Level1)
{
    const std::string testConfig =
        "{\n"
        "  \"bundle_name_map\": [\n"
        "    {\"placeholder\":\"test_app1\",\"bundle_name\":\"com.test.app1\"},\n"
        "    {\"placeholder\":\"test_app2\",\"bundle_name\":\"com.test.app2\"}\n"
        "  ]\n"
        "}";
    
    JsonParser parser(testConfig.c_str());
    ASSERT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    ASSERT_TRUE(cJSON_IsArray(bundleNameMap));
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), 2);
    
    cJSON* item0 = cJSON_GetArrayItem(bundleNameMap, 0);
    ASSERT_NE(item0, nullptr);
    
    cJSON* placeholder0 = cJSON_GetObjectItemCaseSensitive(item0, "placeholder");
    cJSON* bundleName0 = cJSON_GetObjectItemCaseSensitive(item0, "bundle_name");
    
    ASSERT_NE(placeholder0, nullptr);
    ASSERT_NE(bundleName0, nullptr);
    EXPECT_STREQ(cJSON_GetStringValue(placeholder0), "test_app1");
    EXPECT_STREQ(cJSON_GetStringValue(bundleName0), "com.test.app1");
    
    cJSON* item1 = cJSON_GetArrayItem(bundleNameMap, 1);
    ASSERT_NE(item1, nullptr);
    
    cJSON* placeholder1 = cJSON_GetObjectItemCaseSensitive(item1, "placeholder");
    cJSON* bundleName1 = cJSON_GetObjectItemCaseSensitive(item1, "bundle_name");
    
    ASSERT_NE(placeholder1, nullptr);
    ASSERT_NE(bundleName1, nullptr);
    EXPECT_STREQ(cJSON_GetStringValue(placeholder1), "test_app2");
    EXPECT_STREQ(cJSON_GetStringValue(bundleName1), "com.test.app2");
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_NotObject_001
 * @tc.desc: Test InitializeImpl with JSON array instead of object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_NotObject_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    bool dirCreated = CreateDirectoryRecursive(configDir);
    EXPECT_TRUE(dirCreated);
    
    ScopedFileRestorer restorer(configFile);
    
    const std::string arrayConfig = "[\"item1\", \"item2\"]";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    EXPECT_TRUE(outFile.is_open());
    outFile << arrayConfig;
    outFile.close();
    
    JsonParser parser(arrayConfig.c_str());
    EXPECT_FALSE(cJSON_IsObject(parser.Get()));
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_EmptyArray_001
 * @tc.desc: Test InitializeImpl with empty bundle_name_map array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_EmptyArray_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    const std::string emptyArrayConfig = "{\"bundle_name_map\":[]}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << emptyArrayConfig;
    outFile.close();
    
    JsonParser parser(emptyArrayConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_TRUE(cJSON_IsArray(bundleNameMap));
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), 0);
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_MissingKey_001
 * @tc.desc: Test InitializeImpl with missing bundle_name_map key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_MissingKey_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    const std::string noKeyConfig = "{\"other_key\":\"other_value\"}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << noKeyConfig;
    outFile.close();
    
    JsonParser parser(noKeyConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_FALSE(cJSON_IsArray(bundleNameMap));
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_NotArray_001
 * @tc.desc: Test InitializeImpl with bundle_name_map as string instead of array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_NotArray_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    const std::string notArrayConfig = "{\"bundle_name_map\":\"not_an_array\"}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << notArrayConfig;
    outFile.close();
    
    JsonParser parser(notArrayConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_FALSE(cJSON_IsArray(bundleNameMap));
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_MultipleItems_001
 * @tc.desc: Test InitializeImpl with multiple valid items
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_MultipleItems_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    std::string multiItemConfig =
        "{\n"
        "  \"bundle_name_map\": [\n";
    
    for (size_t i = 0; i < FIVE_ITEMS_ARRAY_SIZE; ++i) {
        if (i > 0) {
            multiItemConfig += ",\n";
        }
        multiItemConfig += "    {\"placeholder\":\"app" + std::to_string(i) +
                          "\",\"bundle_name\":\"com.example.app" + std::to_string(i) + "\"}";
    }
    
    multiItemConfig +=
        "\n  ]\n"
        "}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << multiItemConfig;
    outFile.close();
    
    JsonParser parser(multiItemConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_TRUE(cJSON_IsArray(bundleNameMap));
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), FIVE_ITEMS_ARRAY_SIZE);
    
    for (size_t i = 0; i < FIVE_ITEMS_ARRAY_SIZE; ++i) {
        cJSON* item = cJSON_GetArrayItem(bundleNameMap, i);
        EXPECT_NE(item, nullptr);
        
        cJSON* placeholder = cJSON_GetObjectItemCaseSensitive(item, "placeholder");
        cJSON* bundleName = cJSON_GetObjectItemCaseSensitive(item, "bundle_name");
        
        EXPECT_NE(placeholder, nullptr);
        EXPECT_NE(bundleName, nullptr);
    }
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_InvalidItem_001
 * @tc.desc: Test InitializeImpl with item missing placeholder
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_InvalidItem_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    const std::string invalidItemConfig =
        "{\n"
        "  \"bundle_name_map\": [\n"
        "    {\"bundle_name\":\"com.test.app\"}\n"
        "  ]\n"
        "}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << invalidItemConfig;
    outFile.close();
    
    JsonParser parser(invalidItemConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    cJSON* item = cJSON_GetArrayItem(bundleNameMap, 0);
    
    cJSON* placeholder = cJSON_GetObjectItemCaseSensitive(item, "placeholder");
    EXPECT_EQ(placeholder, nullptr);
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_InvalidItem_002
 * @tc.desc: Test InitializeImpl with item missing bundle_name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_InvalidItem_002, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    const std::string invalidItemConfig =
        "{\n"
        "  \"bundle_name_map\": [\n"
        "    {\"placeholder\":\"test_placeholder\"}\n"
        "  ]\n"
        "}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << invalidItemConfig;
    outFile.close();
    
    JsonParser parser(invalidItemConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    cJSON* item = cJSON_GetArrayItem(bundleNameMap, 0);
    
    cJSON* bundleName = cJSON_GetObjectItemCaseSensitive(item, "bundle_name");
    EXPECT_EQ(bundleName, nullptr);
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_NonStringPlaceholder_001
 * @tc.desc: Test InitializeImpl with numeric placeholder
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_NonStringPlaceholder_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    const std::string nonStringConfig =
        "{\n"
        "  \"bundle_name_map\": [\n"
        "    {\"placeholder\":12345,\"bundle_name\":\"com.test.app\"}\n"
        "  ]\n"
        "}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << nonStringConfig;
    outFile.close();
    
    JsonParser parser(nonStringConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    cJSON* item = cJSON_GetArrayItem(bundleNameMap, 0);
    
    cJSON* placeholder = cJSON_GetObjectItemCaseSensitive(item, "placeholder");
    EXPECT_NE(placeholder, nullptr);
    EXPECT_TRUE(cJSON_IsNumber(placeholder));
    EXPECT_FALSE(cJSON_IsString(placeholder));
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_NonStringBundleName_001
 * @tc.desc: Test InitializeImpl with boolean bundle_name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_NonStringBundleName_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    const std::string nonStringConfig =
        "{\n"
        "  \"bundle_name_map\": [\n"
        "    {\"placeholder\":\"test\",\"bundle_name\":true}\n"
        "  ]\n"
        "}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << nonStringConfig;
    outFile.close();
    
    JsonParser parser(nonStringConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    cJSON* item = cJSON_GetArrayItem(bundleNameMap, 0);
    
    cJSON* bundleName = cJSON_GetObjectItemCaseSensitive(item, "bundle_name");
    EXPECT_NE(bundleName, nullptr);
    EXPECT_TRUE(cJSON_IsBool(bundleName));
    EXPECT_FALSE(cJSON_IsString(bundleName));
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_MaxSize_001
 * @tc.desc: Test InitializeImpl with array at max size boundary
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_MaxSize_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    std::string maxSizeConfig = "{\"bundle_name_map\":[";
    for (size_t i = 0; i < MAX_JSON_ARRAY_SIZE; ++i) {
        if (i > 0) {
            maxSizeConfig += ",";
        }
        maxSizeConfig += "{\"placeholder\":\"key" + std::to_string(i) +
                        "\",\"bundle_name\":\"bundle" + std::to_string(i) + "\"}";
    }
    maxSizeConfig += "]}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << maxSizeConfig;
    outFile.close();
    
    JsonParser parser(maxSizeConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_TRUE(cJSON_IsArray(bundleNameMap));
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), MAX_JSON_ARRAY_SIZE);
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_ExceedMaxSize_001
 * @tc.desc: Test InitializeImpl with array exceeding max size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_ExceedMaxSize_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    std::string exceedMaxConfig = "{\"bundle_name_map\":[";
    for (size_t i = 0; i < EXCEED_MAX_ARRAY_SIZE; ++i) {
        if (i > 0) {
            exceedMaxConfig += ",";
        }
        exceedMaxConfig += "{\"placeholder\":\"key" + std::to_string(i) +
                          "\",\"bundle_name\":\"bundle" + std::to_string(i) + "\"}";
    }
    exceedMaxConfig += "]}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << exceedMaxConfig;
    outFile.close();
    
    JsonParser parser(exceedMaxConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_TRUE(cJSON_IsArray(bundleNameMap));
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), EXCEED_MAX_ARRAY_SIZE);
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_MixedValidInvalid_001
 * @tc.desc: Test InitializeImpl with mix of valid and invalid items
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_MixedValidInvalid_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    const std::string mixedConfig =
        "{\n"
        "  \"bundle_name_map\": [\n"
        "    {\"placeholder\":\"valid1\",\"bundle_name\":\"com.valid1\"},\n"
        "    {\"placeholder\":\"invalid\"},\n"
        "    {\"bundle_name\":\"com.invalid\"},\n"
        "    {\"placeholder\":12345,\"bundle_name\":\"com.invalid2\"},\n"
        "    {\"placeholder\":\"valid2\",\"bundle_name\":\"com.valid2\"}\n"
        "  ]\n"
        "}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << mixedConfig;
    outFile.close();
    
    JsonParser parser(mixedConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), FIVE_ITEMS_ARRAY_SIZE);
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_DuplicateKeys_001
 * @tc.desc: Test InitializeImpl with duplicate placeholder keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_DuplicateKeys_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    const std::string duplicateConfig =
        "{\n"
        "  \"bundle_name_map\": [\n"
        "    {\"placeholder\":\"duplicate\",\"bundle_name\":\"com.first\"},\n"
        "    {\"placeholder\":\"duplicate\",\"bundle_name\":\"com.second\"}\n"
        "  ]\n"
        "}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << duplicateConfig;
    outFile.close();
    
    JsonParser parser(duplicateConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), 2);
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_EmptyStrings_001
 * @tc.desc: Test InitializeImpl with empty string values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_EmptyStrings_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    const std::string emptyStringsConfig =
        "{\n"
        "  \"bundle_name_map\": [\n"
        "    {\"placeholder\":\"\",\"bundle_name\":\"\"}\n"
        "  ]\n"
        "}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << emptyStringsConfig;
    outFile.close();
    
    JsonParser parser(emptyStringsConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    cJSON* item = cJSON_GetArrayItem(bundleNameMap, 0);
    
    cJSON* placeholder = cJSON_GetObjectItemCaseSensitive(item, "placeholder");
    cJSON* bundleName = cJSON_GetObjectItemCaseSensitive(item, "bundle_name");
    
    EXPECT_NE(placeholder, nullptr);
    EXPECT_NE(bundleName, nullptr);
    EXPECT_STREQ(cJSON_GetStringValue(placeholder), "");
    EXPECT_STREQ(cJSON_GetStringValue(bundleName), "");
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_SpecialChars_001
 * @tc.desc: Test InitializeImpl with special characters in values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_SpecialChars_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    const std::string specialCharsConfig =
        "{\n"
        "  \"bundle_name_map\": [\n"
        "    {\"placeholder\":\"special.key_123\",\"bundle_name\":\"com.special.app-name\"}\n"
        "  ]\n"
        "}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << specialCharsConfig;
    outFile.close();
    
    JsonParser parser(specialCharsConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    cJSON* item = cJSON_GetArrayItem(bundleNameMap, 0);
    
    cJSON* placeholder = cJSON_GetObjectItemCaseSensitive(item, "placeholder");
    cJSON* bundleName = cJSON_GetObjectItemCaseSensitive(item, "bundle_name");
    
    EXPECT_STREQ(cJSON_GetStringValue(placeholder), "special.key_123");
    EXPECT_STREQ(cJSON_GetStringValue(bundleName), "com.special.app-name");
}

/**
 * @tc.name: BundleNameParser_InitializeImpl_NullItem_001
 * @tc.desc: Test InitializeImpl with null array item
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_InitializeImpl_NullItem_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    const std::string nullItemConfig =
        "{\n"
        "  \"bundle_name_map\": [\n"
        "    null,\n"
        "    {\"placeholder\":\"valid\",\"bundle_name\":\"com.valid\"}\n"
        "  ]\n"
        "}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << nullItemConfig;
    outFile.close();
    
    JsonParser parser(nullItemConfig.c_str());
    EXPECT_TRUE(cJSON_IsObject(parser.Get()));
    
    cJSON* bundleNameMap = cJSON_GetObjectItemCaseSensitive(parser.Get(), "bundle_name_map");
    EXPECT_EQ(cJSON_GetArraySize(bundleNameMap), 2);
    
    cJSON* nullItem = cJSON_GetArrayItem(bundleNameMap, 0);
    EXPECT_TRUE(cJSON_IsNull(nullItem));
}

/**
 * @tc.name: BundleNameParser_Init_MultipleCalls_001
 * @tc.desc: Test Init called multiple times returns same result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_Init_MultipleCalls_001, TestSize.Level1)
{
    BundleNameParser& parser = BundleNameParser::GetInstance();
    
    int32_t result1 = parser.Init();
    int32_t result2 = parser.Init();
    int32_t result3 = parser.Init();
    
    EXPECT_EQ(result1, result2);
    EXPECT_EQ(result2, result3);
}

/**
 * @tc.name: BundleNameParser_GetBundleName_AfterInit_001
 * @tc.desc: Test GetBundleName behavior depends on Init result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleNameParserTest, BundleNameParser_GetBundleName_AfterInit_001, TestSize.Level1)
{
    const std::string configDir = GetTestConfigDir();
    const std::string configFile = configDir + "/bundle_name_config.json";
    
    EXPECT_TRUE(CreateDirectoryRecursive(configDir));
    
    ScopedFileRestorer restorer(configFile);
    
    const std::string testConfig =
        "{\n"
        "  \"bundle_name_map\": [\n"
        "    {\"placeholder\":\"test_key\",\"bundle_name\":\"com.test.bundle\"}\n"
        "  ]\n"
        "}";
    
    std::ofstream outFile(configFile);
    EXPECT_TRUE(outFile.is_open());
    outFile << testConfig;
    outFile.close();
    
    BundleNameParser& parser = BundleNameParser::GetInstance();
    
    int32_t initResult = parser.Init();
    
    std::string result = parser.GetBundleName("test_key");
    
    if (initResult == RET_OK_VALUE) {
        EXPECT_EQ(result, "com.test.bundle");
    } else {
        EXPECT_EQ(result, "");
    }
}

} // namespace MMI
} // namespace OHOS
