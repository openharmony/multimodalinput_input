/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include <fstream>

#include <cJSON.h>

#include "config_policy_utils.h"
#include "util.h"

#include "accesstoken_kit.h"

auto g_mockTokenTypeFlag = OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_INVALID;
std::string g_mockBundleName = "";
int32_t g_mockHapTokenInfoResult = 0;

namespace OHOS {
namespace Security {
namespace AccessToken {
ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID callerToken)
{
    return g_mockTokenTypeFlag;
}

int AccessTokenKit::GetHapTokenInfo(AccessTokenID callerToken, HapTokenInfo& hapTokenInfoRes)
{
    hapTokenInfoRes.bundleName = g_mockBundleName;
    return g_mockHapTokenInfoResult;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
char g_cfgName[] { "custom_config.json" };
constexpr std::uintmax_t MAX_SIZE_OF_CONFIG_FILE { 524288 }; // 512KB
} // namespace

class UtilCommonTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

private:
    void SerializeConfig(cJSON *jsonConfig);
    void BuildConfig4();
    void BuildConfig5();
};

/**
 * @tc.name:IsInteger_001
 * @tc.desc:Verify enum add
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilCommonTest, IsInteger_001, TestSize.Level1)
{
    EXPECT_TRUE(IsInteger("0"));
    EXPECT_TRUE(IsInteger("123456"));
    EXPECT_TRUE(IsInteger("-0"));
    EXPECT_TRUE(IsInteger("-1"));
    EXPECT_TRUE(IsInteger("-918273645"));
    EXPECT_TRUE(IsInteger("  -918273645   "));
    EXPECT_FALSE(IsInteger("a  -918273645   "));
    EXPECT_FALSE(IsInteger("  -918273645   b"));
    EXPECT_FALSE(IsInteger("-"));
    EXPECT_FALSE(IsInteger("-918273645a"));
    EXPECT_FALSE(IsInteger("b-918273645"));
    EXPECT_FALSE(IsInteger("-91827a3645"));
    EXPECT_FALSE(IsInteger(".1"));
    EXPECT_FALSE(IsInteger("1."));
    EXPECT_FALSE(IsInteger("1.0"));
    EXPECT_FALSE(IsInteger("-1.0"));
}

/**
 * @tc.name: GetBundleName_001
 * @tc.desc: Verify that GetBundleName returns an empty string for a invalid TokenType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilCommonTest, GetBundleName_001, TestSize.Level1)
{
    g_mockTokenTypeFlag = Security::AccessToken::ATokenTypeEnum::TOKEN_INVALID;
    uint32_t tokenId = 1;
    std::string ret = GetBundleName(tokenId);
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.name: GetBundleName_002
 * @tc.desc: Verify that GetBundleName returns an empty string for a HAP token with an error result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilCommonTest, GetBundleName_002, TestSize.Level1)
{
    g_mockTokenTypeFlag = Security::AccessToken::ATokenTypeEnum::TOKEN_HAP;
    g_mockHapTokenInfoResult = RET_ERR;
    uint32_t tokenId = 1;
    std::string ret = GetBundleName(tokenId);
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.name: GetBundleName_003
 * @tc.desc: Verify that GetBundleName returns the correct bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilCommonTest, GetBundleName_003, TestSize.Level1)
{
    g_mockTokenTypeFlag = Security::AccessToken::ATokenTypeEnum::TOKEN_HAP;
    g_mockHapTokenInfoResult = RET_OK;
    g_mockBundleName = "TestBundleName";
    uint32_t tokenId = 1;
    std::string ret = GetBundleName(tokenId);
    EXPECT_EQ(ret, g_mockBundleName);
}

/**
 * @tc.name: LoadConfig_001
 * @tc.desc: NA
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilCommonTest, LoadConfig_001, TestSize.Level1)
{
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillRepeatedly(Return(nullptr));

    char cfgName[] { "config.json" };
    EXPECT_FALSE(LoadConfig(cfgName, nullptr));
}

/**
 * @tc.name: LoadConfig_002
 * @tc.desc: NA
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilCommonTest, LoadConfig_002, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillRepeatedly(Return(&cfgFiles));

    char cfgName[] { "config.json" };
    EXPECT_FALSE(LoadConfig(cfgName, nullptr));
}

/**
 * @tc.name: LoadConfig_003
 * @tc.desc: NA
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilCommonTest, LoadConfig_003, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillRepeatedly(Return(&cfgFiles));

    char cfgName[] { "config.json" };
    EXPECT_FALSE(LoadConfig(cfgName,
        [](const char *cfgPath, cJSON *jsonCfg) {
            return false;
        }));
}

void UtilCommonTest::BuildConfig4()
{
    const std::ofstream::pos_type tailPos { MAX_SIZE_OF_CONFIG_FILE };
    std::ofstream ofs(g_cfgName, std::ios_base::out);
    if (ofs.is_open()) {
        ofs.seekp(tailPos);
        ofs << "tail";
        ofs.flush();
        ofs.close();
    }
}

/**
 * @tc.name: LoadConfig_004
 * @tc.desc: NA
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilCommonTest, LoadConfig_004, TestSize.Level1)
{
    BuildConfig4();

    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillRepeatedly(Return(&cfgFiles));

    char cfgName[] { "config.json" };
    EXPECT_FALSE(LoadConfig(cfgName,
        [](const char *cfgPath, cJSON *jsonCfg) {
            return false;
        }));
    std::filesystem::remove(g_cfgName);
}

void UtilCommonTest::SerializeConfig(cJSON *jsonConfig)
{
    if (jsonConfig == nullptr) {
        return;
    }
    auto sConfig = std::unique_ptr<char, std::function<void(char *)>>(
        cJSON_Print(jsonConfig),
        [](char *object) {
            if (object != nullptr) {
                cJSON_free(object);
            }
        });
    std::ofstream ofs(g_cfgName, std::ios_base::out);
    if (ofs.is_open()) {
        ofs << sConfig.get();
        ofs.flush();
        ofs.close();
    }
}

void UtilCommonTest::BuildConfig5()
{
    auto jsonConfig = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    if (jsonConfig == nullptr) {
        return;
    }
    auto jsonTouchscreen = cJSON_CreateObject();
    if (jsonTouchscreen == nullptr) {
        return;
    }
    if (!cJSON_AddItemToObject(jsonConfig.get(), "touchscreen", jsonTouchscreen)) {
        cJSON_Delete(jsonTouchscreen);
        return;
    }
    SerializeConfig(jsonConfig.get());
}

/**
 * @tc.name: LoadConfig_005
 * @tc.desc: NA
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilCommonTest, LoadConfig_005, TestSize.Level1)
{
    BuildConfig5();

    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillRepeatedly(Return(&cfgFiles));

    char cfgName[] { "config.json" };
    EXPECT_TRUE(LoadConfig(cfgName,
        [](const char *cfgPath, cJSON *jsonCfg) {
            return true;
        }));
    std::filesystem::remove(g_cfgName);
}
} // namespace MMI
} // namespace OHOS