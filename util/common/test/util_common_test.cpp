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
using namespace testing::ext;
using namespace OHOS;
} // namespace

class UtilCommonTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
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
} // namespace MMI
} // namespace OHOS