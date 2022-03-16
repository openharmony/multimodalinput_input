/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "error_multimodal.h"
#include "util.h"


namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class UtilTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:getEnumString_001
 * @tc.desc:Verify get enum string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilTest, getEnumString_001, TestSize.Level1)
{
    const int32_t errorCodeEnum = MSG_SEND_FAIL;
    const char *retResult = GetMmiErrorTypeDesc(errorCodeEnum);
    EXPECT_STREQ(retResult, "Send Message Failed");
}

/**
 * @tc.name:getEnumString_002
 * @tc.desc:Verify get enum string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilTest, getEnumString_002, TestSize.Level1)
{
    const int32_t errorCodeEnum = NON_STD_EVENT;
    const char *retResult = GetMmiErrorTypeDesc(errorCodeEnum);
    EXPECT_STREQ(retResult, "Non-Standardized Event");
}

/**
 * @tc.name:getEnumString_003
 * @tc.desc:Verify get enum string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilTest, getEnumString_003, TestSize.Level1)
{
    const int32_t errorCodeEnum = UNKNOWN_EVENT;
    const char *retResult = GetMmiErrorTypeDesc(errorCodeEnum);
    EXPECT_STREQ(retResult, "Unknown Event");
}

/**
 * @tc.name:getEnumString_004
 * @tc.desc:Verify get enum string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilTest, getEnumString_004, TestSize.Level1)
{
    const int32_t errorCodeEnum = UNPROC_MSG;
    const char *retResult = GetMmiErrorTypeDesc(errorCodeEnum);
    EXPECT_STREQ(retResult, "Unprocessed Message");
}

/**
 * @tc.name:getEnumString_005
 * @tc.desc:Verify get enum string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilTest, getEnumString_005, TestSize.Level1)
{
    const int32_t errorCodeEnum = UNKNOWN_MSG_ID;
    const char *retResult = GetMmiErrorTypeDesc(errorCodeEnum);
    EXPECT_STREQ(retResult, "Unknown Message Id");
}

/**
 * @tc.name:GetMicrotime
 * @tc.desc:Verify get micro time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilTest, GetMicrotime, TestSize.Level1)
{
    int64_t retResult = GetMicrotime();
    EXPECT_TRUE(retResult > 0);
}

/**
 * @tc.name:GetMillisTime
 * @tc.desc:Verify get millis time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilTest, GetMillisTime, TestSize.Level1)
{
    int64_t retResult = GetMillisTime();
    EXPECT_TRUE(retResult > 0);
}

/**
 * @tc.name:UuIdGenerate
 * @tc.desc:Verify generate uuid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilTest, UuIdGenerate, TestSize.Level1)
{
    std::string retResult = UuIdGenerate();
    EXPECT_TRUE(retResult.length() == 0);
}

/**
 * @tc.name:GetUUid
 * @tc.desc:Verify get uuid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilTest, GetUUid, TestSize.Level1)
{
    std::string retResult = GetUUid();
    EXPECT_TRUE(retResult.length() >= 0);
}

/**
 * @tc.name:GetThisThreadIdOfString
 * @tc.desc:Verify get thread id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilTest, GetThisThreadIdOfString, TestSize.Level1)
{
    std::string retResult = GetThisThreadIdOfString();
    EXPECT_TRUE(retResult.length() >= 0);
}

HWTEST_F(UtilTest, GetThisThreadId, TestSize.Level1)
{
    uint64_t retResult = GetThisThreadId();
    EXPECT_TRUE(retResult >= 0);
}

/**
 * @tc.name:StringToken_001
 * @tc.desc:Verify string token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilTest, StringToken_001, TestSize.Level1)
{
    std::string str = "sdf_wef_1";
    const std::string sep = "sdf_wef_1.sss";
    std::string token = "_";
    StringToken(str, sep, token);
}

/**
 * @tc.name:StringToken_002
 * @tc.desc:Verify string token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilTest, StringToken_002, TestSize.Level1)
{
    std::string str = { 0 };
    const std::string sep;
    std::string token;
    StringToken(str, sep, token);
}

/**
 * @tc.name:StringToken_003
 * @tc.desc:Verify string token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilTest, StringToken_003, TestSize.Level1)
{
    std::string str = { 0, 1, 2, 3 };
    const std::string sep = { 2 };
    std::string token;
    StringToken(str, sep, token);
}

/**
 * @tc.name:StringSplit
 * @tc.desc:Verify string token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilTest, StringSplit, TestSize.Level1)
{
    const std::string str;
    const std::string sep;
    std::vector<std::string> vecList;
    StringSplit(str, sep, vecList);
}
} // namespace MMI
} // namespace OHOS
