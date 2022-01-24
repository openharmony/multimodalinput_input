/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "util.h"
#include <gtest/gtest.h>
#include "error_multimodal.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MMI;

class UtilTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(UtilTest, getEnumString_001, TestSize.Level1)
{
    const int32_t errorCodeEnum = MSG_SEND_FAIL;
    const char *retResult = GetMmiErrorTypeDesc(errorCodeEnum);
    EXPECT_STREQ(retResult, "Send Message Failed");
}

HWTEST_F(UtilTest, getEnumString_002, TestSize.Level1)
{
    const int32_t errorCodeEnum = NON_STD_EVENT;
    const char *retResult = GetMmiErrorTypeDesc(errorCodeEnum);
    EXPECT_STREQ(retResult, "Non-Standardized Event");
}

HWTEST_F(UtilTest, getEnumString_003, TestSize.Level1)
{
    const int32_t errorCodeEnum = UNKNOWN_EVENT;
    const char *retResult = GetMmiErrorTypeDesc(errorCodeEnum);
    EXPECT_STREQ(retResult, "Unknown Event");
}

HWTEST_F(UtilTest, getEnumString_004, TestSize.Level1)
{
    const int32_t errorCodeEnum = UNPROC_MSG;
    const char *retResult = GetMmiErrorTypeDesc(errorCodeEnum);
    EXPECT_STREQ(retResult, "Unprocessed Message");
}

HWTEST_F(UtilTest, getEnumString_005, TestSize.Level1)
{
    const int32_t errorCodeEnum = UNKNOWN_MSG_ID;
    const char *retResult = GetMmiErrorTypeDesc(errorCodeEnum);
    EXPECT_STREQ(retResult, "Unknown Message Id");
}

HWTEST_F(UtilTest, GetEnv, TestSize.Level1)
{
    std::string retResult = OHOS::MMI::GetEnv("123");
    EXPECT_STREQ(retResult.c_str(), "");
}

HWTEST_F(UtilTest, GetMicrotime, TestSize.Level1)
{
    int64_t retResult = OHOS::MMI::GetMicrotime();
    EXPECT_TRUE(retResult > 0);
}

HWTEST_F(UtilTest, GetMillisTime, TestSize.Level1)
{
    int64_t retResult = OHOS::MMI::GetMillisTime();
    EXPECT_TRUE(retResult > 0);
}

HWTEST_F(UtilTest, UuIdGenerate, TestSize.Level1)
{
    std::string retResult = OHOS::MMI::UuIdGenerate();
    EXPECT_TRUE(retResult.length() == 0);
}

HWTEST_F(UtilTest, GetUUid, TestSize.Level1)
{
    std::string retResult = OHOS::MMI::GetUUid();
    EXPECT_TRUE(retResult.length() >= 0);
}

HWTEST_F(UtilTest, GetThisThreadIdOfString, TestSize.Level1)
{
    std::string retResult = OHOS::MMI::GetThisThreadIdOfString();
    EXPECT_TRUE(retResult.length() >= 0);
}

HWTEST_F(UtilTest, GetThisThreadIdOfLL, TestSize.Level1)
{
    uint64_t retResult = GetThisThreadIdOfLL();
    EXPECT_TRUE(retResult >= 0);
}

HWTEST_F(UtilTest, StringToken_001, TestSize.Level1)
{
    std::string str = "sdf_wef_1";
    const std::string sep = "sdf_wef_1.sss";
    std::string token = "_";
    OHOS::MMI::StringToken(str, sep, token);
}

HWTEST_F(UtilTest, StringToken_002, TestSize.Level1)
{
    std::string str = { 0 };
    const std::string sep;
    std::string token;
    OHOS::MMI::StringToken(str, sep, token);
}

HWTEST_F(UtilTest, StringToken_003, TestSize.Level1)
{
    std::string str = { 0, 1, 2, 3 };
    const std::string sep = { 2 };
    std::string token;
    OHOS::MMI::StringToken(str, sep, token);
}

HWTEST_F(UtilTest, StringSplit, TestSize.Level1)
{
    const std::string str;
    const std::string sep;
    std::vector<std::string> vecList;
    OHOS::MMI::StringSplit(str, sep, vecList);
}
} // namespace
