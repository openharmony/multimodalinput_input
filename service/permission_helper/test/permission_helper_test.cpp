/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <cstdio>

#include <gtest/gtest.h>
#include "ipc_skeleton.h"
#include "mmi_log.h"
#include "proto.h"
#include "tokenid_kit.h"

#include "define_multimodal.h"
#include "permission_helper.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
const std::string INPUT_MONITORING = "ohos.permission.INPUT_MONITORING";
const std::string INPUT_INTERCEPTOR = "ohos.permission.INTERCEPT_INPUT_EVENT";
const std::string INPUT_DISPATCHCONTROL = "ohos.permission.INPUT_CONTROL_DISPATCHING";
} // namespace

class PermissionHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: PermissionHelperTest_GetTokenType
 * @tc.desc: Test GetTokenType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_GetTokenType, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    int32_t result1 = PER_HELPER->GetTokenType();
    EXPECT_EQ(result1, 2);

    tokenId = 2;
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;
    int32_t result2 = PER_HELPER->GetTokenType();
    EXPECT_EQ(result2, 2);

    tokenId = 3;
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    int32_t result3 = PER_HELPER->GetTokenType();
    EXPECT_EQ(result3, 2);

    tokenId = 4;
    tokenType = OHOS::Security::AccessToken::TOKEN_INVALID;
    int32_t result4 = PER_HELPER->GetTokenType();
    EXPECT_EQ(result4, 2);
}

/**
 * @tc.name: PermissionHelperTest_CheckDispatchControl_01
 * @tc.desc: Test CheckDispatchControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckDispatchControl_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    bool result1 = PER_HELPER->CheckDispatchControl();
    EXPECT_TRUE(result1);

    tokenId = 1;
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;
    bool result2 = PER_HELPER->CheckDispatchControl();
    EXPECT_TRUE(result2);

    tokenId = 3;
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    bool result3 = PER_HELPER->CheckDispatchControl();
    EXPECT_TRUE(result3);

    tokenId = 4;
    tokenType = OHOS::Security::AccessToken::TOKEN_INVALID;
    bool result4 = PER_HELPER->CheckDispatchControl();
    EXPECT_TRUE(result4);
}

/**
 * @tc.name: PermissionHelperTest_CheckHapPermission_01
 * @tc.desc: Test CheckHapPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckHapPermission_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 3;
    std::string permissionCode = "access";
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;
    bool result = PER_HELPER->CheckHapPermission(tokenId, permissionCode);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: PermissionHelperTest_CheckHapPermission_02
 * @tc.desc: Test CheckHapPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckHapPermission_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 5;
    std::string permissionCode = "access denied";
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_INVALID;
    bool result = PER_HELPER->CheckHapPermission(tokenId, permissionCode);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: PermissionHelperTest_CheckHapPermission_03
 * @tc.desc: Test CheckHapPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckHapPermission_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    uint32_t required = 1;
    OHOS::Security::AccessToken::HapTokenInfo findInfo;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, findInfo);
    EXPECT_NE(ret, 0);
    bool result = PER_HELPER->CheckHapPermission(tokenId, required);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: PermissionHelperTest_VerifySystemApp_01
 * @tc.desc: Test VerifySystemApp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_VerifySystemApp_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t callerToken = 3;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    tokenType = OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE;
    bool result = PER_HELPER->VerifySystemApp();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: PermissionHelperTest_VerifySystemApp_02
 * @tc.desc: Test VerifySystemApp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_VerifySystemApp_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t callerToken = 5;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    tokenType = OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL;
    bool result = PER_HELPER->VerifySystemApp();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: PermissionHelperTest_CheckPermission
 * @tc.desc: Test CheckPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckPermission, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    uint32_t required = 2;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    bool result1 = PER_HELPER->CheckPermission(required);
    EXPECT_TRUE(result1);

    tokenId = 2;
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;
    bool result2 = PER_HELPER->CheckPermission(required);
    EXPECT_TRUE(result2);

    tokenId = 3;
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    bool result3 = PER_HELPER->CheckPermission(required);
    EXPECT_TRUE(result3);

    tokenId = 4;
    tokenType = OHOS::Security::AccessToken::TOKEN_INVALID;
    bool result4 = PER_HELPER->CheckPermission(required);
    EXPECT_TRUE(result4);
}

/**
 * @tc.name: PermissionHelperTest_CheckMonitor
 * @tc.desc: Test CheckMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckMonitor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    bool result1 = PER_HELPER->CheckMonitor();
    EXPECT_TRUE(result1);

    tokenId = 2;
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;
    bool result2 = PER_HELPER->CheckMonitor();
    EXPECT_TRUE(result2);

    tokenId = 3;
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    bool result3 = PER_HELPER->CheckMonitor();
    EXPECT_TRUE(result3);

    tokenId = 4;
    tokenType = OHOS::Security::AccessToken::TOKEN_INVALID;
    bool result4 = PER_HELPER->CheckMonitor();
    EXPECT_TRUE(result4);
}

/**
 * @tc.name: PermissionHelperTest_CheckInterceptor
 * @tc.desc: Test CheckInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckInterceptor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    bool result1 = PER_HELPER->CheckInterceptor();
    EXPECT_TRUE(result1);

    tokenId = 2;
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;
    bool result2 = PER_HELPER->CheckInterceptor();
    EXPECT_TRUE(result2);

    tokenId = 3;
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    bool result3 = PER_HELPER->CheckInterceptor();
    EXPECT_TRUE(result3);

    tokenId = 4;
    tokenType = OHOS::Security::AccessToken::TOKEN_INVALID;
    bool result4 = PER_HELPER->CheckInterceptor();
    EXPECT_TRUE(result4);
}
} // namespace MMI
} // namespace OHOS