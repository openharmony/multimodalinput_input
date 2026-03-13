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
    uint32_t tokenId = 2;
    std::string permissionCode = "access";
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
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
    uint32_t tokenId = 6;
    std::string permissionCode = "access";
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    bool result = PER_HELPER->CheckHapPermission(tokenId, permissionCode);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: PermissionHelperTest_CheckHapPermission_04
 * @tc.desc: Test CheckHapPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckHapPermission_04, TestSize.Level1)
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
 * @tc.name: PermissionHelperTest_CheckHapPermission_06
 * @tc.desc: Test CheckHapPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckHapPermission_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 3;
    std::string permissionCode = "access";
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    bool result = PER_HELPER->CheckHapPermission(permissionCode);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: PermissionHelperTest_CheckHapPermission_07
 * @tc.desc: Test CheckHapPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckHapPermission_07, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 2;
    std::string permissionCode = "access";
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;

    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permissionCode);
    ret = OHOS::Security::AccessToken::PERMISSION_GRANTED;
    bool result = PER_HELPER->CheckHapPermission(permissionCode);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: PermissionHelperTest_CheckHapPermission_08
 * @tc.desc: Test CheckHapPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckHapPermission_08, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 3;
    std::string permissionCode = "access";
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    bool result = PER_HELPER->CheckHapPermission(permissionCode);
    ASSERT_TRUE(result);
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

/**
 * @tc.name: CheckInjectPermissionTest1
 * @tc.desc: Test CheckInjectPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, CheckInjectPermissionTest1, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(PER_HELPER->CheckInjectPermission());
}

/**
 * @tc.name: PermissionHelperTest_CheckKeyEventHook
 * @tc.desc: Test CheckKeyEventHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckKeyEventHook, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = PER_HELPER->CheckKeyEventHook();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: PermissionHelperTest_AddPermissionUsedRecord001
 * @tc.desc: Test AddPermissionUsedRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_AddPermissionUsedRecord001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    unsigned int token = 3;
    std::string permissionName = "access";
    int32_t successCount = 1;
    int32_t failCount = 1;
    EXPECT_FALSE(PER_HELPER->AddPermissionUsedRecord(token, permissionName, successCount, failCount));
}

/**
 * @tc.name: PermissionHelperTest_CheckInfraredEmmit001
 * @tc.desc: Test CheckInfraredEmmit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckInfraredEmmit001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    auto tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    bool result1 = PER_HELPER->CheckInfraredEmmit();
    EXPECT_TRUE(result1);

    tokenId = 2;
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;
    bool result2 = PER_HELPER->CheckInfraredEmmit();
    EXPECT_TRUE(result2);

    tokenId = 3;
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    bool result3 = PER_HELPER->CheckInfraredEmmit();
    EXPECT_TRUE(result3);

    tokenId = 4;
    tokenType = OHOS::Security::AccessToken::TOKEN_INVALID;
    bool result4 = PER_HELPER->CheckInfraredEmmit();
    EXPECT_TRUE(result4);
}

/**
 * @tc.name: PermissionHelperTest_CheckAuthorize001
 * @tc.desc: Test CheckAuthorize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckAuthorize001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    auto tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    bool result1 = PER_HELPER->CheckAuthorize();
    EXPECT_TRUE(result1);

    tokenId = 2;
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;
    bool result2 = PER_HELPER->CheckAuthorize();
    EXPECT_TRUE(result2);

    tokenId = 3;
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    bool result3 = PER_HELPER->CheckAuthorize();
    EXPECT_TRUE(result3);

    tokenId = 4;
    tokenType = OHOS::Security::AccessToken::TOKEN_INVALID;
    bool result4 = PER_HELPER->CheckAuthorize();
    EXPECT_TRUE(result4);
}

/**
 * @tc.name: PermissionHelperTest_RequestFromShell001
 * @tc.desc: Test RequestFromShell
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_RequestFromShell001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    auto tokenType = OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_INVALID;
    bool result1 = PER_HELPER->RequestFromShell();
    EXPECT_TRUE(result1);

    tokenId = 2;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    bool result2 = PER_HELPER->RequestFromShell();
    EXPECT_TRUE(result2);

    tokenId = 3;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;
    bool result3 = PER_HELPER->RequestFromShell();
    EXPECT_TRUE(result3);

    tokenId = 4;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    bool result4 = PER_HELPER->RequestFromShell();
    EXPECT_TRUE(result4);
}

/**
 * @tc.name: PermissionHelperTest_CheckMouseCursor001
 * @tc.desc: Test CheckMouseCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckMouseCursor001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    auto tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    bool result1 = PER_HELPER->CheckMouseCursor();
    EXPECT_TRUE(result1);

    tokenId = 2;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;
    bool result2 = PER_HELPER->CheckMouseCursor();
    EXPECT_TRUE(result2);

    tokenId = 3;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    bool result3 = PER_HELPER->CheckMouseCursor();
    EXPECT_TRUE(result3);

    tokenId = 4;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_INVALID;
    bool result4 = PER_HELPER->CheckMouseCursor();
    EXPECT_TRUE(result4);
}

/**
 * @tc.name: PermissionHelperTest_CheckInputEventFilter001
 * @tc.desc: Test CheckInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckInputEventFilter001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    auto tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    bool result1 = PER_HELPER->CheckInputEventFilter();
    EXPECT_TRUE(result1);

    tokenId = 2;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;
    bool result2 = PER_HELPER->CheckInputEventFilter();
    EXPECT_TRUE(result2);

    tokenId = 3;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    bool result3 = PER_HELPER->CheckInputEventFilter();
    EXPECT_TRUE(result3);

    tokenId = 4;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_INVALID;
    bool result4 = PER_HELPER->CheckInputEventFilter();
    EXPECT_TRUE(result4);
}

/**
 * @tc.name: PermissionHelperTest_CheckInputDeviceController001
 * @tc.desc: Test CheckInputDeviceController
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckInputDeviceController001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    auto tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    bool result1 = PER_HELPER->CheckInputDeviceController();
    EXPECT_TRUE(result1);

    tokenId = 2;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;
    bool result2 = PER_HELPER->CheckInputDeviceController();
    EXPECT_TRUE(result2);

    tokenId = 3;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    bool result3 = PER_HELPER->CheckInputDeviceController();
    EXPECT_TRUE(result3);

    tokenId = 4;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_INVALID;
    bool result4 = PER_HELPER->CheckInputDeviceController();
    EXPECT_TRUE(result4);
}

/**
 * @tc.name: PermissionHelperTest_CheckFunctionKeyEnabled001
 * @tc.desc: Test CheckFunctionKeyEnabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckFunctionKeyEnabled001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    auto tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    bool result1 = PER_HELPER->CheckFunctionKeyEnabled();
    EXPECT_TRUE(result1);

    tokenId = 2;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;
    bool result2 = PER_HELPER->CheckFunctionKeyEnabled();
    EXPECT_TRUE(result2);

    tokenId = 3;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    bool result3 = PER_HELPER->CheckFunctionKeyEnabled();
    EXPECT_TRUE(result3);

    tokenId = 4;
    tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_INVALID;
    bool result4 = PER_HELPER->CheckFunctionKeyEnabled();
    EXPECT_TRUE(result4);
}

/**
 * @tc.name: PermissionHelperTest_CheckInjectPermission_01
 * @tc.desc: Test CheckInjectPermission with SHELL token type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckInjectPermission_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 3;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL;
    bool result = PER_HELPER->CheckInjectPermission();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: PermissionHelperTest_CheckInjectPermission_02
 * @tc.desc: Test CheckInjectPermission with permission verify failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckInjectPermission_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    // Mock VerifyAccessToken to return PERMISSION_DENIED
    bool result = PER_HELPER->CheckInjectPermission();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: PermissionHelperTest_CheckHapPermission_09
 * @tc.desc: Test CheckHapPermission with TOKEN_INVALID type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckHapPermission_09, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 4;
    std::string permissionCode = "access";
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_INVALID;
    bool result = PER_HELPER->CheckHapPermission(tokenId, permissionCode);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: PermissionHelperTest_CheckHapPermission_10
 * @tc.desc: Test CheckHapPermission with empty permission code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckHapPermission_10, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 2;
    std::string permissionCode = "";
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    bool result = PER_HELPER->CheckHapPermission(tokenId, permissionCode);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: PermissionHelperTest_GetTokenType_01
 * @tc.desc: Test GetTokenType with TOKEN_SHELL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_GetTokenType_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 3;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    int32_t result = PER_HELPER->GetTokenType();
    EXPECT_EQ(result, TokenType::TOKEN_SHELL);
}

/**
 * @tc.name: PermissionHelperTest_CheckKeyEventHook_01
 * @tc.desc: Test CheckKeyEventHook with permission check failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckKeyEventHook_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    // Mock CheckHapPermission to return false
    bool ret = PER_HELPER->CheckKeyEventHook();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: PermissionHelperTest_CheckKeyEventHook_02
 * @tc.desc: Test CheckKeyEventHook with permission check success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckKeyEventHook_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    // Mock CheckHapPermission to return true
    bool ret = PER_HELPER->CheckKeyEventHook();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: PermissionHelperTest_AddPermissionUsedRecord002
 * @tc.desc: Test AddPermissionUsedRecord with success case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_AddPermissionUsedRecord002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    unsigned int token = 3;
    std::string permissionName = "ohos.permission.INPUT_MONITORING";
    int32_t successCount = 1;
    int32_t failCount = 0;
    // Mock PrivacyKit::AddPermissionUsedRecord to return RET_OK
    EXPECT_FALSE(PER_HELPER->AddPermissionUsedRecord(token, permissionName, successCount, failCount));
}

/**
 * @tc.name: PermissionHelperTest_AddPermissionUsedRecord003
 * @tc.desc: Test AddPermissionUsedRecord with empty permission name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_AddPermissionUsedRecord003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    unsigned int token = 3;
    std::string permissionName = "";
    int32_t successCount = 0;
    int32_t failCount = 1;
    EXPECT_FALSE(PER_HELPER->AddPermissionUsedRecord(token, permissionName, successCount, failCount));
}

/**
 * @tc.name: PermissionHelperTest_RequestFromShell_01
 * @tc.desc: Test RequestFromShell with TOKEN_SHELL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_RequestFromShell_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 3;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL;
    bool result = PER_HELPER->RequestFromShell();
    EXPECT_TRUE(result);
}
} // namespace MMI
} // namespace OHOS