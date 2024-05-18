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
 * @tc.name: PermissionHelperTest_CheckMonitorPermission
 * @tc.desc: Test CheckMonitorPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckMonitorPermission, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, INPUT_MONITORING);
    ret = OHOS::Security::AccessToken::PERMISSION_GRANTED;
    bool result = PER_HELPER->CheckMonitorPermission(tokenId);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: PermissionHelperTest_CheckInterceptorPermission
 * @tc.desc: Test CheckInterceptorPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckInterceptorPermission, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, INPUT_INTERCEPTOR);
    ret = OHOS::Security::AccessToken::PERMISSION_GRANTED;
    bool result = PER_HELPER->CheckInterceptorPermission(tokenId);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: PermissionHelperTest_CheckDispatchControlPermission
 * @tc.desc: Test CheckDispatchControlPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckDispatchControlPermission, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 1;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, INPUT_DISPATCHCONTROL);
    ret = OHOS::Security::AccessToken::PERMISSION_GRANTED;
    bool result = PER_HELPER->CheckDispatchControlPermission(tokenId);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: PermissionHelperTest_GetTokenType
 * @tc.desc: Test GetTokenType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_GetTokenType, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 5;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_SHELL;
    int32_t result = PER_HELPER->GetTokenType();
    EXPECT_EQ(result, TokenType::TOKEN_SHELL);
}

/**
 * @tc.name: PermissionHelperTest_CheckDispatchControl
 * @tc.desc: Test CheckDispatchControl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckDispatchControl, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t tokenId = 2;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    tokenType = OHOS::Security::AccessToken::TOKEN_HAP;
    bool result = PER_HELPER->CheckDispatchControl();
    ASSERT_TRUE(result);
}

/**
 * @tc.name: PermissionHelperTest_CheckHapPermission
 * @tc.desc: Test CheckHapPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_CheckHapPermission, TestSize.Level1)
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
 * @tc.name: PermissionHelperTest_VerifySystemApp
 * @tc.desc: Test VerifySystemApp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionHelperTest, PermissionHelperTest_VerifySystemApp, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t callerToken = 3;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    tokenType = OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE;
    bool result = PER_HELPER->VerifySystemApp();
    ASSERT_TRUE(result);
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
    tokenType = OHOS::Security::AccessToken::TOKEN_NATIVE;
    bool result = PER_HELPER->CheckPermission(required);
    ASSERT_TRUE(result);
}

} // namespace MMI
} // namespace OHOS