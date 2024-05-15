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
    static void SetUp() {}
    static void TearDown() {}
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
    bool result = PerHelper->CheckMonitorPermission(tokenId);
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
    bool result = PerHelper->CheckInterceptorPermission(tokenId);
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
    bool result = PerHelper->CheckDispatchControlPermission(tokenId);
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
    int32_t result = PerHelper->GetTokenType();
    EXPECT_EQ(result, TokenType::TOKEN_SHELL);
}
} // namespace MMI
} // namespace OHOS