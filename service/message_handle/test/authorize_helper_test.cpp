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

#include <gtest/gtest.h>

#include "authorize_helper.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AuthorizeHelperTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class AuthorizeHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

void AuthorizeExitFunTest(int32_t) {}

/**
 * @tc.name: AuthorizeHelperTest_OnClientDeath
 * @tc.desc: Test OnClientDeath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizeHelperTest, ClientDeathHandlerTest_OnClientDeath, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = 10;
    AUTHORIZE_HELPER->pid_ = 11;
    EXPECT_NO_FATAL_FAILURE(AUTHORIZE_HELPER->OnClientDeath(pid));
    pid = 11;
    EXPECT_NO_FATAL_FAILURE(AUTHORIZE_HELPER->OnClientDeath(pid));
}

/**
 * @tc.name: AuthorizeHelperTest_AuthorizeProcessExit
 * @tc.desc: Test AuthorizeProcessExit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizeHelperTest, AuthorizeHelperTest_AuthorizeProcessExit, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AUTHORIZE_HELPER->exitCallback_ = AuthorizeExitFunTest;
    EXPECT_NO_FATAL_FAILURE(AUTHORIZE_HELPER->AuthorizeProcessExit());
}

/**
 * @tc.name: AuthorizeHelperTest_AuthorizeProcessExit_001
 * @tc.desc: Test AuthorizeProcessExit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizeHelperTest, AuthorizeHelperTest_AuthorizeProcessExit_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(AUTHORIZE_HELPER->AuthorizeProcessExit());
}

/**
 * @tc.name: AuthorizeHelperTest_AddAuthorizeProcess_001
 * @tc.desc: Test the function AddAuthorizeProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizeHelperTest, AuthorizeHelperTest_AddAuthorizeProcess_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = -1;
    AuthorizeExitCallback exitCallback = nullptr;
    AUTHORIZE_HELPER->isInit_ = false;
    int32_t ret = AUTHORIZE_HELPER->AddAuthorizeProcess(pid, exitCallback);
    EXPECT_EQ(ret, RET_ERR);
    AUTHORIZE_HELPER->isInit_ = true;
    ret = AUTHORIZE_HELPER->AddAuthorizeProcess(pid, exitCallback);
    EXPECT_EQ(ret, RET_ERR);
    pid = 0;
    ret = AUTHORIZE_HELPER->AddAuthorizeProcess(pid, exitCallback);
    EXPECT_EQ(ret, RET_ERR);
    pid = 1;
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_UNAUTHORIZE;
    AUTHORIZE_HELPER->pid_ = -1;
    ret = AUTHORIZE_HELPER->AddAuthorizeProcess(pid, exitCallback);
    EXPECT_EQ(ret, RET_OK);
    AUTHORIZE_HELPER->pid_ = 2;
    ret = AUTHORIZE_HELPER->AddAuthorizeProcess(pid, exitCallback);
    EXPECT_EQ(ret, RET_ERR);
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_SELECTION_AUTHORIZE;
    ret = AUTHORIZE_HELPER->AddAuthorizeProcess(pid, exitCallback);
    EXPECT_EQ(ret, RET_ERR);
    AUTHORIZE_HELPER->pid_ = 1;
    ret = AUTHORIZE_HELPER->AddAuthorizeProcess(pid, exitCallback);
    EXPECT_EQ(ret, RET_OK);
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_AUTHORIZE;
    ret = AUTHORIZE_HELPER->AddAuthorizeProcess(pid, exitCallback);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: AuthorizeHelperTest_CancelAuthorize_001
 * @tc.desc: Test the function CancelAuthorize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizeHelperTest, AuthorizeHelperTest_CancelAuthorize_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = -1;
    EXPECT_NO_FATAL_FAILURE(AUTHORIZE_HELPER->CancelAuthorize(pid));
    pid = 1;
    AUTHORIZE_HELPER->pid_ = 0;
    EXPECT_NO_FATAL_FAILURE(AUTHORIZE_HELPER->CancelAuthorize(pid));
    AUTHORIZE_HELPER->pid_ = 1;
    EXPECT_NO_FATAL_FAILURE(AUTHORIZE_HELPER->CancelAuthorize(pid));
}
} // namespace MMI
} // namespace OHOS