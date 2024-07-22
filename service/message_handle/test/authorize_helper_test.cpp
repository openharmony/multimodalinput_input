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
    AuthorizeHelper authorizeHelper;
    int32_t pid = 10;
    authorizeHelper.pid_ = 11;
    EXPECT_NO_FATAL_FAILURE(authorizeHelper.OnClientDeath(pid));
    pid = 11;
    EXPECT_NO_FATAL_FAILURE(authorizeHelper.OnClientDeath(pid));
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
    AuthorizeHelper authorizeHelper;
    authorizeHelper.exitCallback_ = AuthorizeExitFunTest;
    EXPECT_NO_FATAL_FAILURE(authorizeHelper.AuthorizeProcessExit());
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
    AuthorizeHelper authorizeHelper;
    EXPECT_NO_FATAL_FAILURE(authorizeHelper.AuthorizeProcessExit());
}
} // namespace MMI
} // namespace OHOS