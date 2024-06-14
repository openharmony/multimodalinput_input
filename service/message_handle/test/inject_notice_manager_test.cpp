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

#include "authorization_dialog.h"
#include "inject_notice_manager.h"
#include "message_option.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InjectNoticeManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InjectNoticeManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

class AuthorizationDialogTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: AuthorizationDialogTest_ConnectSystemUi
 * @tc.desc: Test ConnectSystemUi
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_ConnectSystemUi, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    EXPECT_FALSE(dialog.ConnectSystemUi());
}

/**
 * @tc.name: InjectNoticeManagerTest_StartNoticeAbility
 * @tc.desc: Test StartNoticeAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InjectNoticeManagerTest, InjectNoticeManagerTest_StartNoticeAbility, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InjectNoticeManager injectNoticeMgr;
    injectNoticeMgr.isStartSrv_ = false;
    EXPECT_FALSE(injectNoticeMgr.StartNoticeAbility());
}

/**
 * @tc.name: InjectNoticeManagerTest_ConnectNoticeSrv
 * @tc.desc: Test ConnectNoticeSrv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InjectNoticeManagerTest, InjectNoticeManagerTest_ConnectNoticeSrv, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InjectNoticeManager injectNoticeMgr;
    injectNoticeMgr.connectionCallback_ = new (std::nothrow) InjectNoticeManager::InjectNoticeConnection;
    ASSERT_NE(injectNoticeMgr.connectionCallback_, nullptr);
    injectNoticeMgr.connectionCallback_->isConnected_ = true;
    EXPECT_TRUE(injectNoticeMgr.ConnectNoticeSrv());
    injectNoticeMgr.connectionCallback_->isConnected_ = false;
    EXPECT_FALSE(injectNoticeMgr.ConnectNoticeSrv());
}
} // namespace MMI
} // namespace OHOS