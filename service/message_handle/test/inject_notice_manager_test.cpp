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
    EXPECT_TRUE(dialog.ConnectSystemUi());
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

/**
 * @tc.name: AuthorizationDialogTest_ConnectSystemUi_002
 * @tc.desc: Test ConnectSystemUi
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_ConnectSystemUi_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    bool ret = dialog.ConnectSystemUi();
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: AuthorizationDialogTest_OnAbilityConnectDone_001
 * @tc.desc: Test OnAbilityConnectDone
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_OnAbilityConnectDone_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog::DialogAbilityConnection conn;
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject;
    int resultCode = 0;
    ASSERT_NO_FATAL_FAILURE(conn.OnAbilityConnectDone(element, remoteObject, resultCode));
}

/**
 * @tc.name: InjectNoticeManagerTest_StartNoticeAbility_002
 * @tc.desc: Test StartNoticeAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InjectNoticeManagerTest, InjectNoticeManagerTest_StartNoticeAbility_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InjectNoticeManager injectNoticeMgr;
    injectNoticeMgr.isStartSrv_ = true;
    bool ret = injectNoticeMgr.StartNoticeAbility();
    ASSERT_TRUE(ret);
    injectNoticeMgr.isStartSrv_ = false;
    ret = injectNoticeMgr.StartNoticeAbility();
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InjectNoticeManagerTest_ConnectNoticeSrv_002
 * @tc.desc: Test ConnectNoticeSrv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InjectNoticeManagerTest, InjectNoticeManagerTest_ConnectNoticeSrv_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InjectNoticeManager injectNoticeMgr;
    injectNoticeMgr.connectionCallback_ = new (std::nothrow) InjectNoticeManager::InjectNoticeConnection;
    ASSERT_NE(injectNoticeMgr.connectionCallback_, nullptr);
    injectNoticeMgr.connectionCallback_->isConnected_ = true;
    bool ret = injectNoticeMgr.ConnectNoticeSrv();
    ASSERT_TRUE(ret);
    injectNoticeMgr.connectionCallback_->isConnected_ = false;
    ret = injectNoticeMgr.ConnectNoticeSrv();
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InjectNoticeManagerTest_OnAbilityConnectDone_002
 * @tc.desc: Test OnAbilityConnectDone
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InjectNoticeManagerTest, InjectNoticeManagerTest_OnAbilityConnectDone_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InjectNoticeManager::InjectNoticeConnection connection;
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject;
    int resultCode = 0;
    ASSERT_NO_FATAL_FAILURE(connection.OnAbilityConnectDone(element, remoteObject, resultCode));
}

/**
 * @tc.name: InjectNoticeManagerTest_SendNotice_001
 * @tc.desc: Test SendNotice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InjectNoticeManagerTest, InjectNoticeManagerTest_SendNotice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InjectNoticeManager::InjectNoticeConnection connection;
    InjectNoticeInfo noticeInfo;
    noticeInfo.pid = 1;
    bool result = connection.InjectNoticeConnection::SendNotice(noticeInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InjectNoticeManagerTest_SendNotice_002
 * @tc.desc: Test SendNotice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InjectNoticeManagerTest, InjectNoticeManagerTest_SendNotice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InjectNoticeManager::InjectNoticeConnection connection;
    InjectNoticeInfo noticeInfo;
    noticeInfo.pid = -1;
    bool result = connection.InjectNoticeConnection::SendNotice(noticeInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InjectNoticeManagerTest_CancelNotice_001
 * @tc.desc: Test CancelNotice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InjectNoticeManagerTest, InjectNoticeManagerTest_CancelNotice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InjectNoticeManager::InjectNoticeConnection connection;
    InjectNoticeInfo noticeInfo;
    noticeInfo.pid = 1;
    bool result = connection.InjectNoticeConnection::CancelNotice(noticeInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InjectNoticeManagerTest_CancelNotice_002
 * @tc.desc: Test CancelNotice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InjectNoticeManagerTest, InjectNoticeManagerTest_CancelNotice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InjectNoticeManager::InjectNoticeConnection connection;
    InjectNoticeInfo noticeInfo;
    noticeInfo.pid = -1;
    bool result = connection.InjectNoticeConnection::CancelNotice(noticeInfo);
    EXPECT_FALSE(result);
}
} // namespace MMI
} // namespace OHOS