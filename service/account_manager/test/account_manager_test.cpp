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

#include <fstream>
#include <list>
#include <gtest/gtest.h>

#include "account_manager.h"
#include "key_event.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AccountManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t MAIN_ACCOUNT_ID { 100 };
} // namespace

class AccountManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: KeyGestureManagerTest_UnsubscribeCommonEvent_01
 * @tc.desc: Test the funcation UnsubscribeCommonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, KeyGestureManagerTest_UnsubscribeCommonEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    ASSERT_NO_FATAL_FAILURE(accountManager.SubscribeCommonEvent());
    accountManager.subscriber_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(accountManager.UnsubscribeCommonEvent());
}

/**
 * @tc.name: KeyGestureManagerTest_SubscribeCommonEvent_01
 * @tc.desc: Test the funcation SubscribeCommonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, KeyGestureManagerTest_SubscribeCommonEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    accountManager.subscriber_ = nullptr;
    accountManager.timerId_ = -1;
    ASSERT_NO_FATAL_FAILURE(accountManager.SubscribeCommonEvent());
}

/**
 * @tc.name: KeyGestureManagerTest_SubscribeCommonEvent_02
 * @tc.desc: Test the funcation SubscribeCommonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, KeyGestureManagerTest_SubscribeCommonEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    accountManager.subscriber_ = nullptr;
    accountManager.timerId_ = 1;
    ASSERT_NO_FATAL_FAILURE(accountManager.SubscribeCommonEvent());
}

/**
 * @tc.name: KeyGestureManagerTest_SetupMainAccount_01
 * @tc.desc: Test the funcation SetupMainAccount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, KeyGestureManagerTest_SetupMainAccount_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    accountManager.currentAccountId_ = MAIN_ACCOUNT_ID;
    auto [_, isNew] = accountManager.accounts_.emplace(MAIN_ACCOUNT_ID,
        std::make_unique<AccountManager::AccountSetting>(MAIN_ACCOUNT_ID));
    EXPECT_TRUE(isNew);
    ASSERT_NO_FATAL_FAILURE(accountManager.SetupMainAccount());
}

/**
 * @tc.name: KeyGestureManagerTest_OnAddUser_01
 * @tc.desc: Test the funcation OnAddUser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, KeyGestureManagerTest_OnAddUser_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    EventFwk::CommonEventData data;
    int32_t accountId = data.GetCode();
    accountId = 3;
    auto [_, isNew] = accountManager.accounts_.emplace(accountId,
        std::make_unique<AccountManager::AccountSetting>(accountId));
    EXPECT_TRUE(isNew);
    ASSERT_NO_FATAL_FAILURE(accountManager.OnAddUser(data));
}

/**
 * @tc.name: KeyGestureManagerTest_OnRemoveUser_01
 * @tc.desc: Test the funcation OnRemoveUser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, KeyGestureManagerTest_OnRemoveUser_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    EventFwk::CommonEventData data;
    int32_t accountId = data.GetCode();
    accountId = 5;
    ASSERT_NO_FATAL_FAILURE(accountManager.OnAddUser(data));
    ASSERT_NO_FATAL_FAILURE(accountManager.OnRemoveUser(data));
}

/**
 * @tc.name: KeyGestureManagerTest_OnCommonEvent_01
 * @tc.desc: Test the funcation OnCommonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, KeyGestureManagerTest_OnCommonEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    EventFwk::CommonEventData data;
    ASSERT_NO_FATAL_FAILURE(accountManager.OnCommonEvent(data));
}

/**
 * @tc.name: KeyGestureManagerTest_OnSwitchUser_01
 * @tc.desc: Test the funcation OnSwitchUser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, KeyGestureManagerTest_OnSwitchUser_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    EventFwk::CommonEventData data;
    int32_t accountId = data.GetCode();
    accountId = 1;
    accountManager.currentAccountId_ = 1;
    ASSERT_NO_FATAL_FAILURE(accountManager.OnSwitchUser(data));
}

/**
 * @tc.name: KeyGestureManagerTest_OnSwitchUser_02
 * @tc.desc: Test the funcation OnSwitchUser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, KeyGestureManagerTest_OnSwitchUser_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    EventFwk::CommonEventData data;
    int32_t accountId = data.GetCode();
    accountId = 2;
    accountManager.currentAccountId_ = -1;
    ASSERT_NO_FATAL_FAILURE(accountManager.OnSwitchUser(data));
}
} // namespace MMI
} // namespace OHOS