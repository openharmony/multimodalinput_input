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

#include <cstdio>
#include <gtest/gtest.h>
#include <securec.h>

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
constexpr size_t DEFAULT_BUFFER_LENGTH { 512 };
const std::string SECURE_SETTING_URI_PROXY {""};
} // namespace

class AccountManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: AccountManagerTest_GetInstance_01
 * @tc.desc: Test the funcation GetInstance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_GetInstance_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    accountManager.instance_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(accountManager.GetInstance());
}

/**
 * @tc.name: AccountManagerTest_SubscribeCommonEvent_01
 * @tc.desc: Test the funcation SubscribeCommonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_SubscribeCommonEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    accountManager.subscriber_ = nullptr;
    accountManager.timerId_ = -1;
    ASSERT_NO_FATAL_FAILURE(accountManager.SubscribeCommonEvent());
}

/**
 * @tc.name: AccountManagerTest_UnsubscribeCommonEvent_01
 * @tc.desc: Test the funcation UnsubscribeCommonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_UnsubscribeCommonEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    ASSERT_NO_FATAL_FAILURE(accountManager.SubscribeCommonEvent());
    accountManager.subscriber_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(accountManager.UnsubscribeCommonEvent());
}

/**
 * @tc.name: AccountManagerTest_SubscribeCommonEvent_02
 * @tc.desc: Test the funcation SubscribeCommonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_SubscribeCommonEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    accountManager.subscriber_ = nullptr;
    accountManager.timerId_ = 1;
    ASSERT_NO_FATAL_FAILURE(accountManager.SubscribeCommonEvent());
}

/**
 * @tc.name: AccountManagerTest_SetupMainAccount_01
 * @tc.desc: Test the funcation SetupMainAccount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_SetupMainAccount_01, TestSize.Level1)
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
 * @tc.name: AccountManagerTest_OnAddUser_01
 * @tc.desc: Test the funcation OnAddUser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_OnAddUser_01, TestSize.Level1)
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
 * @tc.name: AccountManagerTest_OnRemoveUser_01
 * @tc.desc: Test the funcation OnRemoveUser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_OnRemoveUser_01, TestSize.Level1)
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
 * @tc.name: AccountManagerTest_OnCommonEvent_01
 * @tc.desc: Test the funcation OnCommonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_OnCommonEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    EventFwk::CommonEventData data;
    ASSERT_NO_FATAL_FAILURE(accountManager.OnCommonEvent(data));
}

/**
 * @tc.name: AccountManagerTest_OnSwitchUser_01
 * @tc.desc: Test the funcation OnSwitchUser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_OnSwitchUser_01, TestSize.Level1)
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
 * @tc.name: AccountManagerTest_OnSwitchUser_02
 * @tc.desc: Test the funcation OnSwitchUser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_OnSwitchUser_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager accountManager;
    EventFwk::CommonEventData data;
    int32_t accountId = data.GetCode();
    accountId = 2;
    accountManager.currentAccountId_ = -1;
    ASSERT_NO_FATAL_FAILURE(accountManager.OnSwitchUser(data));
}

/**
 * @tc.name: AccountManagerTest_InitializeSetting_01
 * @tc.desc: Test the funcation InitializeSetting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_InitializeSetting_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 1;
    AccountManager::AccountSetting accountSetting(accountId);
    accountSetting.switchObserver_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(accountSetting.InitializeSetting());
}

/**
 * @tc.name: AccountManagerTest_InitializeSetting_02
 * @tc.desc: Test the funcation InitializeSetting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_InitializeSetting_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 2;
    AccountManager::AccountSetting accountSetting(accountId);
    accountSetting.onScreenLockedSwitchObserver_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(accountSetting.InitializeSetting());
}

/**
 * @tc.name: AccountManagerTest_InitializeSetting_03
 * @tc.desc: Test the funcation InitializeSetting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_InitializeSetting_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 3;
    AccountManager::AccountSetting accountSetting(accountId);
    accountSetting.configObserver_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(accountSetting.InitializeSetting());
}

/**
 * @tc.name: AccountManagerTest_ReadSwitchStatus_01
 * @tc.desc: Test the funcation ReadSwitchStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_ReadSwitchStatus_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 3;
    AccountManager::AccountSetting accountSetting(accountId);
    accountSetting.accountId_ = -1;
    std::string key = "down";
    bool currentSwitchStatus = true;
    bool ret = accountSetting.ReadSwitchStatus(key, currentSwitchStatus);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AccountManagerTest_ReadSwitchStatus_02
 * @tc.desc: Test the funcation ReadSwitchStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_ReadSwitchStatus_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 5;
    AccountManager::AccountSetting accountSetting(accountId);
    accountSetting.accountId_ = 2;
    std::string key = "down";
    bool currentSwitchStatus = false;

    char buf[DEFAULT_BUFFER_LENGTH] {};
    EXPECT_FALSE(sprintf_s(buf, sizeof(buf), SECURE_SETTING_URI_PROXY.c_str(), accountSetting.accountId_) > 0);
    bool ret = accountSetting.ReadSwitchStatus(key, currentSwitchStatus);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AccountManagerTest_ReadLongPressTime_01
 * @tc.desc: Test the funcation ReadLongPressTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_ReadLongPressTime_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 3;
    AccountManager::AccountSetting accountSetting(accountId);
    accountSetting.accountId_ = -1;
    ASSERT_NO_FATAL_FAILURE(accountSetting.ReadLongPressTime());
}

/**
 * @tc.name: AccountManagerTest_ReadLongPressTime_02
 * @tc.desc: Test the funcation ReadLongPressTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_ReadLongPressTime_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 3;
    AccountManager::AccountSetting accountSetting(accountId);
    accountSetting.accountId_ = 2;

    char buf[DEFAULT_BUFFER_LENGTH] {};
    EXPECT_FALSE(sprintf_s(buf, sizeof(buf), SECURE_SETTING_URI_PROXY.c_str(), accountSetting.accountId_) > 0);
    ASSERT_NO_FATAL_FAILURE(accountSetting.ReadLongPressTime());
}

/**
 * @tc.name: AccountManagerTest_AccShortcutTimeout_01
 * @tc.desc: Test the funcation AccShortcutTimeout
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_AccShortcutTimeout_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 1;
    std::string key = "testKey";
    AccountManager::AccountSetting accountSetting(accountId);
    auto accountMgr = ACCOUNT_MGR;
    accountMgr->accounts_.emplace(accountId, std::make_unique<AccountManager::AccountSetting>(accountId));
    ASSERT_NO_FATAL_FAILURE(accountSetting.AccShortcutTimeout(accountId, key));
}

/**
 * @tc.name: AccountManagerTest_AccShortcutTimeout_02
 * @tc.desc: Test the funcation AccShortcutTimeout
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_AccShortcutTimeout_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 2;
    std::string key = "testKey";
    AccountManager::AccountSetting accountSetting(accountId);
    auto accountMgr = ACCOUNT_MGR;
    ASSERT_NO_FATAL_FAILURE(accountSetting.AccShortcutTimeout(accountId, key));
}

/**
 * @tc.name: AccountManagerTest_AccShortcutEnabled_01
 * @tc.desc: Test the funcation AccShortcutEnabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_AccShortcutEnabled_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 1;
    std::string key = "shortcutKey";
    AccountManager::AccountSetting accountSetting(accountId);
    auto accountMgr = ACCOUNT_MGR;
    accountMgr->accounts_.emplace(accountId, std::make_unique<AccountManager::AccountSetting>(accountId));
    ASSERT_NO_FATAL_FAILURE(accountSetting.AccShortcutEnabled(accountId, key));
}

/**
 * @tc.name: AccountManagerTest_AccShortcutEnabled_02
 * @tc.desc: Test the funcation AccShortcutEnabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_AccShortcutEnabled_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 2;
    std::string key = "shortcutKey";
    AccountManager::AccountSetting accountSetting(accountId);
    auto accountMgr = ACCOUNT_MGR;
    ASSERT_NO_FATAL_FAILURE(accountSetting.AccShortcutEnabled(accountId, key));
}

/**
 * @tc.name: AccountManagerTest_AccShortcutEnabledOnScreenLocked_01
 * @tc.desc: Test the funcation AccShortcutEnabledOnScreenLocked
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_AccShortcutEnabledOnScreenLocked_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 1;
    std::string key = "shortcutKey";
    AccountManager::AccountSetting accountSetting(accountId);
    auto accountMgr = ACCOUNT_MGR;
    accountMgr->accounts_.emplace(accountId, std::make_unique<AccountManager::AccountSetting>(accountId));
    ASSERT_NO_FATAL_FAILURE(accountSetting.AccShortcutEnabledOnScreenLocked(accountId, key));
}

/**
 * @tc.name: AccountManagerTest_AccShortcutEnabledOnScreenLocked_02
 * @tc.desc: Test the funcation AccShortcutEnabledOnScreenLocked
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_AccShortcutEnabledOnScreenLocked_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 2;
    std::string key = "shortcutKey";
    AccountManager::AccountSetting accountSetting(accountId);
    auto accountMgr = ACCOUNT_MGR;
    ASSERT_NO_FATAL_FAILURE(accountSetting.AccShortcutEnabledOnScreenLocked(accountId, key));
}

/**
 * @tc.name: AccountManagerTest_ReadSwitchStatus_03
 * @tc.desc: Test the funcation ReadSwitchStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_ReadSwitchStatus_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = -1;
    AccountManager::AccountSetting accountSetting(accountId);
    std::string key = "down";
    bool currentSwitchStatus = true;
    bool ret = accountSetting.ReadSwitchStatus(key, currentSwitchStatus);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AccountManagerTest_ReadSwitchStatus_04
 * @tc.desc: Test the funcation ReadSwitchStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_ReadSwitchStatus_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 5;
    AccountManager::AccountSetting accountSetting(accountId);
    std::string key = "down";
    bool currentSwitchStatus = false;

    char buf[DEFAULT_BUFFER_LENGTH] {};
    EXPECT_FALSE(sprintf_s(buf, sizeof(buf), SECURE_SETTING_URI_PROXY.c_str(), accountSetting.accountId_) > 0);
    bool ret = accountSetting.ReadSwitchStatus(key, currentSwitchStatus);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AccountManagerTest_ReadLongPressTime_03
 * @tc.desc: Test the funcation ReadLongPressTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_ReadLongPressTime_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = -1;
    AccountManager::AccountSetting accountSetting(accountId);
    ASSERT_NO_FATAL_FAILURE(accountSetting.ReadLongPressTime());
}

/**
 * @tc.name: AccountManagerTest_ReadLongPressTime_04
 * @tc.desc: Test the funcation ReadLongPressTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_ReadLongPressTime_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t accountId = 3;
    AccountManager::AccountSetting accountSetting(accountId);
    accountSetting.accountId_ = 2;
    char buf[DEFAULT_BUFFER_LENGTH] {};
    EXPECT_FALSE(sprintf_s(buf, sizeof(buf), SECURE_SETTING_URI_PROXY.c_str(), accountSetting.accountId_) > 0);
    ASSERT_NO_FATAL_FAILURE(accountSetting.ReadLongPressTime());
}

/**
 * @tc.name: AccountManagerTest_GetCurrentAccountSetting
 * @tc.desc: Test the funcation GetCurrentAccountSetting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountManagerTest, AccountManagerTest_GetCurrentAccountSetting, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccountManager manager;
    manager.currentAccountId_ = 123;
    ASSERT_NO_FATAL_FAILURE(manager.GetCurrentAccountSetting());
}

} // namespace MMI
} // namespace OHOS