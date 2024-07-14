/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "account_manager.h"

#include <securec.h>
#include <common_event_manager.h>
#include <common_event_support.h>
#include <system_ability_definition.h>

#include "setting_datashare.h"
#include "timer_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AccountManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MAIN_ACCOUNT_ID { 100 };
constexpr int32_t REPEAT_ONCE { 1 };
constexpr int32_t REPEAT_COOLING_TIME { 1000 };
constexpr size_t DEFAULT_BUFFER_LENGTH { 512 };
const std::string ACC_SHORTCUT_ENABLED { "accessibility_shortcut_enabled" };
const std::string ACC_SHORTCUT_ENABLED_ON_LOCK_SCREEN { "accessibility_shortcut_enabled_on_lock_screen" };
const std::string ACC_SHORTCUT_TIMEOUT { "accessibility_shortcut_timeout" };
const std::string SECURE_SETTING_URI_PROXY {
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_%d?Proxy=true" };
}

std::shared_ptr<AccountManager> AccountManager::instance_;
std::mutex AccountManager::mutex_;

std::shared_ptr<AccountManager> AccountManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<AccountManager>();
        }
    }
    return instance_;
}

void AccountManager::CommonEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    if (accountMgr_.scheduler_ == nullptr) {
        MMI_HILOGE("Account manager is not initialized");
        return;
    }
    accountMgr_.scheduler_->PostSyncTask([&]() {
        accountMgr_.OnCommonEvent(data);
        return RET_OK;
    });
}

AccountManager::AccountSetting::AccountSetting(int32_t accountId)
    : accountId_(accountId)
{
    InitializeSetting();
}

AccountManager::AccountSetting::~AccountSetting()
{
    if (timerId_ >= 0) {
        TimerMgr->RemoveTimer(timerId_);
    }
    auto &setting = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID);
    if (switchObserver_ != nullptr) {
        setting.UnregisterObserver(switchObserver_);
    }
    if (onScreenLockedSwitchObserver_ != nullptr) {
        setting.UnregisterObserver(onScreenLockedSwitchObserver_);
    }
    if (configObserver_ != nullptr) {
        setting.UnregisterObserver(configObserver_);
    }
}

AccountManager::AccountSetting::AccountSetting(const AccountSetting &other)
    : accountId_(other.accountId_), accShortcutTimeout_(other.accShortcutTimeout_),
      accShortcutEnabled_(other.accShortcutEnabled_),
      accShortcutEnabledOnScreenLocked_(other.accShortcutEnabledOnScreenLocked_)
{}

AccountManager::AccountSetting& AccountManager::AccountSetting::operator=(const AccountSetting &other)
{
    accountId_ = other.accountId_;
    accShortcutTimeout_ = other.accShortcutTimeout_;
    accShortcutEnabled_ = other.accShortcutEnabled_;
    accShortcutEnabledOnScreenLocked_ = other.accShortcutEnabledOnScreenLocked_;
    return *this;
}

void AccountManager::AccountSetting::AccShortcutTimeout(int32_t accountId, const std::string &key)
{
    auto accountMgr = ACCOUNT_MGR;
    std::lock_guard<std::mutex> guard { accountMgr->lock_ };
    if (auto iter = accountMgr->accounts_.find(accountId); iter != accountMgr->accounts_.end()) {
        iter->second->OnAccShortcutTimeoutChanged(key);
    } else {
        MMI_HILOGW("No account(%{public}d)", accountId);
    }
}

void AccountManager::AccountSetting::AccShortcutEnabled(int32_t accountId, const std::string &key)
{
    auto accountMgr = ACCOUNT_MGR;
    std::lock_guard<std::mutex> guard { accountMgr->lock_ };
    if (auto iter = accountMgr->accounts_.find(accountId); iter != accountMgr->accounts_.end()) {
        iter->second->OnAccShortcutEnabled(key);
    } else {
        MMI_HILOGW("No account(%{public}d)", accountId);
    }
}

void AccountManager::AccountSetting::AccShortcutEnabledOnScreenLocked(int32_t accountId, const std::string &key)
{
    auto accountMgr = ACCOUNT_MGR;
    std::lock_guard<std::mutex> guard { accountMgr->lock_ };
    if (auto iter = accountMgr->accounts_.find(accountId); iter != accountMgr->accounts_.end()) {
        iter->second->OnAccShortcutEnabledOnScreenLocked(key);
    } else {
        MMI_HILOGW("No account(%{public}d)", accountId);
    }
}

sptr<SettingObserver> AccountManager::AccountSetting::RegisterSettingObserver(
    const std::string &key, SettingObserver::UpdateFunc onUpdate)
{
    char buf[DEFAULT_BUFFER_LENGTH] {};
    if (sprintf_s(buf, sizeof(buf), SECURE_SETTING_URI_PROXY.c_str(), accountId_) < 0) {
        MMI_HILOGE("Failed to format URI");
        return nullptr;
    }
    MMI_HILOGI("[AccountSetting] Registering observer of '%{public}s' in %{public}s", key.c_str(), buf);
    auto &settingHelper = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID);
    sptr<SettingObserver> settingObserver = settingHelper.CreateObserver(key, onUpdate);
    ErrCode ret = settingHelper.RegisterObserver(settingObserver, std::string(buf));
    if (ret != ERR_OK) {
        MMI_HILOGE("[AccountSetting] Failed to register '%{public}s' observer, error:%{public}d",
            key.c_str(), ret);
        return nullptr;
    }
    return settingObserver;
}

void AccountManager::AccountSetting::InitializeSetting()
{
    CALL_INFO_TRACE;
    if (switchObserver_ == nullptr) {
        switchObserver_ = RegisterSettingObserver(ACC_SHORTCUT_ENABLED,
            [accountId = accountId_](const std::string &key) {
                AccountManager::AccountSetting::AccShortcutEnabled(accountId, key);
            });
    }
    if (onScreenLockedSwitchObserver_ == nullptr) {
        onScreenLockedSwitchObserver_ = RegisterSettingObserver(ACC_SHORTCUT_ENABLED_ON_LOCK_SCREEN,
            [accountId = accountId_](const std::string &key) {
                AccountManager::AccountSetting::AccShortcutEnabledOnScreenLocked(accountId, key);
            });
    }
    if (configObserver_ == nullptr) {
        configObserver_ = RegisterSettingObserver(ACC_SHORTCUT_TIMEOUT,
            [accountId = accountId_](const std::string &key) {
                AccountManager::AccountSetting::AccShortcutTimeout(accountId, key);
            });
    }
    if ((switchObserver_ == nullptr) || (onScreenLockedSwitchObserver_ == nullptr) || (configObserver_ == nullptr)) {
        timerId_ = TimerMgr->AddTimer(REPEAT_COOLING_TIME, REPEAT_ONCE, [this]() {
            InitializeSetting();
        });
        if (timerId_ < 0) {
            MMI_HILOGE("AddTimer fail, setting will not work");
        }
    } else {
        timerId_ = -1;
    }
}

void AccountManager::AccountSetting::OnAccShortcutTimeoutChanged(const std::string &key)
{
    MMI_HILOGI("[AccountSetting][%{public}d] Setting '%{public}s' has changed", GetAccountId(), key.c_str());
    ReadLongPressTime();
}

void AccountManager::AccountSetting::OnAccShortcutEnabled(const std::string &key)
{
    MMI_HILOGI("[AccountSetting][%{public}d] Setting '%{public}s' has changed", GetAccountId(), key.c_str());
    accShortcutEnabled_ = ReadSwitchStatus(key, accShortcutEnabled_);
}

void AccountManager::AccountSetting::OnAccShortcutEnabledOnScreenLocked(const std::string &key)
{
    MMI_HILOGI("[AccountSetting][%{public}d] Setting '%{public}s' has changed", GetAccountId(), key.c_str());
    accShortcutEnabledOnScreenLocked_ = ReadSwitchStatus(key, accShortcutEnabledOnScreenLocked_);
}

bool AccountManager::AccountSetting::ReadSwitchStatus(const std::string &key, bool currentSwitchStatus)
{
    if (accountId_ < 0) {
        return false;
    }
    char buf[DEFAULT_BUFFER_LENGTH] {};
    if (sprintf_s(buf, sizeof(buf), SECURE_SETTING_URI_PROXY.c_str(), accountId_) < 0) {
        MMI_HILOGE("Failed to format URI");
        return currentSwitchStatus;
    }
    bool switchOn = true;
    auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).GetBoolValue(
        key, switchOn, std::string(buf));
    if (ret != RET_OK) {
        MMI_HILOGE("[AccountSetting] Failed to acquire '%{public}s', error:%{public}d", key.c_str(), ret);
        return currentSwitchStatus;
    }
    MMI_HILOGI("[AccountSetting] '%{public}s' switch %{public}s", key.c_str(), switchOn ? "on" : "off");
    return switchOn;
}

void AccountManager::AccountSetting::ReadLongPressTime()
{
    if (accountId_ < 0) {
        return;
    }
    char buf[DEFAULT_BUFFER_LENGTH] {};
    if (sprintf_s(buf, sizeof(buf), SECURE_SETTING_URI_PROXY.c_str(), accountId_) < 0) {
        MMI_HILOGE("Failed to format URI");
        return;
    }
    int32_t longPressTime {};
    auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).GetIntValue(
        ACC_SHORTCUT_TIMEOUT, longPressTime, std::string(buf));
    if (ret != RET_OK) {
        MMI_HILOGE("[AccountSetting] Failed to acquire '%{public}s', error:%{public}d",
            ACC_SHORTCUT_TIMEOUT.c_str(), ret);
        return;
    }
    accShortcutTimeout_ = longPressTime;
    MMI_HILOGI("[AccountSetting] '%{public}s' was set to %{public}d",
        ACC_SHORTCUT_TIMEOUT.c_str(), accShortcutTimeout_);
}

AccountManager::AccountManager()
{
    handlers_ = {
        {
            EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED,
            [this](const EventFwk::CommonEventData &data) {
                OnAddUser(data);
            },
        }, {
            EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED,
            [this](const EventFwk::CommonEventData &data) {
                OnRemoveUser(data);
            },
        }, {
            EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED,
            [this](const EventFwk::CommonEventData &data) {
                OnSwitchUser(data);
            },
        }
    };
}

AccountManager::~AccountManager()
{
    std::lock_guard<std::mutex> guard { lock_ };
    UnsubscribeCommonEvent();
    accounts_.clear();
}

void AccountManager::Initialize(DelegateTasks *scheduler)
{
    MMI_HILOGI("Initialize account manager");
    std::lock_guard<std::mutex> guard { lock_ };
    scheduler_ = scheduler;
    SetupMainAccount();
    SubscribeCommonEvent();
}

AccountManager::AccountSetting AccountManager::GetCurrentAccountSetting()
{
    std::lock_guard<std::mutex> guard { lock_ };
    if (auto iter = accounts_.find(currentAccountId_); iter != accounts_.end()) {
        return *iter->second;
    }
    auto [iter, _] = accounts_.emplace(currentAccountId_, std::make_unique<AccountSetting>(currentAccountId_));
    return *iter->second;
}

void AccountManager::SubscribeCommonEvent()
{
    CALL_INFO_TRACE;
    if (subscriber_ == nullptr) {
        EventFwk::MatchingSkills matchingSkills;

        for (auto &item : handlers_) {
            MMI_HILOGD("Add event: %{public}s", item.first.c_str());
            matchingSkills.AddEvent(item.first);
        }
        EventFwk::CommonEventSubscribeInfo subscribeInfo { matchingSkills };
        subscriber_ = std::make_shared<CommonEventSubscriber>(subscribeInfo, *this);
    }
    if (EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_)) {
        MMI_HILOGI("SubscribeCommonEvent succeed");
        return;
    }
    MMI_HILOGI("SubscribeCommonEvent fail, retry later");
    int32_t timerId = TimerMgr->AddTimer(REPEAT_COOLING_TIME, REPEAT_ONCE, [this]() {
        SubscribeCommonEvent();
    });
    if (timerId < 0) {
        MMI_HILOGE("AddTimer fail, SubscribeCommonEvent fail");
    }
}

void AccountManager::UnsubscribeCommonEvent()
{
    CALL_INFO_TRACE;
    if (subscriber_ != nullptr) {
        if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_)) {
            MMI_HILOGE("UnSubscribeCommonEvent fail");
        }
        subscriber_ = nullptr;
    }
}

void AccountManager::SetupMainAccount()
{
    MMI_HILOGI("Setup main account(%{public}d)", MAIN_ACCOUNT_ID);
    currentAccountId_ = MAIN_ACCOUNT_ID;
    auto [_, isNew] = accounts_.emplace(MAIN_ACCOUNT_ID, std::make_unique<AccountSetting>(MAIN_ACCOUNT_ID));
    if (!isNew) {
        MMI_HILOGW("Account(%{public}d) has existed", MAIN_ACCOUNT_ID);
    }
}

void AccountManager::OnCommonEvent(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    MMI_HILOGI("Receive common event: %{public}s", action.c_str());
    if (auto iter = handlers_.find(action); iter != handlers_.end()) {
        iter->second(data);
    } else {
        MMI_HILOGW("Ignore event: %{public}s", action.c_str());
    }
}

void AccountManager::OnAddUser(const EventFwk::CommonEventData &data)
{
    int32_t accountId = data.GetCode();
    MMI_HILOGI("Add account(%{public}d)", accountId);
    auto [_, isNew] = accounts_.emplace(accountId, std::make_unique<AccountSetting>(accountId));
    if (!isNew) {
        MMI_HILOGW("Account(%{public}d) has existed", accountId);
    }
}

void AccountManager::OnRemoveUser(const EventFwk::CommonEventData &data)
{
    int32_t accountId = data.GetCode();
    MMI_HILOGI("Remove account(%{public}d)", accountId);
    if (auto iter = accounts_.find(accountId); iter != accounts_.end()) {
        accounts_.erase(iter);
        MMI_HILOGI("Account(%{public}d) has been removed", accountId);
    } else {
        MMI_HILOGW("No account(%{public}d)", accountId);
    }
}

void AccountManager::OnSwitchUser(const EventFwk::CommonEventData &data)
{
    int32_t accountId = data.GetCode();
    MMI_HILOGI("Switch to account(%{public}d)", accountId);
    if (currentAccountId_ != accountId) {
        if (auto iter = accounts_.find(accountId); iter == accounts_.end()) {
            accounts_.emplace(accountId, std::make_unique<AccountSetting>(accountId));
        }
        currentAccountId_ = accountId;
        MMI_HILOGI("Switched to account(%{public}d)", currentAccountId_);
    }
}
} // namespace MMI
} // namespace OHOS
