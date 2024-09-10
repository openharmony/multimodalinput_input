/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ACCOUNT_MANAGER_H
#define ACCOUNT_MANAGER_H

#include <map>
#include <memory>

#include <common_event_subscriber.h>
#include <nocopyable.h>

#include "setting_observer.h"

namespace OHOS {
namespace MMI {
class AccountManager final {
    class CommonEventSubscriber : public EventFwk::CommonEventSubscriber {
    public:
        CommonEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
            : EventFwk::CommonEventSubscriber(subscribeInfo) {}
        ~CommonEventSubscriber() = default;

        void OnReceiveEvent(const EventFwk::CommonEventData &data);
    };

public:
    class AccountSetting final {
    public:
        AccountSetting(int32_t accountId);
        ~AccountSetting();
        DISALLOW_MOVE(AccountSetting);
        AccountSetting(const AccountSetting &other);
        AccountSetting& operator=(const AccountSetting &other);

        int32_t GetAccountId() const;
        bool GetAccShortcutEnabled() const;
        bool GetAccShortcutEnabledOnScreenLocked() const;
        int32_t GetAccShortcutTimeout() const;

    private:
        static void AccShortcutTimeout(int32_t accountId, const std::string &key);
        static void AccShortcutEnabled(int32_t accountId, const std::string &key);
        static void AccShortcutEnabledOnScreenLocked(int32_t accountId, const std::string &key);
        sptr<SettingObserver> RegisterSettingObserver(const std::string &key, SettingObserver::UpdateFunc onUpdate);
        void InitializeSetting();
        void OnAccShortcutTimeoutChanged(const std::string &key);
        void OnAccShortcutEnabled(const std::string &key);
        void OnAccShortcutEnabledOnScreenLocked(const std::string &key);
        bool ReadSwitchStatus(const std::string &key, bool currentSwitchStatus);
        void ReadLongPressTime();

        int32_t accountId_ { -1 };
        int32_t timerId_ { -1 };
        int32_t accShortcutTimeout_ { 3000 }; // 3s
        bool accShortcutEnabled_ {};
        bool accShortcutEnabledOnScreenLocked_ {};
        sptr<SettingObserver> switchObserver_;
        sptr<SettingObserver> onScreenLockedSwitchObserver_;
        sptr<SettingObserver> configObserver_;
    };

    static std::shared_ptr<AccountManager> GetInstance();

    AccountManager();
    ~AccountManager();
    DISALLOW_COPY_AND_MOVE(AccountManager);

    void Initialize();
    AccountSetting GetCurrentAccountSetting();

private:
#ifdef SCREENLOCK_MANAGER_ENABLED
    void InitializeScreenLockStatus();
#endif // SCREENLOCK_MANAGER_ENABLED
    void SubscribeCommonEvent();
    void UnsubscribeCommonEvent();
    void SetupMainAccount();
    void OnCommonEvent(const EventFwk::CommonEventData &data);
    void OnAddUser(const EventFwk::CommonEventData &data);
    void OnRemoveUser(const EventFwk::CommonEventData &data);
    void OnSwitchUser(const EventFwk::CommonEventData &data);

    static std::shared_ptr<AccountManager> instance_;
    static std::mutex mutex_;
    std::mutex lock_;
    int32_t timerId_ { -1 };
    int32_t currentAccountId_ { -1 };
    std::shared_ptr<CommonEventSubscriber> subscriber_;
    std::map<int32_t, std::unique_ptr<AccountSetting>> accounts_;
    std::map<std::string, std::function<void(const EventFwk::CommonEventData &)>> handlers_;
};

inline int32_t AccountManager::AccountSetting::GetAccountId() const
{
    return accountId_;
}

inline bool AccountManager::AccountSetting::GetAccShortcutEnabled() const
{
    return accShortcutEnabled_;
}

inline bool AccountManager::AccountSetting::GetAccShortcutEnabledOnScreenLocked() const
{
    return accShortcutEnabledOnScreenLocked_;
}

inline int32_t AccountManager::AccountSetting::GetAccShortcutTimeout() const
{
    return accShortcutTimeout_;
}

#define ACCOUNT_MGR ::OHOS::MMI::AccountManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // ACCOUNT_MANAGER_H
