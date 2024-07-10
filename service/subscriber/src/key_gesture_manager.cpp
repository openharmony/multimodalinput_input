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

#include "key_gesture_manager.h"

#include <algorithm>
#include <system_ability_definition.h>

#include "app_state_observer.h"
#include "define_multimodal.h"
#include "display_event_monitor.h"
#include "setting_datashare.h"
#include "timer_manager.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyGestureManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t COMBINATION_KEY_TIMEOUT { 150 };
constexpr int32_t INVALID_ENTITY_ID { -1 };
constexpr int32_t REPEAT_ONCE { 1 };
constexpr int32_t RETRY_COOLING_TIME { 500 }; // 500ms
constexpr int32_t DEFAULT_LONG_PRESS_TIME { 3000 }; // 3s
constexpr size_t SINGLE_KEY_PRESSED { 1 };
const std::string ACC_SHORTCUT_ENABLED { "accessibility_shortcut_enabled" };
const std::string ACC_SHORTCUT_ENABLED_ON_LOCK_SCREEN { "accessibility_shortcut_enabled_on_lock_screen" };
const std::string ACC_SHORTCUT_TIMEOUT { "accessibility_shortcut_timeout" };
const std::string SECURE_SETTING_URI_PROXY {
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_100?Proxy=true" };
}

void KeyGestureManager::Handler::ResetTimer()
{
    if (timerId_ >= 0) {
        TimerMgr->RemoveTimer(timerId_);
        timerId_ = INVALID_ENTITY_ID;
    }
}

bool KeyGestureManager::KeyGesture::IsWorking()
{
    return true;
}

int32_t KeyGestureManager::KeyGesture::AddHandler(int32_t pid, int32_t longPressTime,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    static int32_t baseId { 0 };

    longPressTime = std::max(longPressTime, COMBINATION_KEY_TIMEOUT);
    return handlers_.emplace_back(++baseId, pid, longPressTime, callback).GetId();
}

bool KeyGestureManager::KeyGesture::RemoveHandler(int32_t id)
{
    for (auto iter = handlers_.begin(); iter != handlers_.end(); ++iter) {
        if (iter->GetId() == id) {
            handlers_.erase(iter);
            MMI_HILOGI("Handler(%{public}d) of key gesture was removed", iter->GetId());
            return true;
        }
    }
    return false;
}

void KeyGestureManager::KeyGesture::Reset()
{
    MarkActive(false);
    ResetTimers();
}

void KeyGestureManager::KeyGesture::ResetTimers()
{
    for (auto &handler : handlers_) {
        handler.ResetTimer();
    }
}

std::set<int32_t> KeyGestureManager::KeyGesture::GetForegroundPids() const
{
    std::set<int32_t> pids;
    std::vector<AppExecFwk::AppStateData> appStates = APP_OBSERVER_MGR->GetForegroundAppData();
    std::for_each(appStates.cbegin(), appStates.cend(), [&pids](auto &appState) {
        pids.insert(appState.pid);
    });
    return pids;
}

bool KeyGestureManager::KeyGesture::HaveForegroundHandler(const std::set<int32_t> &foregroundApps) const
{
    return std::any_of(handlers_.cbegin(), handlers_.cend(), [&foregroundApps](const auto &handler) {
        return (foregroundApps.find(handler.GetPid()) != foregroundApps.cend());
    });
}

void KeyGestureManager::KeyGesture::TriggerHandlers(std::shared_ptr<KeyEvent> keyEvent)
{
    std::set<int32_t> foregroundPids = GetForegroundPids();
    bool haveForeground = HaveForegroundHandler(foregroundPids);

    for (auto &handler : handlers_) {
        if (!haveForeground || (foregroundPids.find(handler.GetPid()) != foregroundPids.end())) {
            auto timerId = TimerMgr->AddTimer(handler.GetLongPressTime(), REPEAT_ONCE,
                [this, handlerId = handler.GetId(), tKeyEvent = KeyEvent::Clone(keyEvent)]() {
                    RunHandler(handlerId, tKeyEvent);
                });
            handler.SetTimerId(timerId);
        }
    }
}

void KeyGestureManager::KeyGesture::RunHandler(int32_t handlerId, std::shared_ptr<KeyEvent> keyEvent)
{
    for (auto &handler : handlers_) {
        if (handler.GetId() == handlerId) {
            handler.Run(keyEvent);
            break;
        }
    }
}

void KeyGestureManager::KeyGesture::NotifyHandlers(std::shared_ptr<KeyEvent> keyEvent)
{
    std::set<int32_t> foregroundPids = GetForegroundPids();
    bool haveForeground = HaveForegroundHandler(foregroundPids);

    for (auto &handler : handlers_) {
        if (!haveForeground || (foregroundPids.find(handler.GetPid()) != foregroundPids.end())) {
            handler.Run(keyEvent);
        }
    }
}

bool KeyGestureManager::LongPressSingleKey::ShouldIntercept(std::shared_ptr<KeyOption> keyOption) const
{
    std::set<int32_t> keys = keyOption->GetPreKeys();
    return (keys.empty() && (keyOption->GetFinalKey() == keyCode_));
}

bool KeyGestureManager::LongPressSingleKey::Intercept(std::shared_ptr<KeyEvent> keyEvent)
{
    if ((keyEvent->GetKeyCode() == keyCode_) && (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN)) {
        if (IsActive()) {
            int32_t now = GetSysClockTime();
            if (now >= (firstDownTime_ + MS2US(COMBINATION_KEY_TIMEOUT))) {
                NotifyHandlers(keyEvent);
            }
        } else {
            firstDownTime_ = GetSysClockTime();
            MarkActive(true);
            TriggerHandlers(keyEvent);
        }
        return true;
    }
    if (IsActive()) {
        Reset();
        if (keyEvent->GetKeyCode() == keyCode_) {
            NotifyHandlers(keyEvent);
        }
    }
    return false;
}

void KeyGestureManager::LongPressSingleKey::Dump(std::ostringstream &output) const
{
    output << "[" << keyCode_ << "] --> {";
    if (auto iter = handlers_.begin(); iter != handlers_.end()) {
        output << iter->GetLongPressTime();
        for (++iter; iter != handlers_.end(); ++iter) {
            output << "," << iter->GetLongPressTime();
        }
    }
    output << "}";
}

bool KeyGestureManager::LongPressCombinationKey::ShouldIntercept(std::shared_ptr<KeyOption> keyOption) const
{
    std::set<int32_t> keys = keyOption->GetPreKeys();
    keys.insert(keyOption->GetFinalKey());
    return (keys_ == keys);
}

bool KeyGestureManager::LongPressCombinationKey::Intercept(std::shared_ptr<KeyEvent> keyEvent)
{
    if ((keys_.find(keyEvent->GetKeyCode()) != keys_.end()) &&
        (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN)) {
        if (IsActive()) {
            std::ostringstream output;
            output << "[LongPressCombinationKey] ";
            Dump(output);
            MMI_HILOGI("%{public}s is active now", output.str().c_str());
            return true;
        }
        if (!IsWorking()) {
            std::ostringstream output;
            output << "[LongPressCombinationKey] Switch off ";
            Dump(output);
            MMI_HILOGI("%{public}s", output.str().c_str());
            return false;
        }
        if (handlers_.empty()) {
            std::ostringstream output;
            output << "[LongPressCombinationKey] No handler for ";
            Dump(output);
            MMI_HILOGI("%{public}s", output.str().c_str());
            return false;
        }
        if (RecognizeGesture(keyEvent)) {
            TriggerAll(keyEvent);
            return true;
        }
    }
    if (IsActive()) {
        Reset();
    }
    return false;
}

void KeyGestureManager::LongPressCombinationKey::Dump(std::ostringstream &output) const
{
    output << "[";
    if (auto keyIter = keys_.begin(); keyIter != keys_.end()) {
        output << *keyIter;
        for (++keyIter; keyIter != keys_.end(); ++keyIter) {
            output << "," << *keyIter;
        }
    }
    output << "] --> {";
    if (auto iter = handlers_.begin(); iter != handlers_.end()) {
        output << "(ID:" << iter->GetId() << ",T:" << iter->GetLongPressTime() << ")";
        for (++iter; iter != handlers_.end(); ++iter) {
            output << ",(ID:" << iter->GetId() << ",T:" << iter->GetLongPressTime() << ")";
        }
    }
    output << "}";
}

bool KeyGestureManager::LongPressCombinationKey::RecognizeGesture(std::shared_ptr<KeyEvent> keyEvent)
{
    if (keyEvent->GetPressedKeys().size() == SINGLE_KEY_PRESSED) {
        firstDownTime_ = GetSysClockTime();
    }
    int32_t now = GetSysClockTime();
    return std::all_of(keys_.cbegin(), keys_.cend(), [this, keyEvent, now](auto keyCode) {
        auto itemOpt = keyEvent->GetKeyItem(keyCode);
        return (itemOpt && itemOpt->IsPressed() &&
                (now < (firstDownTime_ + MS2US(COMBINATION_KEY_TIMEOUT))));
    });
}

void KeyGestureManager::LongPressCombinationKey::TriggerAll(std::shared_ptr<KeyEvent> keyEvent)
{
    MarkActive(true);
    std::ostringstream output;
    output << "[LongPressCombinationKey] trigger ";
    Dump(output);
    MMI_HILOGI("%{public}s", output.str().c_str());
    TriggerHandlers(keyEvent);
}

KeyGestureManager::PullUpAccessibility::PullUpAccessibility()
    : LongPressCombinationKey(std::set({ KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP }))
{
    InitializeSetting();
}

KeyGestureManager::PullUpAccessibility::~PullUpAccessibility()
{
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

bool KeyGestureManager::PullUpAccessibility::IsWorking()
{
    return ((DISPLAY_MONITOR->GetScreenStatus() != EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) &&
            (DISPLAY_MONITOR->GetScreenLocked() ? setting_.enableOnScreenLocked : setting_.enable));
}

int32_t KeyGestureManager::PullUpAccessibility::AddHandler(int32_t pid,
    int32_t longPressTime, std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    return KeyGesture::AddHandler(pid, DEFAULT_LONG_PRESS_TIME, callback);
}

sptr<SettingObserver> KeyGestureManager::PullUpAccessibility::RegisterSettingObserver(
    const std::string &key, SettingObserver::UpdateFunc onUpdate)
{
    MMI_HILOGI("[PullUpAccessibility] Registering observer of '%{public}s'", key.c_str());
    auto &settingHelper = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID);
    sptr<SettingObserver> settingObserver = settingHelper.CreateObserver(key, onUpdate);
    ErrCode ret = settingHelper.RegisterObserver(settingObserver, SECURE_SETTING_URI_PROXY);
    if (ret != ERR_OK) {
        MMI_HILOGE("[PullUpAccessibility] Failed to register '%{public}s' observer, error:%{public}d",
            key.c_str(), ret);
        return nullptr;
    }
    return settingObserver;
}

void KeyGestureManager::PullUpAccessibility::InitializeSetting()
{
    if (switchObserver_ == nullptr) {
        switchObserver_ = RegisterSettingObserver(ACC_SHORTCUT_ENABLED, [this](const std::string &key) {
            setting_.enable = ReadSwitchStatus(key, setting_.enable);
        });
        setting_.enable = ReadSwitchStatus(ACC_SHORTCUT_ENABLED, setting_.enable);
    }
    if (onScreenLockedSwitchObserver_ == nullptr) {
        onScreenLockedSwitchObserver_ = RegisterSettingObserver(ACC_SHORTCUT_ENABLED_ON_LOCK_SCREEN,
            [this](const std::string &key) {
                setting_.enableOnScreenLocked = ReadSwitchStatus(key, setting_.enableOnScreenLocked);
            });
        setting_.enableOnScreenLocked = ReadSwitchStatus(
            ACC_SHORTCUT_ENABLED_ON_LOCK_SCREEN, setting_.enableOnScreenLocked);
    }
    if (configObserver_ == nullptr) {
        configObserver_ = RegisterSettingObserver(ACC_SHORTCUT_TIMEOUT,
            [this](const std::string &key) {
                ReadLongPressTime();
            });
        ReadLongPressTime();
    }
    if ((switchObserver_ == nullptr) || (onScreenLockedSwitchObserver_ == nullptr) || (configObserver_ == nullptr)) {
        TimerMgr->AddTimer(RETRY_COOLING_TIME, REPEAT_ONCE, [this]() {
            InitializeSetting();
        });
    }
}

bool KeyGestureManager::PullUpAccessibility::ReadSwitchStatus(const std::string &key, bool currentSwitchStatus)
{
    bool switchOn = true;
    auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).GetBoolValue(
        key, switchOn, SECURE_SETTING_URI_PROXY);
    if (ret != RET_OK) {
        MMI_HILOGE("[PullUpAccessibility] Failed to acquire '%{public}s', error:%{public}d", key.c_str(), ret);
        return currentSwitchStatus;
    }
    MMI_HILOGI("[PullUpAccessibility] '%{public}s' switch %{public}s", key.c_str(), switchOn ? "on" : "off");
    return switchOn;
}

void KeyGestureManager::PullUpAccessibility::ReadLongPressTime()
{
    int32_t longPressTime {};
    auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).GetIntValue(
        ACC_SHORTCUT_TIMEOUT, longPressTime, SECURE_SETTING_URI_PROXY);
    if (ret != RET_OK) {
        MMI_HILOGE("[PullUpAccessibility] Failed to acquire '%{public}s', error:%{public}d",
            ACC_SHORTCUT_TIMEOUT.c_str(), ret);
        longPressTime = DEFAULT_LONG_PRESS_TIME;
    }
    if (longPressTime < COMBINATION_KEY_TIMEOUT) {
        longPressTime = COMBINATION_KEY_TIMEOUT;
    }
    MMI_HILOGI("[PullUpAccessibility] '%{public}s' setting: %{public}d",
        ACC_SHORTCUT_TIMEOUT.c_str(), longPressTime);
    if (!handlers_.empty()) {
        for (auto &handler : handlers_) {
            handler.SetLongPressTime(longPressTime);
        }
        MMI_HILOGI("[PullUpAccessibility] '%{public}s' was set to %{public}d",
            ACC_SHORTCUT_TIMEOUT.c_str(), longPressTime);
    }
}

KeyGestureManager::KeyGestureManager()
{
    keyGestures_.push_back(std::make_unique<PullUpAccessibility>());
    keyGestures_.push_back(std::make_unique<LongPressSingleKey>(KeyEvent::KEYCODE_VOLUME_DOWN));
    keyGestures_.push_back(std::make_unique<LongPressSingleKey>(KeyEvent::KEYCODE_VOLUME_UP));
}

bool KeyGestureManager::ShouldIntercept(std::shared_ptr<KeyOption> keyOption) const
{
    CALL_INFO_TRACE;
    CHKPF(keyOption);
    return std::any_of(keyGestures_.cbegin(), keyGestures_.cend(),
        [keyOption](const auto &keyGesture) {
            return keyGesture->ShouldIntercept(keyOption);
        });
}

int32_t KeyGestureManager::AddKeyGesture(int32_t pid, std::shared_ptr<KeyOption> keyOption,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    CHKPR(keyOption, INVALID_ENTITY_ID);
    for (auto &keyGesture : keyGestures_) {
        if (keyGesture->ShouldIntercept(keyOption)) {
            auto downDuration = std::max(keyOption->GetFinalKeyDownDuration(), COMBINATION_KEY_TIMEOUT);
            return keyGesture->AddHandler(pid, downDuration, callback);
        }
    }
    return INVALID_ENTITY_ID;
}

void KeyGestureManager::RemoveKeyGesture(int32_t id)
{
    for (auto &keyGesture : keyGestures_) {
        if (keyGesture->RemoveHandler(id)) {
            break;
        }
    }
}

bool KeyGestureManager::Intercept(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_INFO_TRACE;
    CHKPF(keyEvent);
    for (auto iter = keyGestures_.begin(); iter != keyGestures_.end(); ++iter) {
        if ((*iter)->Intercept(keyEvent)) {
            std::ostringstream output;
            output << "Intercepted by ";
            (*iter)->Dump(output);
            MMI_HILOGI("%{public}s", output.str().c_str());
            for (++iter; iter != keyGestures_.end(); ++iter) {
                (*iter)->Reset();
            }
            return true;
        }
    }
    return false;
}

void KeyGestureManager::Dump() const
{
    for (const auto &keyGesture : keyGestures_) {
        std::ostringstream output;
        keyGesture->Dump(output);
        MMI_HILOGI("%{public}s", output.str().c_str());
    }
}
} // namespace MMI
} // namespace OHOS
