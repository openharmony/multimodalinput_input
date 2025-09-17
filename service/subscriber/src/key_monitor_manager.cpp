/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "key_monitor_manager.h"

#include "bundle_name_parser.h"
#include "define_multimodal.h"
#include "event_log_helper.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "key_auto_repeat.h"
#include "multimodal_input_plugin_manager.h"
#include "timer_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyMonitorManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t REPEAT_ONCE { 1 };
const std::string MEETIME_NAME { "MEETIME_DTOD_NAME" };
}

const std::set<int32_t> KeyMonitorManager::allowedKeys_ {
    KeyEvent::KEYCODE_VOLUME_DOWN,
    KeyEvent::KEYCODE_VOLUME_UP,
    KeyEvent::KEYCODE_MEDIA_PLAY_PAUSE,
    KeyEvent::KEYCODE_MEDIA_NEXT,
    KeyEvent::KEYCODE_MEDIA_PREVIOUS,
};

std::shared_ptr<KeyMonitorManager> KeyMonitorManager::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<KeyMonitorManager> instance_;

    std::call_once(flag, []() {
        instance_ = std::make_shared<KeyMonitorManager>();
    });
    return instance_;
}

bool KeyMonitorManager::Monitor::operator<(const Monitor &other) const
{
    if (session_ != other.session_) {
        return (session_ < other.session_);
    }
    if (key_ != other.key_) {
        return (key_ < other.key_);
    }
    if (action_ != other.action_) {
        return (action_ < other.action_);
    }
    return (isRepeat_ < other.isRepeat_);
}

std::string KeyMonitorManager::Monitor::Dump() const
{
    std::ostringstream sMonitor;
    sMonitor << "Session:" << session_ << ",Key:" << key_ << ",Action:" << action_
        << ",IsRepeat:" << std::boolalpha << isRepeat_;
    return std::move(sMonitor).str();
}

bool KeyMonitorManager::Monitor::IsFocused() const
{
    return WIN_MGR->IsFocusedSession(session_);
}

bool KeyMonitorManager::Monitor::Want(std::shared_ptr<KeyEvent> keyEvent) const
{
    CHKPF(keyEvent);
    int32_t keyCode = keyEvent->GetKeyCode();
    int32_t keyAction = keyEvent->GetKeyAction();
    int32_t repeatCode = KeyRepeat->GetRepeatKeyCode();
    MMI_HILOGD("[key_:%{public}d, KC:%{private}d], [action_:%{public}d, KA:%{public}d]"
        "[isRepeat_:%{public}d, repeatCode:%{private}d]",
        key_, keyCode, action_, keyAction, isRepeat_, repeatCode);

    if (key_ != keyCode) {
        MMI_HILOGE("Invalid subscription key:%{private}d", keyCode);
        return false;
    }

    bool repeatValue = (keyAction == KeyEvent::KEY_ACTION_DOWN) ? (keyCode != repeatCode) :
        ((keyCode == repeatCode) || keyEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE));
    bool flag = false;
    if (action_ == MonitorType::MONITOR_ACTION_ONLY_DOWN) {
        flag = (keyAction == KeyEvent::KEY_ACTION_DOWN) &&
            (isRepeat_ || (keyCode != repeatCode));
    } else if (action_ == MonitorType::MONITOR_ACTION_DOWN_AND_UP) {
        flag = ((keyAction == KeyEvent::KEY_ACTION_DOWN) ||
            (keyAction == KeyEvent::KEY_ACTION_UP)) && (isRepeat_ || repeatValue);
    } else  {
        MMI_HILOGW("Invalid MonitorType");
        flag = false;
    }
    return flag;
}

KeyMonitorManager::KeyMonitorManager()
{
    auto udsServer = InputHandler->GetUDSServer();
    if (udsServer != nullptr) {
        udsServer->AddSessionDeletedCallback([this](SessionPtr sess) {
            CHKPV(sess);
            OnSessionLost(sess->GetPid());
        });
    }
}

int32_t KeyMonitorManager::AddMonitor(const Monitor &monitor, const std::string &bundleName)
{
    MMI_HILOGI("Add key monitor(%{public}s)", monitor.Dump().c_str());
    if (!CheckMonitor(monitor)) {
        MMI_HILOGE("Invalid monitor(%{public}s)", monitor.Dump().c_str());
        return -PARAM_INPUT_INVALID;
    }
    auto [_, isNew] = monitors_.emplace(monitor);
    if (!isNew) {
        MMI_HILOGW("Duplicate registration of monitor(%{public}s)", monitor.Dump().c_str());
    }
    std::string name = BUNDLE_NAME_PARSER.GetBundleName(MEETIME_NAME);
    if (name == bundleName) {
        MMI_HILOGI("The meetime has already subscribed, bundleName:%{public}s", bundleName.c_str());
        SetMeeTimeSubcriber(true, "Subscriber");
        meeTimeMonitor_.emplace(bundleName, monitor.session_);
    }

    return RET_OK;
}

void KeyMonitorManager::RemoveMonitor(const Monitor &monitor, const std::string &bundleName)
{
    MMI_HILOGI("Remove key monitor(%{public}s)", monitor.Dump().c_str());
    auto iter = monitors_.find(monitor);
    if (iter == monitors_.cend()) {
        MMI_HILOGW("No key monitor(%{public}s)", monitor.Dump().c_str());
        return;
    }
    monitors_.erase(iter);

    std::string name = BUNDLE_NAME_PARSER.GetBundleName(MEETIME_NAME);
    if (name == bundleName) {
        SetMeeTimeSubcriber(false, "Unsubscriber");
        if (meeTimeMonitor_.find(bundleName) != meeTimeMonitor_.cend()) {
            MMI_HILOGI("Remove MeeTime monitor:%{public}s", bundleName.c_str());
            meeTimeMonitor_.erase(bundleName);
        }
    }
}

void KeyMonitorManager::NotifyMeeTimeMonitor(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    std::string name = BUNDLE_NAME_PARSER.GetBundleName(MEETIME_NAME);
    auto it = meeTimeMonitor_.find(name);
    if (it != meeTimeMonitor_.cend()) {
        int32_t value = it->second;
        MMI_HILOGI("Notify MeeTime [name:%{public}s, value:%{public}d]", name.c_str(), value);
        NotifyKeyMonitor(keyEvent, value, isMeeTimeSubcriber_);
    }
}

bool KeyMonitorManager::Intercept(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    if (CheckMeeTimeMonitor(keyEvent)) {
        NotifyMeeTimeMonitor(keyEvent);
        return true;
    }
    std::set<int32_t> sessions;
    auto nTriggered = std::count_if(monitors_.cbegin(), monitors_.cend(),
        [this, keyEvent, &sessions](const auto &monitor) {
            if (monitor.Want(keyEvent)) {
                if (CheckMeeTimeMonitor(keyEvent)) {
                    NotifyMeeTimeMonitor(keyEvent);
                    return true;
                }
                if (monitor.IsFocused() &&
                    (sessions.find(monitor.session_) == sessions.cend())) {
                    sessions.emplace(monitor.session_);
                    NotifyKeyMonitor(keyEvent, monitor.session_, isMeeTimeSubcriber_);
                    return true;
                }
            }
            return false;
        });
    return (nTriggered > 0);
}

bool KeyMonitorManager::Intercept(std::shared_ptr<KeyEvent> keyEvent, int32_t delay)
{
    CHKPF(keyEvent);
    if ((keyEvent->GetKeyAction() != KeyEvent::KEY_ACTION_DOWN) || (delay <= 0)) {
        return false;
    }
    std::set<int32_t> sessions;
    auto nTriggered = std::count_if(monitors_.cbegin(), monitors_.cend(),
        [this, keyEvent, delay, &sessions](const auto &monitor) {
            if (!monitor.Want(keyEvent)) {
                return false;
            }
            if (CheckMeeTimeMonitor(keyEvent)) {
                NotifyMeeTimeMonitor(keyEvent);
                return true;
            }
            if (!monitor.IsFocused()) {
                return false;
            }
            if (pending_.find(monitor) != pending_.cend()) {
                return true;
            }
            if (sessions.find(monitor.session_) != sessions.cend()) {
                return false;
            }
            sessions.emplace(monitor.session_);
            auto tKeyEvent = KeyEvent::Clone(keyEvent);
            auto timerId = TimerMgr->AddTimer(delay, REPEAT_ONCE,
                [this, monitor, tKeyEvent]() {
                    pending_.erase(monitor);
                    NotifyKeyMonitor(tKeyEvent, monitor.session_, isMeeTimeSubcriber_);
                }, "KeyMonitorManager");
            if (timerId < 0) {
                MMI_HILOGE("AddTimer fail");
                return false;
            }
            pending_.emplace(monitor, PendingMonitor {
                .timerId_ = timerId,
                .keyEvent_ = tKeyEvent,
            });
            return true;
        });
    return (nTriggered > 0);
}

void KeyMonitorManager::NotifyPendingMonitors()
{
    for (const auto &[monitor, pendingData] : pending_) {
        TimerMgr->RemoveTimer(pendingData.timerId_);
        NotifyKeyMonitor(pendingData.keyEvent_, monitor.session_, isMeeTimeSubcriber_);
    };
    pending_.clear();
}

void KeyMonitorManager::ResetAll(int32_t keyCode)
{
    for (auto iter = pending_.cbegin(); iter != pending_.cend();) {
        if (iter->first.key_ != keyCode) {
            ++iter;
        } else {
            TimerMgr->RemoveTimer(iter->second.timerId_);
            iter = pending_.erase(iter);
        }
    }
}

void KeyMonitorManager::OnSessionLost(int32_t session)
{
    std::string name = BUNDLE_NAME_PARSER.GetBundleName(MEETIME_NAME);
    auto it = meeTimeMonitor_.find(name);
    if (it != meeTimeMonitor_.cend()) {
        int32_t value = it->second;
        if (value == session) {
            MMI_HILOGI("Session value:%{public}d", value);
            SetMeeTimeSubcriber(false, "SessionLost");
            meeTimeMonitor_.erase(name);
        }
    }

    for (auto mIter = monitors_.cbegin(); mIter != monitors_.cend();) {
        if (mIter->session_ == session) {
            mIter = monitors_.erase(mIter);
        } else {
            ++mIter;
        }
    }
}

bool KeyMonitorManager::CheckMonitor(const Monitor &monitor)
{
    CALL_DEBUG_ENTER;
    if (allowedKeys_.find(monitor.key_) == allowedKeys_.cend()) {
        MMI_HILOGE("Invalid pressKey [%{public}d]", monitor.key_);
        return false;
    }
    return (monitor.action_ == MonitorType::MONITOR_ACTION_ONLY_DOWN) ||
           (monitor.action_ == MonitorType::MONITOR_ACTION_DOWN_AND_UP);
}

void KeyMonitorManager::NotifyKeyMonitor(std::shared_ptr<KeyEvent> keyEvent,
    int32_t session, int32_t status)
{
    CALL_DEBUG_ENTER;
    NetPacket pkt(MmiMessageId::ON_SUBSCRIBE_KEY_MONITOR);
    InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt);
    pkt << status;
    CHKPV(keyEvent);
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Failed to package key event(No:%{public}d)", keyEvent->GetId());
        return;
    }
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    auto fd = udsServer->GetClientFd(session);
    if (!udsServer->SendMsg(fd, pkt)) {
        MMI_HILOGE("Failed to notify key monitor");
        return;
    }
    if (!EventLogHelper::IsBetaVersion()) {
        MMI_HILOGI("Notify key monitor(PID:%{public}d)", session);
    } else {
        if (EventLogHelper::IsBetaVersion() && !keyEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
            MMI_HILOGI("Notify key monitor(KC:%{private}d, KA:%{public}d, PID:%{public}d)",
                keyEvent->GetKeyCode(), keyEvent->GetKeyAction(), session);
        } else {
            MMI_HILOGI("Notify key monitor(KC:%{private}d, KA:%{public}d, PID:%{public}d)",
                keyEvent->GetKeyCode(), keyEvent->GetKeyAction(), session);
        }
    }
}

void KeyMonitorManager::SetMeeTimeSubcriber(bool status, std::string monitorType)
{
    CALL_INFO_TRACE;
    isMeeTimeSubcriber_ = status;
    auto manager = InputPluginManager::GetInstance();
    CHKPV(manager);
    MMI_HILOGI("Set flag, isMeeTimeSubcriber_:%{public}d, monitorType:%{public}s",
        static_cast<bool>(isMeeTimeSubcriber_), monitorType.c_str());
    manager->HandleMonitorStatus(status, monitorType);
}

bool KeyMonitorManager::CheckMeeTimeMonitor(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (keyEvent->GetKeyCode() != KeyEvent::KEYCODE_VOLUME_UP) {
        return false;
    }
    bool flag = keyEvent->HasFlag(InputEvent::EVENT_MEETIME);
    MMI_HILOGI("Check meetime monitor, flag:%{public}d, isMeeTimeSubcriber_:%{public}d",
        flag, static_cast<bool>(isMeeTimeSubcriber_));
    if (flag && isMeeTimeSubcriber_) {
        return true;
    }
    return false;
}
} // namespace MMI
} // namespace OHOS
