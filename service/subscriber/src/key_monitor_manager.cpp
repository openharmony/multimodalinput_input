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

#include "define_multimodal.h"
#include "event_log_helper.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "key_auto_repeat.h"
#include "timer_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyMonitorManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t REPEAT_ONCE { 1 };
}

std::mutex KeyMonitorManager::mutex_;
std::shared_ptr<KeyMonitorManager> KeyMonitorManager::instance_;

const std::set<int32_t> KeyMonitorManager::allowedKeys_ {
    KeyEvent::KEYCODE_VOLUME_DOWN,
    KeyEvent::KEYCODE_VOLUME_UP,
};

std::shared_ptr<KeyMonitorManager> KeyMonitorManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<KeyMonitorManager>();
        }
    }
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
    return ((key_ == keyEvent->GetKeyCode()) &&
            (action_ == keyEvent->GetKeyAction()) &&
            (isRepeat_ ||
             (keyEvent->GetKeyAction() != KeyEvent::KEY_ACTION_DOWN) ||
             (keyEvent->GetKeyCode() != KeyRepeat->GetRepeatKeyCode())));
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

int32_t KeyMonitorManager::AddMonitor(const Monitor &monitor)
{
    MMI_HILOGI("Add key monitor(%{public}s)", monitor.Dump().c_str());
    if (!CheckMonitor(monitor)) {
        MMI_HILOGE("Invalid monitor(%{public}s)", monitor.Dump().c_str());
        return KEY_MONITOR_ERROR_INVALID_MONITOR;
    }
    auto [_, isNew] = monitors_.emplace(monitor);
    if (!isNew) {
        MMI_HILOGW("Duplicate registration of monitor(%{public}s)", monitor.Dump().c_str());
    }
    return RET_OK;
}

void KeyMonitorManager::RemoveMonitor(const Monitor &monitor)
{
    MMI_HILOGI("Remove key monitor(%{public}s)", monitor.Dump().c_str());
    auto iter = monitors_.find(monitor);
    if (iter == monitors_.cend()) {
        MMI_HILOGW("No key monitor(%{public}s)", monitor.Dump().c_str());
        return;
    }
    monitors_.erase(iter);
}

bool KeyMonitorManager::Intercept(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    std::set<int32_t> sessions;

    auto nTriggered = std::count_if(monitors_.cbegin(), monitors_.cend(),
        [this, keyEvent, &sessions](const auto &monitor) {
            if (monitor.Want(keyEvent) &&
                monitor.IsFocused() &&
                (sessions.find(monitor.session_) == sessions.cend())) {
                sessions.emplace(monitor.session_);
                NotifyKeyMonitor(keyEvent, monitor.session_);
                return true;
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
                    NotifyKeyMonitor(tKeyEvent, monitor.session_);
                });
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
        NotifyKeyMonitor(pendingData.keyEvent_, monitor.session_);
    };
    pending_.clear();
}

void KeyMonitorManager::ResetAll()
{
    std::for_each(pending_.cbegin(), pending_.cbegin(), [](const auto &item) {
        TimerMgr->RemoveTimer(item.second.timerId_);
    });
    pending_.clear();
}

void KeyMonitorManager::OnSessionLost(int32_t session)
{
    MMI_HILOGI("Session(%{public}d) is lost", session);
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
    return (allowedKeys_.find(monitor.key_) != allowedKeys_.cend());
}

void KeyMonitorManager::NotifyKeyMonitor(std::shared_ptr<KeyEvent> keyEvent, int32_t session)
{
    CALL_DEBUG_ENTER;
    NetPacket pkt(MmiMessageId::ON_SUBSCRIBE_KEY_MONITOR);
    InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt);
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Failed to package key event(No:%{public}d)", keyEvent->GetId());
        return;
    }
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    auto fd = udsServer->GetClientFd(session);
    if (!udsServer->SendMsg(fd, pkt)) {
        MMI_HILOGE("Failed to nitofy key monitor");
        return;
    }
    if (!EventLogHelper::IsBetaVersion()) {
        MMI_HILOGI("Notify key monitor(PID:%{public}d)", session);
    } else {
        if (EventLogHelper::IsBetaVersion() && !keyEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
            MMI_HILOGI("Notify key monitor(KC:%d, KA:%{public}d, PID:%{public}d)",
                keyEvent->GetKeyCode(), keyEvent->GetKeyAction(), session);
        } else {
            MMI_HILOGI("Notify key monitor(KC:%{private}d, KA:%{public}d, PID:%{public}d)",
                keyEvent->GetKeyCode(), keyEvent->GetKeyAction(), session);
        }
    }
}
} // namespace MMI
} // namespace OHOS
