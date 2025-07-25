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

#include "event_pre_monitor_handler.h"

#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventPreMonitorHandler"

namespace OHOS {
namespace MMI {
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void EventPreMonitorHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    OnHandleEvent(keyEvent);
    CHKPV(nextHandler_);
    nextHandler_->HandleKeyEvent(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void EventPreMonitorHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    CHKPV(nextHandler_);
    nextHandler_->HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void EventPreMonitorHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    CHKPV(nextHandler_);
    nextHandler_->HandleTouchEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

int32_t EventPreMonitorHandler::AddInputHandler(
    SessionPtr session, int32_t handlerId, HandleEventType eventType, std::vector<int32_t> keys)
{
    CALL_INFO_TRACE;
    CHKPR(session, RET_ERR);
    if ((eventType & HANDLE_EVENT_TYPE_ALL) == HANDLE_EVENT_TYPE_NONE) {
        MMI_HILOGE("Invalid event type");
        return RET_ERR;
    }
    InitSessionLostCallback();
    auto mon = std::make_shared<SessionHandler>(session, handlerId, eventType, keys);
    return monitors_.AddMonitor(mon, keys);
}

void EventPreMonitorHandler::RemoveInputHandler(SessionPtr sess, int32_t handlerId)
{
    CALL_INFO_TRACE;
    monitors_.RemoveMonitor(sess, handlerId);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
bool EventPreMonitorHandler::OnHandleEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    MMI_HILOGD("Handle KeyEvent");
    CHKPF(keyEvent);
    auto keyHandler = InputHandler->GetEventNormalizeHandler();
    CHKPF(keyHandler);
    if (keyEvent->GetKeyCode() != keyHandler->GetCurrentHandleKeyCode()) {
        MMI_HILOGW("Keycode has been changed");
    }
    if (keyEvent->HasFlag(InputEvent::EVENT_FLAG_NO_MONITOR)) {
        MMI_HILOGD("This event has been tagged as not to be monitored");
    } else {
        if (monitors_.HandleEvent(keyEvent)) {
            MMI_HILOGD("Key event was consumed");
            return true;
        }
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

void EventPreMonitorHandler::InitSessionLostCallback()
{
    if (sessionLostCallbackInitialized_) {
        return;
    }
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    udsServerPtr->AddSessionDeletedCallback([this] (SessionPtr session) {
        return this->OnSessionLost(session);
    });
    sessionLostCallbackInitialized_ = true;
    MMI_HILOGD("The callback on session deleted is registered successfully");
}

void EventPreMonitorHandler::OnSessionLost(SessionPtr session)
{
    monitors_.OnSessionLost(session);
}

void EventPreMonitorHandler::SessionHandler::SendToClient(
    std::shared_ptr<KeyEvent> keyEvent, NetPacket &pkt, int32_t handlerId) const
{
    CHKPV(keyEvent);
    CHKPV(session_);
    pkt.Clean();
    if (InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt) != RET_OK) {
        MMI_HILOGE("Packet key event failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return;
    }
    int32_t fd = session_->GetFd();
    pkt << fd << handlerId;
    if (!session_->SendMsg(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
    }
}

int32_t EventPreMonitorHandler::MonitorCollection::AddMonitor(
    const std::shared_ptr<SessionHandler> monitor, std::vector<int32_t> keys)
{
    if (sessionHandlers_.size() >= MAX_N_INPUT_MONITORS) {
        MMI_HILOGE("The number of monitors exceeds the maximum:%{public}zu, monitors errCode:%{public}d",
            sessionHandlers_.size(),
            INVALID_MONITOR_MON);
        return RET_ERR;
    }
    for (auto &iter : sessionHandlers_) {
        if (IsEqualsKeys(keys, iter.first)) {
            iter.second.push_back(monitor);
            return RET_OK;
        }
    }
    sessionHandlers_[keys] = std::list<std::shared_ptr<SessionHandler>>();
    sessionHandlers_[keys].push_back(monitor);

    return RET_OK;
}

bool EventPreMonitorHandler::MonitorCollection::IsEqualsKeys(std::vector<int32_t> newKeys, std::vector<int32_t> oldKeys)
{
    if (newKeys.size() != oldKeys.size()) {
        MMI_HILOGE("The size of preKeys is not match");
        return false;
    }

    for (const auto &newKey : newKeys) {
        auto it = std::find(oldKeys.begin(), oldKeys.end(), newKey);
        if (it == oldKeys.end()) {
            MMI_HILOGE("Can't find the key");
            return false;
        }
    }

    return true;
}

void EventPreMonitorHandler::MonitorCollection::RemoveMonitor(SessionPtr sess, int32_t handlerId)
{
    for (auto iter = sessionHandlers_.begin(); iter != sessionHandlers_.end();) {
        auto &sessionHandlers = iter->second;
        for (auto it = sessionHandlers.begin(); it != sessionHandlers.end();) {
            CHKPC(*it);
            if ((*it)->handlerId_ == handlerId && (*it)->session_ == sess) {
                it = sessionHandlers.erase(it);
            } else {
                ++it;
            }
        }
        if (sessionHandlers.empty()) {
            iter = sessionHandlers_.erase(iter);
        } else {
            ++iter;
        }
    }
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
bool EventPreMonitorHandler::MonitorCollection::HandleEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    MMI_HILOGD("Handle KeyEvent");
    NetPacket pkt(MmiMessageId::ON_PRE_KEY_EVENT);
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write key event failed");
        return false;
    }
    for (auto iter = sessionHandlers_.begin(); iter != sessionHandlers_.end(); iter++) {
        auto &sessionHandlers = iter->second;
        for (auto it = sessionHandlers.begin(); it != sessionHandlers.end(); it++) {
            CHKPC(*it);
            auto keys = (*it)->keys_;
            auto keyIter = std::find(keys.begin(), keys.end(), keyEvent->GetKeyCode());
            if (keyIter != keys.end()) {
                (*it)->SendToClient(keyEvent, pkt, (*it)->handlerId_);
            }
        }
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
bool EventPreMonitorHandler::MonitorCollection::HandleEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    return false;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

void EventPreMonitorHandler::MonitorCollection::OnSessionLost(SessionPtr session)
{
    CALL_INFO_TRACE;
    for (auto iter = sessionHandlers_.begin(); iter != sessionHandlers_.end();) {
        auto &handlers = iter->second;
        for (auto inner = handlers.begin(); inner != handlers.end();) {
            auto handler = *inner;
            if (handler->session_ == session) {
                inner = handlers.erase(inner);
            } else {
                ++inner;
            }
        }
        if (handlers.empty()) {
            iter = sessionHandlers_.erase(iter);
        } else {
            ++iter;
        }
    }
}

void EventPreMonitorHandler::Dump(int32_t fd, const std::vector<std::string> &args)
{
    return monitors_.Dump(fd, args);
}

void EventPreMonitorHandler::MonitorCollection::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    mprintf(fd, "Monitor information:\t");
    mprintf(fd, "monitors: count=%zu", sessionHandlers_.size());
    for (const auto &item : sessionHandlers_) {
        const std::list<std::shared_ptr<SessionHandler>> &handlers = item.second;
        for (const auto &handler : handlers) {
            CHKPC(handler);
            SessionPtr session = handler->session_;
            if (!session) {
                continue;
            }
            mprintf(fd,
                "EventType:%d | Pid:%d | Uid:%d | Fd:%d "
                "| EarliestEventTime:%" PRId64 " | Descript:%s "
                "| ProgramName:%s \t",
                handler->eventType_, session->GetPid(),
                session->GetUid(), session->GetFd(),
                session->GetEarliestEventTime(), session->GetDescript().c_str(),
                session->GetProgramName().c_str());
        }
    }
}
} // namespace MMI
} // namespace OHOS
