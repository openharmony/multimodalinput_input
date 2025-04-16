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

#include "input_active_subscriber_handler.h"
#include <future>
#include <chrono>
#include <parameters.h>
#include "dfx_hisysevent.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputActiveSubscriberHandler"

namespace OHOS {
namespace MMI {
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void InputActiveSubscriberHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    CHKPV(nextHandler_);
    OnSubscribeInputActive(keyEvent);
    nextHandler_->HandleKeyEvent(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void InputActiveSubscriberHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    CHKPV(nextHandler_);
    OnSubscribeInputActive(pointerEvent);
    nextHandler_->HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void InputActiveSubscriberHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    CHKPV(nextHandler_);
    OnSubscribeInputActive(pointerEvent);
    nextHandler_->HandleTouchEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_SWITCH
void InputActiveSubscriberHandler::HandleSwitchEvent(const std::shared_ptr<SwitchEvent> switchEvent)
{
    CHKPV(switchEvent);
    CHKPV(nextHandler_);
    nextHandler_->HandleSwitchEvent(switchEvent);
}
#endif // OHOS_BUILD_ENABLE_SWITCH

int32_t InputActiveSubscriberHandler::SubscribeInputActive(SessionPtr sess, int32_t subscribeId, int64_t interval)
{
    CALL_INFO_TRACE;
    if (subscribeId < 0) {
        MMI_HILOGE("Invalid subscribeId");
        return RET_ERR;
    }
    CHKPR(sess, ERROR_NULL_POINTER);
    MMI_HILOGD("subscribeId: %{public}d interval: %{public}" PRId64, subscribeId, interval);
    auto subscriber = std::make_shared<Subscriber>(subscribeId, sess, interval);
    InsertSubscriber(subscriber);
    InitSessionDeleteCallback();
    return RET_OK;
}

int32_t InputActiveSubscriberHandler::UnsubscribeInputActive(SessionPtr sess, int32_t subscribeId)
{
    CALL_INFO_TRACE;
    MMI_HILOGD("subscribeId: %{public}d", subscribeId);
    std::lock_guard<std::mutex> guard(subscriberMutex_);
    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
        if ((*it) && (*it)->id_ == subscribeId && (*it)->sess_ == sess) {
            subscribers_.erase(it);
            return RET_OK;
        }
    }
    MMI_HILOGE("UnsubscribeInputActive failed with subscribeId(%{public}d)", subscribeId);
    return RET_ERR;
}

bool InputActiveSubscriberHandler::IsImmediateNotifySubscriber(
    std::shared_ptr<Subscriber> subscriber, int64_t eventTime)
{
    if (subscriber->interval_ <= 0) {
        return true;
    }
    if (subscriber->sendEventLastTime_ <= 0) {
        return true;
    }
    if (subscriber->sendEventLastTime_ > eventTime) {
        subscriber->sendEventLastTime_ = 0;
        return true;
    }
    if (eventTime - subscriber->sendEventLastTime_ >= subscriber->interval_) {
        return true;
    }
    return false;
}

void InputActiveSubscriberHandler::StartIntervalTimer(std::shared_ptr<Subscriber> subscriber, int64_t eventTime)
{
    if (subscriber->timerId_ >= 0) {
        return;
    }
    auto timerIntervalMs = subscriber->interval_ - (eventTime - subscriber->sendEventLastTime_);
    auto timerId = TimerMgr->AddTimer(timerIntervalMs, 1, [this, subscriber] {
        auto currentTime = GetMillisTime();
        if (subscriber->lastEventType_ == EVENTTYPE_KEY) {
            if (subscriber->keyEvent_) {
                NotifySubscriber(subscriber->keyEvent_, subscriber);
            } else {
                currentTime = 0;
                MMI_HILOGE("lastKeyEvent is null");
            }
        } else if (subscriber->lastEventType_ == EVENTTYPE_POINTER) {
            if (subscriber->pointerEvent_) {
                NotifySubscriber(subscriber->pointerEvent_, subscriber);
            } else {
                currentTime = 0;
                MMI_HILOGE("lastPointerEvent is null");
            }
        } else {
            currentTime = 0;
            MMI_HILOGE("lastEventType_ is invalid");
        }
        subscriber->timerId_ = INVALID_TIMERID;
        CleanSubscribeInfo(subscriber, currentTime);
    });
    if (timerId < 0) {
        MMI_HILOGE("AddTimer fail, setting will not work");
    } else {
        subscriber->timerId_ = timerId;
    }
}

void InputActiveSubscriberHandler::CleanSubscribeInfo(std::shared_ptr<Subscriber> subscriber, int64_t eventTime)
{
    if (subscriber->timerId_ >= 0) {
        TimerMgr->RemoveTimer(subscriber->timerId_);
        subscriber->timerId_ = INVALID_TIMERID;
    }
    subscriber->lastEventType_ = EVENTTYPE_INVALID;
    subscriber->keyEvent_ = nullptr;
    subscriber->pointerEvent_ = nullptr;
    subscriber->sendEventLastTime_ = eventTime;
}

void InputActiveSubscriberHandler::OnSubscribeInputActive(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    MMI_HILOGD("The Subscribe InputActive keycode: %{private}d", keyEvent->GetKeyCode());
    std::lock_guard<std::mutex> guard(subscriberMutex_);
    for (const auto &subscriber : subscribers_) {
        if (!subscriber) {
            MMI_HILOGE("subscriber is null");
            continue;
        }
        MMI_HILOGD("subscriber interval = %{public}" PRId64 ", id = %{public}d, pid = %{public}d",
            subscriber->interval_, subscriber->id_, subscriber->sess_ ? subscriber->sess_->GetPid() : -1);
        auto currentTime = GetMillisTime();
        if (IsImmediateNotifySubscriber(subscriber, currentTime)) {
            CleanSubscribeInfo(subscriber, currentTime);
            NotifySubscriber(keyEvent, subscriber);
        } else {
            subscriber->keyEvent_ = keyEvent;
            subscriber->lastEventType_ = EVENTTYPE_KEY;
            StartIntervalTimer(subscriber, currentTime);
        }
    }
}

void InputActiveSubscriberHandler::OnSubscribeInputActive(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    MMI_HILOGD("The Subscribe InputActive pointerId: %{private}d", pointerEvent->GetPointerId());
    std::lock_guard<std::mutex> guard(subscriberMutex_);
    for (const auto &subscriber : subscribers_) {
        if (!subscriber) {
            MMI_HILOGE("subscriber is null");
            continue;
        }
        MMI_HILOGD("subscriber interval = %{public}" PRId64 ", id = %{public}d, pid = %{public}d",
            subscriber->interval_, subscriber->id_, subscriber->sess_ ? subscriber->sess_->GetPid() : -1);
        auto currentTime = GetMillisTime();
        if (IsImmediateNotifySubscriber(subscriber, currentTime)) {
            CleanSubscribeInfo(subscriber, currentTime);
            NotifySubscriber(pointerEvent, subscriber);
        } else {
            subscriber->pointerEvent_ = pointerEvent;
            subscriber->lastEventType_ = EVENTTYPE_POINTER;
            StartIntervalTimer(subscriber, currentTime);
        }
    }
}

void InputActiveSubscriberHandler::InsertSubscriber(std::shared_ptr<Subscriber> subscriber)
{
    CALL_DEBUG_ENTER;
    CHKPV(subscriber);
    MMI_HILOGI("InsertSubscriber id = %{public}d", subscriber->id_);
    std::lock_guard<std::mutex> guard(subscriberMutex_);
    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
        if ((*it) && (*it)->id_ == subscriber->id_ && (*it)->sess_ == subscriber->sess_) {
            MMI_HILOGW("Repeat registration id: %{public}d, desc:%{public}s", subscriber->id_,
                subscriber->sess_ ? subscriber->sess_->GetDescript().c_str() : "invalid session");
            return;
        }
    }
    subscribers_.push_back(subscriber);
}

void InputActiveSubscriberHandler::OnSessionDelete(SessionPtr sess)
{
    CALL_DEBUG_ENTER;
    CHKPV(sess);
    std::lock_guard<std::mutex> guard(subscriberMutex_);
    for (auto it = subscribers_.begin(); it != subscribers_.end();) {
        if ((*it) && (*it)->sess_ == sess) {
            it = subscribers_.erase(it);
        } else {
            it++;
        }
    }
}

void InputActiveSubscriberHandler::NotifySubscriber(
    const std::shared_ptr<KeyEvent> keyEvent, const std::shared_ptr<Subscriber> subscriber)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    CHKPV(subscriber);
    CHKPV(InputHandler);
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    NetPacket pkt(MmiMessageId::ON_SUBSCRIBE_INPUT_ACTIVE);
    pkt << HANDLE_EVENT_TYPE_KEY;
    InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt);
    if (subscriber->sess_ == nullptr) {
        MMI_HILOGE("Subscriber's sess is null");
        return;
    }
    int32_t fd = subscriber->sess_->GetFd();
    pkt << fd << subscriber->id_;
    MMI_HILOGI("Notify subscriber id: %{public}d, keycode:%{private}d, pid: %{public}d",
        subscriber->id_, keyEvent->GetKeyCode(), subscriber->sess_->GetPid());
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write dispatch subscriber failed");
        return;
    }
    if (!udsServerPtr->SendMsg(fd, pkt)) {
        MMI_HILOGE("Leave, server dispatch subscriber failed");
    }
}

void InputActiveSubscriberHandler::NotifySubscriber(
    const std::shared_ptr<PointerEvent> pointerEvent, const std::shared_ptr<Subscriber> subscriber)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    CHKPV(subscriber);
    CHKPV(InputHandler);
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    NetPacket pkt(MmiMessageId::ON_SUBSCRIBE_INPUT_ACTIVE);
    pkt << HANDLE_EVENT_TYPE_POINTER;
    InputEventDataTransformation::Marshalling(pointerEvent, pkt);
    if (subscriber->sess_ == nullptr) {
        MMI_HILOGE("Subscriber's sess is null");
        return;
    }
    int32_t fd = subscriber->sess_->GetFd();
    pkt << subscriber->id_;
    MMI_HILOGI("Notify subscriber id: %{public}d, pointerId:%{private}d, pid: %{public}d",
        subscriber->id_, pointerEvent->GetPointerId(), subscriber->sess_->GetPid());
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write dispatch subscriber failed");
        return;
    }
    if (!udsServerPtr->SendMsg(fd, pkt)) {
        MMI_HILOGE("Leave, server dispatch subscriber failed");
    }
}

bool InputActiveSubscriberHandler::InitSessionDeleteCallback()
{
    CALL_DEBUG_ENTER;
    if (callbackInitialized_) {
        MMI_HILOGD("Session delete callback has already been initialized");
        return true;
    }
    CHKPF(InputHandler);
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPF(udsServerPtr);
    std::function<void(SessionPtr)> callback =
        [this] (SessionPtr sess) { return this->OnSessionDelete(sess); };
    udsServerPtr->AddSessionDeletedCallback(callback);
    callbackInitialized_ = true;
    return true;
}

void InputActiveSubscriberHandler::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    mprintf(fd, "Subscriber information:\t");
    mprintf(fd, "subscribers: count = %zu", subscribers_.size());
    std::lock_guard<std::mutex> guard(subscriberMutex_);
    for (const auto& subscriber : subscribers_) {
        if (subscriber == nullptr) {
            continue;
        }
        SessionPtr session = subscriber->sess_;
        if (session == nullptr) {
            continue;
        }
        mprintf(fd, "subscriber id:%d | Pid:%d | Uid:%d | Fd:%d\t", subscriber->id_,
            session->GetPid(), session->GetUid(), session->GetFd());
    }
}
} // namespace MMI
} // namespace OHOS