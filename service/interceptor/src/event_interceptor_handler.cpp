/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "event_interceptor_handler.h"

#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "event_dispatch_handler.h"
#include "input_device_manager.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "mmi_log.h"
#include "net_packet.h"
#include "proto.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventInterceptorHandler"

namespace OHOS {
namespace MMI {
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void EventInterceptorHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    if (OnHandleEvent(keyEvent)) {
        MMI_HILOGD("KeyEvent filter find a keyEvent from Original event keyCode:%{public}d",
            keyEvent->GetKeyCode());
        BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::KEY_INTERCEPT_EVENT);
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleKeyEvent(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void EventInterceptorHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (OnHandleEvent(pointerEvent)) {
        BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP);
        MMI_HILOGD("Interception is succeeded");
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void EventInterceptorHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (OnHandleEvent(pointerEvent)) {
        BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP);
        MMI_HILOGD("Interception is succeeded");
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleTouchEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

int32_t EventInterceptorHandler::AddInputHandler(InputHandlerType handlerType,
    HandleEventType eventType, int32_t priority, uint32_t deviceTags, SessionPtr session)
{
    CALL_INFO_TRACE;
    CHKPR(session, RET_ERR);
    if ((eventType & HANDLE_EVENT_TYPE_ALL) == HANDLE_EVENT_TYPE_NONE) {
        MMI_HILOGE("Invalid event type");
        return RET_ERR;
    }
    InitSessionLostCallback();
    SessionHandler interceptor { handlerType, eventType, priority, deviceTags, session };
    MMI_HILOGD("handlerType:%{public}d, eventType:%{public}d, deviceTags:%{public}d, priority:%{public}d",
        handlerType, eventType, deviceTags, priority);
    return interceptors_.AddInterceptor(interceptor);
}

void EventInterceptorHandler::RemoveInputHandler(InputHandlerType handlerType,
    HandleEventType eventType, int32_t priority, uint32_t deviceTags, SessionPtr session)
{
    CALL_INFO_TRACE;
    CHKPV(session);
    if (handlerType == InputHandlerType::INTERCEPTOR) {
        SessionHandler interceptor { handlerType, eventType, priority, deviceTags, session };
        MMI_HILOGD("handlerType:%{public}d, eventType:%{public}d, deviceTags:%{public}d, priority:%{public}d",
            handlerType, eventType, deviceTags, priority);
        interceptors_.RemoveInterceptor(interceptor);
    }
}
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
bool EventInterceptorHandler::OnHandleEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    MMI_HILOGD("Handle KeyEvent");
    CHKPF(keyEvent);
    if (keyEvent->HasFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT)) {
        MMI_HILOGW("This event has been tagged as not to be intercepted");
        return false;
    }
    return interceptors_.HandleEvent(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
bool EventInterceptorHandler::OnHandleEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (pointerEvent->HasFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT)) {
        MMI_HILOGW("This event has been tagged as not to be intercepted");
        return false;
    }
    return interceptors_.HandleEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

void EventInterceptorHandler::InitSessionLostCallback()
{
    if (sessionLostCallbackInitialized_)  {
        MMI_HILOGE("Init session is failed");
        return;
    }
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    udsServerPtr->AddSessionDeletedCallback([this] (SessionPtr session) { this->OnSessionLost(session); });
    sessionLostCallbackInitialized_ = true;
    MMI_HILOGD("The callback on session deleted is registered successfully");
}

void EventInterceptorHandler::OnSessionLost(SessionPtr session)
{
    interceptors_.OnSessionLost(session);
}

void EventInterceptorHandler::SessionHandler::SendToClient(std::shared_ptr<KeyEvent> keyEvent) const
{
    CHKPV(keyEvent);
    NetPacket pkt(MmiMessageId::REPORT_KEY_EVENT);
    pkt << handlerType_ << deviceTags_;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write key event failed");
        return;
    }
    if (InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt) != RET_OK) {
        MMI_HILOGE("Packet key event failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return;
    }
    if (!session_->SendMsg(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}

void EventInterceptorHandler::SessionHandler::SendToClient(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPV(pointerEvent);
    NetPacket pkt(MmiMessageId::REPORT_POINTER_EVENT);
    MMI_HILOGD("Service send to client InputHandlerType:%{public}d", handlerType_);
    pkt << handlerType_ << deviceTags_;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write pointer event failed");
        return;
    }
    if (InputEventDataTransformation::Marshalling(pointerEvent, pkt) != RET_OK) {
        MMI_HILOGE("Marshalling pointer event failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return;
    }
    if (!session_->SendMsg(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
bool EventInterceptorHandler::InterceptorCollection::HandleEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    if (interceptors_.empty()) {
        MMI_HILOGD("Key interceptors is empty");
        return false;
    }
    MMI_HILOGD("There are currently:%{public}zu interceptors", interceptors_.size());
    bool isInterceptor = false;
    std::vector<KeyEvent::KeyItem> keyItems = keyEvent->GetKeyItems();
    if (keyItems.empty()) {
        MMI_HILOGE("keyItems is empty");
        return false;
    }
    std::shared_ptr<InputDevice> inputDevice = INPUT_DEV_MGR->GetInputDevice(keyItems.front().GetDeviceId());
    CHKPF(inputDevice);
    uint32_t capKeyboard = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    for (const auto &interceptor : interceptors_) {
        MMI_HILOGD("eventType:%{public}d, deviceTags:%{public}d",
            interceptor.eventType_, interceptor.deviceTags_);
        if ((capKeyboard & interceptor.deviceTags_) == 0) {
            MMI_HILOGD("Interceptor cap does not have keyboard");
            continue;
        }
        if (!inputDevice->HasCapability(interceptor.deviceTags_)) {
            continue;
        }
        if ((interceptor.eventType_ & HANDLE_EVENT_TYPE_KEY) == HANDLE_EVENT_TYPE_KEY) {
            interceptor.SendToClient(keyEvent);
            MMI_HILOGD("Key event was intercepted");
            isInterceptor = true;
            break;
        }
    }
    return isInterceptor;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

bool EventInterceptorHandler::InterceptorCollection::CheckInputDeviceSource(
    const std::shared_ptr<PointerEvent> pointerEvent, uint32_t deviceTags) const
{
    if ((pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) &&
        ((deviceTags & CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TOUCH)) ||
        (deviceTags & CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TABLET_TOOL)))) {
        return true;
    } else if ((pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) &&
        (deviceTags & CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_POINTER))) {
        return true;
    } else if ((pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHPAD) &&
        (deviceTags & CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_POINTER))) {
        return true;
    }
    return false;
}

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
bool EventInterceptorHandler::InterceptorCollection::HandleEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (interceptors_.empty()) {
        MMI_HILOGD("Interceptors are empty");
        return false;
    }
    MMI_HILOGD("There are currently:%{public}zu interceptors", interceptors_.size());
    bool isInterceptor = false;
    PointerEvent::PointerItem pointerItem;
    int32_t pointerId = pointerEvent->GetPointerId();
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("GetPointerItem:%{public}d fail", pointerId);
        return false;
    }
    std::shared_ptr<InputDevice> inputDevice = INPUT_DEV_MGR->GetInputDevice(pointerItem.GetDeviceId(), false);
    CHKPF(inputDevice);
    uint32_t capPointer = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    uint32_t capTouch = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TOUCH);
    for (const auto &interceptor : interceptors_) {
        MMI_HILOGD("eventType:%{public}d, deviceTags:%{public}d",
            interceptor.eventType_, interceptor.deviceTags_);
        if (((capPointer | capTouch) & interceptor.deviceTags_) == 0) {
            MMI_HILOGD("Interceptor cap does not have pointer or touch");
            continue;
        }
        if (!CheckInputDeviceSource(pointerEvent, interceptor.deviceTags_)) {
            continue;
        }
#ifndef OHOS_BUILD_EMULATOR
        if (!inputDevice->HasCapability(interceptor.deviceTags_)) {
            continue;
        }
#endif // OHOS_BUILD_EMULATOR
        if ((interceptor.eventType_ & HANDLE_EVENT_TYPE_POINTER) == HANDLE_EVENT_TYPE_POINTER) {
            interceptor.SendToClient(pointerEvent);
            MMI_HILOGD("Pointer event was intercepted");
            isInterceptor = true;
            break;
        }
    }
    return isInterceptor;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

int32_t EventInterceptorHandler::InterceptorCollection::AddInterceptor(const SessionHandler& interceptor)
{
    for (auto iter = interceptors_.begin(); iter != interceptors_.end(); ++iter) {
        if (iter->session_ == interceptor.session_) {
            interceptors_.erase(iter);
            break;
        }
    }

    if (interceptors_.size() >= MAX_N_INPUT_INTERCEPTORS) {
        MMI_HILOGE("The number of interceptors exceeds limit");
        return RET_ERR;
    }

    auto iterIndex = interceptors_.cbegin();
    for (; iterIndex != interceptors_.cend(); ++iterIndex) {
        if (interceptor.priority_ < iterIndex->priority_) {
            break;
        }
    }
    auto sIter = interceptors_.emplace(iterIndex, interceptor);
    if (sIter == interceptors_.end()) {
        MMI_HILOGE("Failed to add interceptor");
        return RET_ERR;
    }
    return RET_OK;
}

void EventInterceptorHandler::InterceptorCollection::RemoveInterceptor(const SessionHandler& interceptor)
{
    for (auto iter = interceptors_.begin(); iter != interceptors_.end(); ++iter) {
        if (iter->session_ == interceptor.session_) {
            interceptors_.erase(iter);
            break;
        }
    }
    if (interceptor.eventType_ == HANDLE_EVENT_TYPE_NONE) {
        MMI_HILOGD("Unregister interceptor successfully");
        return;
    }

    auto iterIndex = interceptors_.cbegin();
    for (; iterIndex != interceptors_.cend(); ++iterIndex) {
        if (interceptor.priority_ < iterIndex->priority_) {
            break;
        }
    }
    auto sIter = interceptors_.emplace(iterIndex, interceptor);
    if (sIter == interceptors_.end()) {
        MMI_HILOGE("Internal error, interceptor has been removed");
        return;
    }
    MMI_HILOGD("Event type is updated:%{public}u", interceptor.eventType_);
}

void EventInterceptorHandler::InterceptorCollection::OnSessionLost(SessionPtr session)
{
    CALL_INFO_TRACE;
    auto iter = interceptors_.cbegin();
    while (iter != interceptors_.cend()) {
        if (iter->session_ != session) {
            ++iter;
        } else {
            iter = interceptors_.erase(iter);
        }
    }
}

void EventInterceptorHandler::Dump(int32_t fd, const std::vector<std::string> &args)
{
    return interceptors_.Dump(fd, args);
}

void EventInterceptorHandler::InterceptorCollection::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    mprintf(fd, "Interceptor information:\t");
    mprintf(fd, "interceptors: count=%zu", interceptors_.size());
    for (const auto &item : interceptors_) {
        SessionPtr session = item.session_;
        CHKPV(session);
        mprintf(fd,
                "handlerType:%d | eventType:%u | Pid:%d | Uid:%d | Fd:%d "
                "| EarliestEventTime:%" PRId64 " | Descript:%s | ProgramName:%s \t",
                item.handlerType_, item.eventType_,
                session->GetPid(), session->GetUid(),
                session->GetFd(),
                session->GetEarliestEventTime(), session->GetDescript().c_str(),
                session->GetProgramName().c_str());
    }
}
} // namespace MMI
} // namespace OHOS
