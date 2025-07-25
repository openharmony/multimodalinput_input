/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "dfx_hisysevent.h"
#include "event_dispatch_handler.h"
#include "input_device_manager.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "mmi_log.h"
#include "net_packet.h"
#include "proto.h"
#include "util_ex.h"
#include "init_param.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventInterceptorHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ACCESSIBILITY_UID { 1103 };

const std::string DEFAULT_KEYEVENT_INTERCEPT_WHITELIST = "2722;41;40;0;22;17;16;23;2841;9;2089;2083;";
} // namespace

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void EventInterceptorHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    if (TouchPadKnuckleDoubleClickHandle(keyEvent)) {
        return;
    }
    bool isIntercept = this->KeyInterceptByHostOSWhiteList(keyEvent->GetKeyCode());
    if (!isIntercept && OnHandleEvent(keyEvent)) {
        MMI_HILOGD("KeyEvent filter find a keyEvent from Original event key code:%{private}d",
            keyEvent->GetKeyCode());
        BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::KEY_INTERCEPT_EVENT);
        DfxHisysevent::ReportKeyEvent("intercept");
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleKeyEvent(keyEvent);
}

bool EventInterceptorHandler::KeyInterceptByHostOSWhiteList(int32_t keyCode)
{
    if (keyevent_intercept_whitelist != nullptr && keyevent_intercept_whitelist->empty()) {
        return false;
    }
    if (keyevent_intercept_whitelist == nullptr) {
        uint32_t size = 0;
        int ret = SystemReadParam("const.multimodalinput.keyevent_intercept_whitelist", nullptr, &size);
        std::string intercept_whitelist = "";
        if (ret == 0) {
            std::vector<char> value(size + 1);
            ret = SystemReadParam("const.multimodalinput.keyevent_intercept_whitelist", value.data(), &size);
            if (ret == 0) {
                intercept_whitelist = std::string(value.data());
            } else {
                intercept_whitelist = DEFAULT_KEYEVENT_INTERCEPT_WHITELIST;
            }
        }
        keyevent_intercept_whitelist = std::make_unique<std::string>(intercept_whitelist);
    }
    std::string keyString = std::to_string(keyCode);
    keyString += ";";
    bool isIntercept = keyevent_intercept_whitelist->find(keyString) != std::string::npos;
    MMI_HILOGD("Received key event is %{private}d isIntercept is %{public}d", keyCode, isIntercept);
    return isIntercept;
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
    MMI_HILOGD("The handlerType:%{public}d, eventType:%{public}d, deviceTags:%{public}d, priority:%{public}d",
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
        MMI_HILOGD("The handlerType:%{public}d, eventType:%{public}d, deviceTags:%{public}d, priority:%{public}d",
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
    if (sessionLostCallbackInitialized_) {
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

bool EventInterceptorHandler::CheckInputDeviceSource(
    const std::shared_ptr<PointerEvent> pointerEvent, uint32_t deviceTags)
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

void EventInterceptorHandler::SessionHandler::SendToClient(std::shared_ptr<KeyEvent> keyEvent) const
{
    CHKPV(keyEvent);
    CHKPV(session_);
    if (session_->GetUid() == ACCESSIBILITY_UID) {
        keyEvent->AddFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    }
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
    CHKPV(session_);
    if (session_->GetUid() == ACCESSIBILITY_UID) {
        pointerEvent->AddFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    }
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
        DfxHisysevent::ReportFailHandleKey("InterceptorCollection::HandleEvent", keyEvent->GetKeyCode(),
            DfxHisysevent::KEY_ERROR_CODE::INVALID_PARAMETER);
        return false;
    }
    std::shared_ptr<InputDevice> inputDevice = INPUT_DEV_MGR->GetInputDevice(keyItems.front().GetDeviceId());
    CHKPF(inputDevice);
    uint32_t capKeyboard = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    for (const auto &interceptor : interceptors_) {
        MMI_HILOGD("The eventType:%{public}d, deviceTags:%{public}d",
            interceptor.eventType_, interceptor.deviceTags_);
        if ((capKeyboard & interceptor.deviceTags_) == 0) {
            MMI_HILOGD("Interceptor cap does not have keyboard");
            continue;
        }
        if (!inputDevice->HasCapability(interceptor.deviceTags_)) {
            continue;
        }
        auto session = interceptor.session_;
        if (session != nullptr) {
            int32_t tokenType = session->GetTokenType();
            int32_t pid = session->GetPid();
            if (tokenType == TokenType::TOKEN_HAP && !IInputWindowsManager::GetInstance()->CheckAppFocused(pid)) {
                MMI_HILOGD("Token hap is not focus, no need interceptor key");
                continue;
            }
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
        MMI_HILOGD("The eventType:%{public}d, deviceTags:%{public}d",
            interceptor.eventType_, interceptor.deviceTags_);
        if (((capPointer | capTouch) & interceptor.deviceTags_) == 0) {
            MMI_HILOGD("Interceptor cap does not have pointer or touch");
            continue;
        }
        if (!EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, interceptor.deviceTags_)) {
            continue;
        }
#ifndef OHOS_BUILD_EMULATOR
        if (!inputDevice->HasCapability(interceptor.deviceTags_)) {
            continue;
        }
#endif // OHOS_BUILD_EMULATOR
        auto session = interceptor.session_;
        if (session != nullptr) {
            int32_t tokenType = session->GetTokenType();
            if ((tokenType == TokenType::TOKEN_HAP) &&
                (IInputWindowsManager::GetInstance()->GetWindowPid(pointerEvent->GetTargetWindowId()) !=
                session->GetPid())) {
                MMI_HILOGD("Token hap is not hit, no need interceptor pointer");
                continue;
            }
        }
        if ((interceptor.eventType_ & HANDLE_EVENT_TYPE_POINTER) == HANDLE_EVENT_TYPE_POINTER) {
            interceptor.SendToClient(pointerEvent);
            if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP ||
                pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP) {
                    MMI_HILOGI("Action:%{public}d event was intercepted", pointerEvent->GetPointerAction());
            }
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

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
bool EventInterceptorHandler::TouchPadKnuckleDoubleClickHandle(std::shared_ptr<KeyEvent> event)
{
    CHKPF(event);
    CHKPF(nextHandler_);
    if (event->GetKeyAction() != KNUCKLE_1F_DOUBLE_CLICK &&
        event->GetKeyAction() != KNUCKLE_2F_DOUBLE_CLICK) {
        return false;
    }
    MMI_HILOGI("Current is touchPad knuckle double click action");
    nextHandler_->HandleKeyEvent(event);
    return true;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD
} // namespace MMI
} // namespace OHOS
