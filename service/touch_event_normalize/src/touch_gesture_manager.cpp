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

#include "touch_gesture_manager.h"

#include "key_command_handler_util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchGestureManager"

namespace OHOS {
namespace MMI {
namespace {
const char* TOUCH_GESTURE_RECOGNIZER_NAME { "touchGesture" };
}

TouchGestureManager::TouchGestureManager(std::shared_ptr<DelegateInterface> delegate)
    : delegate_(delegate)
{
    touchGesture_ = TouchGestureAdapter::GetGestureFactory();
    SetupSessionObserver();
}

TouchGestureManager::~TouchGestureManager()
{
    RemoveAllHandlers();
}

void TouchGestureManager::AddHandler(int32_t session, TouchGestureType gestureType, int32_t nFingers)
{
    if (!GestureMonitorHandler::CheckMonitorValid(gestureType, nFingers)) {
        MMI_HILOGE("Unsupported touch gesture (GestureType:%{public}d, FingerNo:%{public}d)",
            static_cast<int32_t>(gestureType), nFingers);
        return;
    }
    Handler handler {
        .session_ = session,
        .gesture_ = gestureType,
        .nFingers_ = nFingers,
    };
    if (handlers_.find(handler) != handlers_.cend()) {
        return;
    }
    MMI_HILOGI("Start monitoring touch gesture(Session:%{public}d, Gesture:%{public}u, nFingers:%{public}d)",
        session, gestureType, nFingers);
    StartRecognization(gestureType, nFingers);
    handlers_.emplace(handler);
}

void TouchGestureManager::RemoveHandler(int32_t session, TouchGestureType gestureType, int32_t nFingers)
{
    Handler handler {
        .session_ = session,
        .gesture_ = gestureType,
        .nFingers_ = nFingers,
    };
    auto iter = handlers_.find(handler);
    if (iter == handlers_.cend()) {
        return;
    }
    handlers_.erase(iter);
    MMI_HILOGI("Stop monitoring touch gesture(Session:%{public}d, Gesture:%{public}u, nFingers:%{public}d)",
        session, gestureType, nFingers);
    StopRecognization(gestureType, nFingers);
}

void TouchGestureManager::HandleGestureWindowEmerged(int32_t windowId, std::shared_ptr<PointerEvent> lastTouchEvent)
{
    CHKPV(touchGesture_);
    touchGesture_->HandleGestureWindowEmerged(windowId, lastTouchEvent);
}

void TouchGestureManager::StartRecognization(TouchGestureType gestureType, int32_t nFingers)
{
    auto iter = std::find_if(handlers_.cbegin(), handlers_.cend(),
        [gestureType, nFingers](const auto &handler) {
            return ((handler.gesture_ == gestureType) && (handler.nFingers_ == nFingers));
        });
    if (iter != handlers_.cend()) {
        return;
    }
    MMI_HILOGI("Start recognizing touch gesture(Gesture:%{public}u, nFingers:%{public}d)", gestureType, nFingers);
    CHKPV(touchGesture_);
    touchGesture_->SetGestureCondition(true, gestureType, nFingers);

    auto delegate = delegate_.lock();
    CHKPV(delegate);
    if (delegate->HasHandler(TOUCH_GESTURE_RECOGNIZER_NAME)) {
        return;
    }
    MMI_HILOGI("Start touch gesture recognization");
    auto callback = [touchGesture = touchGesture_](std::shared_ptr<PointerEvent> event) -> int32_t {
        CHKPR(touchGesture, ERROR_NULL_POINTER);
        touchGesture->process(event);
        return RET_OK;
    };
    auto ret = delegate->AddHandler(
        InputHandlerType::MONITOR,
        DelegateInterface::HandlerSummary {
            .handlerName = TOUCH_GESTURE_RECOGNIZER_NAME,
            .eventType = HANDLE_EVENT_TYPE_POINTER,
            .mode = HandlerMode::SYNC,
            .cb = callback,
        });
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to add gesture recognizer, ret:%{public}d", ret);
    }
}

void TouchGestureManager::StopRecognization(TouchGestureType gestureType, int32_t nFingers)
{
    auto iter = std::find_if(handlers_.cbegin(), handlers_.cend(),
        [gestureType, nFingers](const auto &handler) {
            return ((handler.gesture_ == gestureType) && (handler.nFingers_ == nFingers));
        });
    if (iter != handlers_.cend()) {
        return;
    }
    MMI_HILOGI("Stop recognizing touch gesture(Gesture:%{public}u, nFingers:%{public}d)", gestureType, nFingers);
    CHKPV(touchGesture_);
    touchGesture_->SetGestureCondition(false, gestureType, nFingers);

    if (!handlers_.empty()) {
        return;
    }
    MMI_HILOGI("Stop touch gesture recognization");
    auto delegate = delegate_.lock();
    CHKPV(delegate);
    delegate->RemoveHandler(InputHandlerType::MONITOR, TOUCH_GESTURE_RECOGNIZER_NAME);
}

void TouchGestureManager::RemoveAllHandlers()
{
    for (auto iter = handlers_.cbegin(); iter != handlers_.cend(); iter = handlers_.cbegin()) {
        RemoveHandler(iter->session_, iter->gesture_, iter->nFingers_);
    }
}

void TouchGestureManager::SetupSessionObserver()
{
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    udsServerPtr->AddSessionDeletedCallback([this](SessionPtr session) {
        CHKPV(session);
        OnSessionLost(session->GetPid());
    });
}

void TouchGestureManager::OnSessionLost(int32_t session)
{
    MMI_HILOGI("Clear handlers related to lost session(%{public}d)", session);
    std::set<Handler> handlers;

    std::for_each(handlers_.cbegin(), handlers_.cend(),
        [session, &handlers](const auto &handler) {
            if (handler.session_ == session) {
                handlers.emplace(handler);
            }
        });
    std::for_each(handlers.cbegin(), handlers.cend(),
        [this](const auto &handler) {
            MMI_HILOGI("Remove handler(%{public}u, %{public}d) related to lost session(%{public}d)",
                handler.gesture_, handler.nFingers_, handler.session_);
            RemoveHandler(handler.session_, handler.gesture_, handler.nFingers_);
        });
}
} // namespace MMI
} // namespace OHOS