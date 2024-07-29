/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef EVENT_INTERCEPTOR_HANDLER_H
#define EVENT_INTERCEPTOR_HANDLER_H

#include <set>

#include "nocopyable.h"

#include "i_input_event_handler.h"
#include "i_input_event_collection_handler.h"
#include "input_device.h"
#include "input_handler_type.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
class EventInterceptorHandler : public IInputEventHandler {
public:
    EventInterceptorHandler() = default;
    DISALLOW_COPY_AND_MOVE(EventInterceptorHandler);
    ~EventInterceptorHandler() = default;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_TOUCH
    int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags, SessionPtr session);
    void RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags, SessionPtr session);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    bool OnHandleEvent(std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool OnHandleEvent(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    void Dump(int32_t fd, const std::vector<std::string> &args);
    static bool CheckInputDeviceSource(
        const std::shared_ptr<PointerEvent> pointerEvent, uint32_t deviceTags);

private:
    void InitSessionLostCallback();
    void OnSessionLost(SessionPtr session);

private:
    class SessionHandler {
    public:
        SessionHandler(InputHandlerType handlerType, HandleEventType eventType, int32_t priority,
            uint32_t deviceTags, SessionPtr session) : handlerType_(handlerType),
            eventType_(eventType & HANDLE_EVENT_TYPE_ALL), priority_(priority), deviceTags_(deviceTags),
            session_(session) {}
        void SendToClient(std::shared_ptr<KeyEvent> keyEvent) const;
        void SendToClient(std::shared_ptr<PointerEvent> pointerEvent) const;
        InputHandlerType handlerType_ { NONE };
        HandleEventType eventType_ { HANDLE_EVENT_TYPE_ALL };
        int32_t priority_ { DEFUALT_INTERCEPTOR_PRIORITY };
        uint32_t deviceTags_ { CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX) };
        SessionPtr session_ { nullptr };
    };

    class InterceptorCollection final : public IInputEventCollectionHandler, protected NoCopyable {
    public:
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
        bool HandleEvent(std::shared_ptr<KeyEvent> keyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
        bool HandleEvent(std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
        int32_t AddInterceptor(const SessionHandler& interceptor);
        void RemoveInterceptor(const SessionHandler& interceptor);
        void OnSessionLost(SessionPtr session);
        void Dump(int32_t fd, const std::vector<std::string> &args);
        std::list<SessionHandler> interceptors_;
    };

private:
    bool sessionLostCallbackInitialized_ { false };
    InterceptorCollection interceptors_;
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_INTERCEPTOR_HANDLER_H