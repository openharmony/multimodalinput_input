/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef EVENT_MONITOR_HANDLER_H
#define EVENT_MONITOR_HANDLER_H

#include <mutex>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "nocopyable.h"

#include "i_input_event_collection_handler.h"
#include "i_input_event_handler.h"
#include "input_handler_type.h"
#include "uds_session.h"
#include "nap_process.h"
#ifdef PLAYER_FRAMEWORK_EXISTS
#include "input_screen_capture_monitor_listener.h"
#endif

namespace OHOS {
namespace MMI {
class EventMonitorHandler final : public IInputEventHandler {
public:
    EventMonitorHandler() = default;
    DISALLOW_COPY_AND_MOVE(EventMonitorHandler);
    ~EventMonitorHandler() override = default;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_TOUCH
    int32_t AddInputHandler(InputHandlerType handlerType,
        HandleEventType eventType, std::shared_ptr<IInputEventConsumer> callback);
    void RemoveInputHandler(InputHandlerType handlerType,
        HandleEventType eventType, std::shared_ptr<IInputEventConsumer> callback);
    int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType, SessionPtr session);
    void RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType, SessionPtr session);
    void MarkConsumed(int32_t eventId, SessionPtr session);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    bool OnHandleEvent(std::shared_ptr<KeyEvent> KeyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool OnHandleEvent(std::shared_ptr<PointerEvent> PointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    void Dump(int32_t fd, const std::vector<std::string> &args);
#ifdef PLAYER_FRAMEWORK_EXISTS
    void RegisterScreenCaptureListener();
#endif

private:
    void InitSessionLostCallback();
    void OnSessionLost(SessionPtr session);

private:
    class SessionHandler {
    public:
        SessionHandler(InputHandlerType handlerType, HandleEventType eventType,
            SessionPtr session, std::shared_ptr<IInputEventConsumer> cb = nullptr)
            : handlerType_(handlerType), eventType_(eventType & HANDLE_EVENT_TYPE_ALL),
              session_(session), callback(cb) {}
        void SendToClient(std::shared_ptr<KeyEvent> keyEvent, NetPacket &pkt) const;
        void SendToClient(std::shared_ptr<PointerEvent> pointerEvent, NetPacket &pkt) const;
        bool operator<(const SessionHandler& other) const
        {
            return (session_ < other.session_);
        }
        InputHandlerType handlerType_;
        HandleEventType eventType_;
        SessionPtr session_ { nullptr };
        std::shared_ptr<IInputEventConsumer> callback {nullptr};
    };

    class MonitorCollection : public IInputEventCollectionHandler, protected NoCopyable {
    public:
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
        virtual bool HandleEvent(std::shared_ptr<KeyEvent> KeyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
        virtual bool HandleEvent(std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
        int32_t AddMonitor(const SessionHandler& mon);
        void RemoveMonitor(const SessionHandler& mon);
        void MarkConsumed(int32_t eventId, SessionPtr session);

        bool HasMonitor(SessionPtr session);
#ifdef OHOS_BUILD_ENABLE_TOUCH
        void UpdateConsumptionState(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
        void Monitor(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
        void OnSessionLost(SessionPtr session);
        void Dump(int32_t fd, const std::vector<std::string> &args);

    struct ConsumptionState {
        std::set<int32_t> eventIds_;
        bool isMonitorConsumed_ { false };
        std::shared_ptr<PointerEvent> lastPointerEvent_ { nullptr };
    };

    private:
        std::set<SessionHandler> monitors_;
        std::unordered_map<int32_t, ConsumptionState> states_;
    };

private:
    bool sessionLostCallbackInitialized_ { false };
    MonitorCollection monitors_;
#ifdef PLAYER_FRAMEWORK_EXISTS
    sptr<InputScreenCaptureMonitorListener> screenCaptureMonitorListener_ { nullptr };
#endif
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_MONITOR_HANDLER_H