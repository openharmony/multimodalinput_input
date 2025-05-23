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

#include <unordered_set>

#include "gesture_monitor_handler.h"
#include "i_input_event_collection_handler.h"
#include "i_input_event_handler.h"
#include "nap_process.h"

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
    bool CheckHasInputHandler(HandleEventType eventType);
    int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        std::shared_ptr<IInputEventConsumer> callback,
        TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE, int32_t fingers = 0);
    void RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        std::shared_ptr<IInputEventConsumer> callback,
        TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE, int32_t fingers = 0);
    int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        SessionPtr session, TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE, int32_t fingers = 0);
    void RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        SessionPtr session, TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE, int32_t fingers = 0);
    int32_t AddInputHandler(InputHandlerType handlerType, std::vector<int32_t> actionsType, SessionPtr session);
    void RemoveInputHandler(InputHandlerType handlerType, std::vector<int32_t> actionsType, SessionPtr session);
    void MarkConsumed(int32_t eventId, SessionPtr session);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    bool OnHandleEvent(std::shared_ptr<KeyEvent> KeyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool OnHandleEvent(std::shared_ptr<PointerEvent> PointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    void Dump(int32_t fd, const std::vector<std::string> &args);
#ifdef PLAYER_FRAMEWORK_EXISTS
    void ProcessScreenCapture(int32_t pid, bool isStart);
#endif

private:
    void InitSessionLostCallback();
    void OnSessionLost(SessionPtr session);

private:
    class SessionHandler {
    public:
        SessionHandler(InputHandlerType handlerType, HandleEventType eventType,
            std::shared_ptr<IInputEventConsumer> cb,
            TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE, int32_t fingers = 0)
            : handlerType_(handlerType), eventType_(eventType & HANDLE_EVENT_TYPE_ALL), callback_(cb)
        {
            if ((gestureType & TOUCH_GESTURE_TYPE_ALL) != TOUCH_GESTURE_TYPE_NONE) {
                gesture_.AddGestureMonitor(gestureType, fingers);
            }
        }

        SessionHandler(InputHandlerType handlerType, HandleEventType eventType, SessionPtr session,
            TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE, int32_t fingers = 0)
            : handlerType_(handlerType), eventType_(eventType & HANDLE_EVENT_TYPE_ALL), session_(session)
        {
            if ((gestureType & TOUCH_GESTURE_TYPE_ALL) != TOUCH_GESTURE_TYPE_NONE) {
                gesture_.AddGestureMonitor(gestureType, fingers);
            }
        }

        SessionHandler(InputHandlerType handlerType, uint32_t eventType, SessionPtr session,
            std::vector<int32_t> actionsType, std::shared_ptr<IInputEventConsumer> cb = nullptr)
            : handlerType_(handlerType), eventType_(eventType), session_(session), actionsType_(actionsType),
              callback_(cb) {}

        SessionHandler(const SessionHandler& other)
        {
            handlerType_ = other.handlerType_;
            eventType_ = other.eventType_;
            session_ = other.session_;
            callback_ = other.callback_;
            gesture_ = other.gesture_;
            actionsType_ = other.actionsType_;
        }

        bool Expect(std::shared_ptr<PointerEvent> pointerEvent) const;
        void SendToClient(std::shared_ptr<KeyEvent> keyEvent, NetPacket &pkt) const;
        void SendToClient(std::shared_ptr<PointerEvent> pointerEvent, NetPacket &pkt) const;
        bool operator<(const SessionHandler& other) const
        {
            return (session_ < other.session_);
        }
        void operator()(const GestureMonitorHandler& other)
        {
            gesture_ = other;
        }

        InputHandlerType handlerType_;
        HandleEventType eventType_;
        SessionPtr session_ { nullptr };
        std::vector<int32_t> actionsType_;
        GestureMonitorHandler gesture_;
        std::shared_ptr<IInputEventConsumer> callback_ { nullptr };
    };

    class MonitorCollection : public IInputEventCollectionHandler, protected NoCopyable {
    public:
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
        virtual bool HandleEvent(std::shared_ptr<KeyEvent> KeyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
        virtual bool HandleEvent(std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
        bool CheckHasInputHandler(HandleEventType eventType);
        int32_t UpdateEventTypeMonitor(const std::set<SessionHandler>::iterator &iter,
            const SessionHandler &monitor, SessionHandler &handler, bool isFound);
        int32_t UpdateActionsTypeMonitor(const std::set<SessionHandler>::iterator &iter,
            const SessionHandler &monitor, bool isFound);
        int32_t AddMonitor(const SessionHandler& mon);
        void RemoveMonitor(const SessionHandler& mon);
        void MarkConsumed(int32_t eventId, SessionPtr session);
        bool IsNeedInsertToMonitors(std::vector<int32_t> actionsType);

        bool HasMonitor(SessionPtr session);
        bool HasScreenCaptureMonitor(SessionPtr session);
        void RemoveScreenCaptureMonitor(SessionPtr session);
        void RecoveryScreenCaptureMonitor(SessionPtr session);
#ifdef OHOS_BUILD_ENABLE_TOUCH
        void UpdateConsumptionState(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
        void IsSendToClient(const SessionHandler &monitor, std::shared_ptr<PointerEvent> pointerEvent,
            NetPacket &pkt, std::unordered_set<int32_t> fingerFocusPidSet);
        void Monitor(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
        void OnSessionLost(SessionPtr session);
        void Dump(int32_t fd, const std::vector<std::string> &args);
        bool CheckIfNeedSendToClient(SessionHandler monitor, std::shared_ptr<PointerEvent> pointerEvent,
            std::unordered_set<int32_t> fingerFocusPidSet);
        bool IsPinch(std::shared_ptr<PointerEvent> pointerEvent);
        bool IsRotate(std::shared_ptr<PointerEvent> pointerEvent);
        bool IsThreeFingersSwipe(std::shared_ptr<PointerEvent> pointerEvent);
        bool IsFourFingersSwipe(std::shared_ptr<PointerEvent> pointerEvent);
        bool IsBeginAndEnd(std::shared_ptr<PointerEvent> pointerEvent);
        bool IsThreeFingersTap(std::shared_ptr<PointerEvent> pointerEvent);
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
        bool IsFingerprint(std::shared_ptr<PointerEvent> pointerEvent);
        bool CheckIfNeedSendFingerprintEvent(SessionHandler monitor, std::shared_ptr<PointerEvent> pointerEvent,
            std::unordered_set<int32_t> fingerFocusPidSet);
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
#ifdef OHOS_BUILD_ENABLE_X_KEY
        bool IsXKey(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_X_KEY

        struct ConsumptionState {
            std::set<int32_t> eventIds_;
            bool isMonitorConsumed_ { false };
            std::shared_ptr<PointerEvent> lastPointerEvent_ { nullptr };
        };

    private:
        std::set<SessionHandler> monitors_;
        std::map<int32_t, std::set<SessionHandler>> endScreenCaptureMonitors_;
        std::unordered_map<int32_t, ConsumptionState> states_;
        std::vector<int32_t> insertToMonitorsActions_;
    };

private:
    bool sessionLostCallbackInitialized_ { false };
    MonitorCollection monitors_;
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_MONITOR_HANDLER_H