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

#ifndef MMI_EVENT_MONITOR_HANDLER_MOCK_H
#define MMI_EVENT_MONITOR_HANDLER_MOCK_H

#include <cstdint>

#include "gmock/gmock.h"
#include "i_input_event_consumer.h"
#include "i_input_event_handler.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
class IEventMonitorHandler : public IInputEventHandler {
public:
    IEventMonitorHandler() = default;
    virtual ~IEventMonitorHandler() = default;

    virtual int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        std::shared_ptr<IInputEventConsumer> callback, TouchGestureType gestureType, int32_t fingers) = 0;
    virtual void RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        std::shared_ptr<IInputEventConsumer> callback, TouchGestureType gestureType, int32_t fingers) = 0;
    virtual int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType, SessionPtr session) = 0;
    virtual void RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType, SessionPtr session) = 0;
    virtual int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        SessionPtr session, TouchGestureType gestureType, int32_t fingers) = 0;
    virtual void RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        SessionPtr session, TouchGestureType gestureType, int32_t fingers) = 0;
    virtual int32_t AddInputHandler(InputHandlerType handlerType,
        std::vector<int32_t> actionsType, SessionPtr session) = 0;
    virtual void RemoveInputHandler(InputHandlerType handlerType,
        std::vector<int32_t> actionsType, SessionPtr session) = 0;
    virtual void MarkConsumed(int32_t eventId, SessionPtr session) = 0;
};

class EventMonitorHandler : public IEventMonitorHandler {
public:
    EventMonitorHandler() = default;
    virtual ~EventMonitorHandler() override = default;

    MOCK_METHOD(void, HandleKeyEvent, (const std::shared_ptr<KeyEvent>));
    MOCK_METHOD(void, HandlePointerEvent, (const std::shared_ptr<PointerEvent>));
    MOCK_METHOD(void, HandleTouchEvent, (const std::shared_ptr<PointerEvent>));
    MOCK_METHOD(int32_t, AddInputHandler,
        (InputHandlerType, HandleEventType, std::shared_ptr<IInputEventConsumer>, TouchGestureType, int32_t));
    MOCK_METHOD(void, RemoveInputHandler,
        (InputHandlerType, HandleEventType, std::shared_ptr<IInputEventConsumer>, TouchGestureType, int32_t));
    MOCK_METHOD(int32_t, AddInputHandler, (InputHandlerType, HandleEventType, SessionPtr));
    MOCK_METHOD(void, RemoveInputHandler, (InputHandlerType, HandleEventType, SessionPtr));
    MOCK_METHOD(int32_t, AddInputHandler, (InputHandlerType, HandleEventType, SessionPtr, TouchGestureType, int32_t));
    MOCK_METHOD(void, RemoveInputHandler, (InputHandlerType, HandleEventType, SessionPtr, TouchGestureType, int32_t));
    MOCK_METHOD(int32_t, AddInputHandler, (InputHandlerType, std::vector<int32_t>, SessionPtr));
    MOCK_METHOD(void, RemoveInputHandler, (InputHandlerType, std::vector<int32_t>, SessionPtr));
    MOCK_METHOD(void, MarkConsumed, (int32_t, SessionPtr));
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_EVENT_MONITOR_HANDLER_MOCK_H