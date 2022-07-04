/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INPUT_HANDLER_MANAGER_H
#define INPUT_HANDLER_MANAGER_H

#include <limits>
#include <map>
#include <mutex>

#include "singleton.h"

#include "input_handler_type.h"
#include "i_input_event_consumer.h"
#include "mmi_event_handler.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class InputHandlerManager : public Singleton<InputHandlerManager> {
public:
    InputHandlerManager() = default;
    DISALLOW_COPY_AND_MOVE(InputHandlerManager);
    int32_t AddHandler(InputHandlerType handlerType, std::shared_ptr<IInputEventConsumer> consumer,
        HandleEventType eventType = HandleEventType::ALL);
    void RemoveHandler(int32_t handlerId, InputHandlerType handlerType);
    void MarkConsumed(int32_t monitorId, int32_t eventId);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void OnInputEvent(int32_t handlerId, std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void OnInputEvent(int32_t handlerId, std::shared_ptr<PointerEvent> pointerEvent);
#endif
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    void OnConnected();
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR

private:
    struct Handler {
        int32_t handlerId_ { 0 };
        InputHandlerType handlerType_ { NONE };
        HandleEventType eventType_ { HandleEventType::ALL };
        std::shared_ptr<IInputEventConsumer> consumer_ { nullptr };
        EventHandlerPtr eventHandler_ { nullptr };
    };

private:
    int32_t GetNextId();
    int32_t AddLocal(int32_t handlerId, InputHandlerType handlerType,
        HandleEventType eventType, std::shared_ptr<IInputEventConsumer> monitor);
    void AddToServer(int32_t handlerId, InputHandlerType handlerType,
        HandleEventType eventType);
    int32_t RemoveLocal(int32_t handlerId, InputHandlerType handlerType);
    void RemoveFromServer(int32_t handlerId, InputHandlerType handlerType);

    std::shared_ptr<IInputEventConsumer> FindHandler(int32_t handlerId);
    EventHandlerPtr GetEventHandler(int32_t handlerId);
    bool PostTask(int32_t handlerId, const AppExecFwk::EventHandler::Callback &callback);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void OnKeyEventTask(std::shared_ptr<IInputEventConsumer> consumer, int32_t handlerId,
        std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void OnPointerEventTask(std::shared_ptr<IInputEventConsumer> consumer, int32_t handlerId,
        std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

private:
    std::mutex mtxHandlers_;
    std::map<int32_t, Handler> inputHandlers_;
    int32_t nextId_ { 1 };
};
} // namespace MMI
} // namespace OHOS
#define InputHandlerMgr InputHandlerManager::GetInstance()
#endif // INPUT_HANDLER_MANAGER_H