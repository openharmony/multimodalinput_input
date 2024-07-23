/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef INPUT_HANDLER_MANAGER_H
#define INPUT_HANDLER_MANAGER_H

#include <limits>
#include <map>
#include <mutex>

#include "input_device.h"
#include "input_handler_type.h"
#include "i_input_event_consumer.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class InputHandlerManager {
public:
    InputHandlerManager();
    virtual ~InputHandlerManager() = default;
    DISALLOW_COPY_AND_MOVE(InputHandlerManager);

public:
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent, uint32_t deviceTags);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent, uint32_t deviceTags);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    template<typename T>
    bool RecoverPointerEvent(std::initializer_list<T> pointerActionEvents, T pointerActionEvent);
    void OnConnected();
    void OnDisconnected();
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
    bool HasHandler(int32_t handlerId);
    virtual InputHandlerType GetHandlerType() const = 0;
    HandleEventType GetEventType() const;
    int32_t GetPriority() const;
    uint32_t GetDeviceTags() const;

protected:
    int32_t AddHandler(InputHandlerType handlerType, std::shared_ptr<IInputEventConsumer> consumer,
        HandleEventType eventType = HANDLE_EVENT_TYPE_ALL, int32_t priority = DEFUALT_INTERCEPTOR_PRIORITY,
        uint32_t deviceTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX));
    void RemoveHandler(int32_t handlerId, InputHandlerType IsValidHandlerType);

private:
    struct Handler {
        int32_t handlerId_ { 0 };
        InputHandlerType handlerType_ { NONE };
        HandleEventType eventType_ { HANDLE_EVENT_TYPE_ALL };
        int32_t priority_ { DEFUALT_INTERCEPTOR_PRIORITY };
        uint32_t deviceTags_ { CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX) };
        std::shared_ptr<IInputEventConsumer> consumer_ { nullptr };
    };

private:
    int32_t GetNextId();
    int32_t AddLocal(int32_t handlerId, InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags, std::shared_ptr<IInputEventConsumer> monitor);
    int32_t AddToServer(InputHandlerType handlerType, HandleEventType eventType, int32_t priority,
        uint32_t deviceTags);
    int32_t RemoveLocal(int32_t handlerId, InputHandlerType handlerType, uint32_t &deviceTags);
    void RemoveFromServer(InputHandlerType handlerType, HandleEventType eventType, int32_t priority,
        uint32_t deviceTags);

    std::shared_ptr<IInputEventConsumer> FindHandler(int32_t handlerId);
    void OnDispatchEventProcessed(int32_t eventId, int64_t actionTime);
    void AddMouseEventId(std::shared_ptr<PointerEvent> pointerEvent);
    void AddProcessedEventId(std::shared_ptr<PointerEvent> pointerEvent, int32_t consumerCount);
    int32_t GetMonitorConsumerInfos(std::shared_ptr<PointerEvent> pointerEvent,
        std::map<int32_t, std::shared_ptr<IInputEventConsumer>> &consumerInfos);
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool CheckInputDeviceSource(const std::shared_ptr<PointerEvent> pointerEvent, uint32_t deviceTags) const;
    void GetConsumerInfos(std::shared_ptr<PointerEvent> pointerEvent, uint32_t deviceTags,
        std::map<int32_t, std::shared_ptr<IInputEventConsumer>> &consumerInfos);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

private:
    std::list<Handler> interHandlers_;
    std::map<int32_t, Handler> monitorHandlers_;
    std::map<int32_t, int32_t> processedEvents_;
    std::set<int32_t> mouseEventIds_;
    std::function<void(int32_t, int64_t)> monitorCallback_ { nullptr };
    int32_t nextId_ { 1 };
    std::mutex mtxHandlers_;
    std::shared_ptr<PointerEvent> lastPointerEvent_ { nullptr };
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_HANDLER_MANAGER_H
