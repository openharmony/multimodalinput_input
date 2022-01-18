/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_MULTIMDOALINPUT_INPUT_MANAGER_H
#define OHOS_MULTIMDOALINPUT_INPUT_MANAGER_H

#include <memory>
#include <list>

#include "display_info.h"
#include "i_input_event_consumer.h"
#include "error_multimodal.h"
#include "key_option.h"
#include "input_device_event.h"

namespace OHOS {
namespace MMI {
class InputManager {
public:
    static InputManager *GetInstance();
    virtual ~InputManager() = default;

    void UpdateDisplayInfo(const std::vector<PhysicalDisplayInfo> &physicalDisplays,
        const std::vector<LogicalDisplayInfo> &logicalDisplays);                         // 建议本地调用，可IPC
    int32_t AddInputEventFilter(std::function<bool(std::shared_ptr<PointerEvent>)> filter);

    void SetWindowInputEventConsumer(std::shared_ptr<OHOS::MMI::IInputEventConsumer> inputEventConsumer);

    /**
    *@brief Subscribes to the key input event that meets a specific condition. When such an event occurs, the <b>callback</b> specified is invoked to process the event.
    *@param keyOption Indicates the condition of the key input event.
    *@param callback Indicates the callback.
    *@return Returns the subscription ID, which uniquely identifies a subscription in the process. If the value is greater than or equal to <b>0</b>, the subscription is successful. Otherwise, the subscription fails.
    *@since 8
    */
    int32_t SubscribeKeyEvent(std::shared_ptr<KeyOption> keyOption,
        std::function<void(std::shared_ptr<KeyEvent>)> callback);

    /**
    *@brief Unsubscribes from a key input event.
    *@param subscriberId Indicates the subscription ID, which is the return value of <b>SubscribeKeyEvent</b>.
    *@return void
    *@since 8
    */
    void UnsubscribeKeyEvent(int32_t subscriberId);

    int32_t AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor);
    int32_t AddMonitor(std::function<void(std::shared_ptr<PointerEvent>)> monitor);

    /**
    *@brief Adds an input event monitor. After such a monitor is added, an input event is copied and distributed to the monitor while being distributed to the original target.
    *@param monitor Indicates the input event monitor. After an input event is generated, the functions of the monitor object will be called.
    *@return Returns the monitor ID, which uniquely identifies a monitor in the process. If the value is greater than or equal to <b>0</b>, the monitor is successfully added. Otherwise, the monitor fails to be added.
    *@since 8
    */
    int32_t AddMonitor(std::shared_ptr<IInputEventConsumer> consumer);

    /**
    *@brief Removes a monitor.
    *@param monitorId Indicates the monitor ID, which is the return value of <b>AddMonitor</b>.
    *@return void
    *@since 8
    */
    void RemoveMonitor(int32_t monitorId);

    /**
    *@brief Marks that a monitor has consumed a touchscreen input event. After being consumed, the touchscreen input event will not be distributed to the original target.
    *@param monitorId Indicates the monitor ID.
    *@param eventId Indicates the ID of the consumed touchscreen input event.
    *@return void
    *@since 8
    */
    void MarkConsumed(int32_t monitorId, int32_t eventId);
    
    /**
    *@brief Adds an input event interceptor. After such an interceptor is added, an input event will be distributed to the interceptor instead of the original target and monitor.
    *@param interceptor Indicates the input event interceptor. After an input event is generated, the functions of the interceptor object will be called.
    *@return Returns the interceptor ID, which uniquely identifies an interceptor in the process. If the value is greater than or equal to <b>0</b>, the interceptor is successfully added. Otherwise, the interceptor fails to be added.
    *@since 8
    */
    int32_t AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptorId);
    int32_t AddInterceptor(int32_t sourceType, std::function<void(std::shared_ptr<PointerEvent>)> interceptor);
    int32_t AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor);

    /**
    *@brief Removes an interceptor.
    *@param interceptorId Indicates the interceptor ID, which is the return value of <b>AddInterceptor</b>.
    *@return void
    *@since 8
    */
    void RemoveInterceptor(int32_t interceptorId);

    /**
    *@brief Simulates a key input event. This event will be distributed and processed in the same way as the event reported by the input device.
    *@param keyEvent Indicates the key input event to simulate.
    *@return void
    *@since 8
    */
    void SimulateInputEvent(std::shared_ptr<KeyEvent> keyEvent);
    void SimulateInputEvent(std::list<std::shared_ptr<KeyEvent>> keyEvents);

    /**
    *@brief Simulates a touchpad input event, touchscreen input event, or mouse device input event. This event will be distributed and processed in the same way as the event reported by the input device.
    *@param pointerEvent Indicates the touchpad input event, touchscreen input event, or mouse device input event to simulate.
    *@return void
    *@since 8
    */
    void SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void SimulateInputEvent(std::list<std::shared_ptr<PointerEvent>> pointerEvents);

private:
    InputManager() = default;
    static InputManager *mInstance_;
};
}
} // namespace OHOS::MMI
#endif // OHOS_MULTIMDOALINPUT_INPUT_MANAGER_H
