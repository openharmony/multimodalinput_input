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
    void SetInputEventFilter(std::function<bool(std::shared_ptr<PointerEvent> filter)>); // 只能本地

    void SetWindowInputEventConsumer(std::shared_ptr<OHOS::MMI::IInputEventConsumer> inputEventConsumer);

    int32_t SubscribeKeyEvent(std::shared_ptr<KeyOption> keyOption,
        std::function<void(std::shared_ptr<KeyEvent>)> callback);
    void UnsubscribeKeyEvent(int32_t subscriberId);

    int32_t AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor);
    int32_t AddMonitor(std::function<void(std::shared_ptr<PointerEvent>)> monitor);
    int32_t AddMonitor(std::function<bool(std::shared_ptr<KeyEvent>)> monitor);
    void RemoveMonitor(int32_t monitorId);

    int32_t AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptorId);
    void RemoveInterceptor(int32_t interceptorId);

    void SimulateInputEvent(std::shared_ptr<KeyEvent> keyEvent);
    void SimulateInputEvent(std::list<std::shared_ptr<KeyEvent>> keyEvents);
    void SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void SimulateInputEvent(std::list<std::shared_ptr<PointerEvent>> pointerEvents);
    void GetInputDeviceIdsAsync(std::function<void(std::vector<int32_t>)> callback);
    void GetInputDeviceAsync(int32_t deviceId,
                             std::function<void(std::shared_ptr<InputDeviceEvent::InputDeviceInfo>)> callback);

private:
    InputManager() = default;
    static InputManager *mInstance_;
};
}
} // namespace OHOS::MMI
#endif // OHOS_MULTIMDOALINPUT_INPUT_MANAGER_H
