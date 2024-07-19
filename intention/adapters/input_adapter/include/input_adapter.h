/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef INPUT_ADAPTER_H
#define INPUT_ADAPTER_H

#include "nocopyable.h"

#include "i_input_adapter.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class InputAdapter final : public IInputAdapter {
public:
    InputAdapter() = default;
    ~InputAdapter() = default;
    DISALLOW_COPY_AND_MOVE(InputAdapter);

    int32_t AddMonitor(std::function<void(std::shared_ptr<MMI::PointerEvent>)> callback) override;
    int32_t AddMonitor(std::function<void(std::shared_ptr<MMI::KeyEvent>)> callback) override;
    void RemoveMonitor(int32_t monitorId) override;

    int32_t AddInterceptor(std::function<void(std::shared_ptr<MMI::PointerEvent>)> pointerCb) override;
    int32_t AddInterceptor(std::function<void(std::shared_ptr<MMI::KeyEvent>)> keyCb) override;
    int32_t AddInterceptor(std::function<void(std::shared_ptr<MMI::PointerEvent>)> pointerCb,
                           std::function<void(std::shared_ptr<MMI::KeyEvent>)> keyCb) override;
    void RemoveInterceptor(int32_t interceptorId) override;

    int32_t AddFilter(std::function<bool(std::shared_ptr<MMI::PointerEvent>)> callback) override;
    void RemoveFilter(int32_t filterId) override;

    int32_t SetPointerVisibility(bool visible, int32_t priority = 0) override;
    int32_t SetPointerLocation(int32_t x, int32_t y) override;
    int32_t EnableInputDevice(bool enable) override;

    void SimulateInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) override;
    void SimulateInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) override;
    int32_t AddVirtualInputDevice(std::shared_ptr<MMI::InputDevice> device, int32_t &deviceId) override;
    int32_t RemoveVirtualInputDevice(int32_t deviceId) override;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // INPUT_ADAPTER_H