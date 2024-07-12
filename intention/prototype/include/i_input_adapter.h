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

#ifndef I_INPUT_ADAPTER_H
#define I_INPUT_ADAPTER_H

#include <functional>
#include <memory>

#include "input_device.h"
#include "key_event.h"
#include "pointer_event.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class IInputAdapter {
public:
    IInputAdapter() = default;
    virtual ~IInputAdapter() = default;

    virtual int32_t AddMonitor(std::function<void(std::shared_ptr<MMI::PointerEvent>)> callback) = 0;
    virtual int32_t AddMonitor(std::function<void(std::shared_ptr<MMI::KeyEvent>)> callback) = 0;
    virtual void RemoveMonitor(int32_t monitorId) = 0;

    virtual int32_t AddInterceptor(std::function<void(std::shared_ptr<MMI::PointerEvent>)> pointerCb) = 0;
    virtual int32_t AddInterceptor(std::function<void(std::shared_ptr<MMI::KeyEvent>)> keyCb) = 0;
    virtual int32_t AddInterceptor(std::function<void(std::shared_ptr<MMI::PointerEvent>)> pointerCb,
                                   std::function<void(std::shared_ptr<MMI::KeyEvent>)> keyCb) = 0;
    virtual void RemoveInterceptor(int32_t interceptorId) = 0;

    virtual int32_t AddFilter(std::function<bool(std::shared_ptr<MMI::PointerEvent>)> callback) = 0;
    virtual void RemoveFilter(int32_t filterId) = 0;

    virtual int32_t SetPointerVisibility(bool visible, int32_t priority = 0) = 0;
    virtual int32_t SetPointerLocation(int32_t x, int32_t y) = 0;
    virtual int32_t EnableInputDevice(bool enable) = 0;

    virtual void SimulateInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) = 0;
    virtual void SimulateInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) = 0;
    virtual int32_t AddVirtualInputDevice(std::shared_ptr<MMI::InputDevice> device, int32_t &deviceId) = 0;
    virtual int32_t RemoveVirtualInputDevice(int32_t deviceId) = 0;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_INPUT_ADAPTER_H
