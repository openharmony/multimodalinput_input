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

#include "input_adapter.h"

#include "input_manager.h"
#include "i_input_event_consumer.h"
#include "i_input_event_filter.h"

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "InputAdapter"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

class PointerFilter : public MMI::IInputEventFilter {
public:
    explicit PointerFilter(std::function<bool(std::shared_ptr<MMI::PointerEvent>)> filter)
        : filter_(filter) {}

    bool OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const override
    {
        return (filter_ != nullptr ? filter_(pointerEvent) : false);
    }

    bool OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const override
    {
        return false;
    }

private:
    std::function<bool(std::shared_ptr<MMI::PointerEvent>)> filter_;
};

class InterceptorConsumer : public MMI::IInputEventConsumer {
public:
    InterceptorConsumer(std::function<void(std::shared_ptr<MMI::PointerEvent>)> pointerCb,
                        std::function<void(std::shared_ptr<MMI::KeyEvent>)> keyCb)
        : pointerCb_(pointerCb), keyCb_(keyCb) {}

    void OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const override
    {
        if (keyCb_ != nullptr) {
            keyCb_(keyEvent);
        }
    }

    void OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const override
    {
        if (pointerCb_ != nullptr) {
            pointerCb_(pointerEvent);
        }
    }

    void OnInputEvent(std::shared_ptr<MMI::AxisEvent> axisEvent) const override {}

private:
    std::function<void(std::shared_ptr<MMI::PointerEvent>)> pointerCb_;
    std::function<void(std::shared_ptr<MMI::KeyEvent>)> keyCb_;
};

int32_t InputAdapter::AddMonitor(std::function<void(std::shared_ptr<MMI::PointerEvent>)> callback)
{
    int32_t monitorId = MMI::InputManager::GetInstance()->AddMonitor(callback);
    if (monitorId < 0) {
        FI_HILOGE("AddMonitor fail");
    }
    return monitorId;
}

int32_t InputAdapter::AddMonitor(std::function<void(std::shared_ptr<MMI::KeyEvent>)> callback)
{
    int32_t monitorId = MMI::InputManager::GetInstance()->AddMonitor(callback);
    if (monitorId < 0) {
        FI_HILOGE("AddMonitor fail");
    }
    return monitorId;
}

void InputAdapter::RemoveMonitor(int32_t monitorId)
{
    MMI::InputManager::GetInstance()->RemoveMonitor(monitorId);
}

int32_t InputAdapter::AddInterceptor(std::function<void(std::shared_ptr<MMI::PointerEvent>)> pointerCb)
{
    return AddInterceptor(pointerCb, nullptr);
}

int32_t InputAdapter::AddInterceptor(std::function<void(std::shared_ptr<MMI::KeyEvent>)> keyCb)
{
    return AddInterceptor(nullptr, keyCb);
}

int32_t InputAdapter::AddInterceptor(std::function<void(std::shared_ptr<MMI::PointerEvent>)> pointerCb,
                                     std::function<void(std::shared_ptr<MMI::KeyEvent>)> keyCb)
{
    uint32_t tags { 0u };
    if (pointerCb != nullptr) {
        tags |= MMI::CapabilityToTags(MMI::INPUT_DEV_CAP_POINTER);
    }
    if (keyCb != nullptr) {
        tags |= MMI::CapabilityToTags(MMI::INPUT_DEV_CAP_KEYBOARD);
    }
    if (tags == 0u) {
        FI_HILOGE("Both interceptors are null");
        return -1;
    }
    auto interceptor = std::make_shared<InterceptorConsumer>(pointerCb, keyCb);
    constexpr int32_t DEFAULT_PRIORITY { 499 };
    int32_t interceptorId = MMI::InputManager::GetInstance()->AddInterceptor(interceptor, DEFAULT_PRIORITY, tags);
    if (interceptorId < 0) {
        FI_HILOGE("AddInterceptor fail");
    }
    return interceptorId;
}

void InputAdapter::RemoveInterceptor(int32_t interceptorId)
{
    MMI::InputManager::GetInstance()->RemoveInterceptor(interceptorId);
}

int32_t InputAdapter::AddFilter(std::function<bool(std::shared_ptr<MMI::PointerEvent>)> callback)
{
    constexpr int32_t DEFAULT_PRIORITY { 220 };
    auto filter = std::make_shared<PointerFilter>(callback);
    uint32_t tags = CapabilityToTags(MMI::INPUT_DEV_CAP_POINTER);
    int32_t filterId = MMI::InputManager::GetInstance()->AddInputEventFilter(filter, DEFAULT_PRIORITY, tags);
    if (filterId < 0) {
        FI_HILOGE("AddInputEventFilter fail");
    }
    return filterId;
}

void InputAdapter::RemoveFilter(int32_t filterId)
{
    MMI::InputManager::GetInstance()->RemoveInputEventFilter(filterId);
}

int32_t InputAdapter::SetPointerVisibility(bool visible, int32_t priority)
{
    FI_HILOGI("Set pointer visibility, visible:%{public}s", visible ? "true" : "false");
    return MMI::InputManager::GetInstance()->SetPointerVisible(visible, priority);
}

int32_t InputAdapter::SetPointerLocation(int32_t x, int32_t y)
{
    return MMI::InputManager::GetInstance()->SetPointerLocation(x, y);
}

int32_t InputAdapter::EnableInputDevice(bool enable)
{
    return MMI::InputManager::GetInstance()->EnableInputDevice(enable);
}

void InputAdapter::SimulateInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}

void InputAdapter::SimulateInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent)
{
    MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
}

int32_t InputAdapter::AddVirtualInputDevice(std::shared_ptr<MMI::InputDevice> device, int32_t &deviceId)
{
    return MMI::InputManager::GetInstance()->AddVirtualInputDevice(device, deviceId);
}

int32_t InputAdapter::RemoveVirtualInputDevice(int32_t deviceId)
{
    return MMI::InputManager::GetInstance()->RemoveVirtualInputDevice(deviceId);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS