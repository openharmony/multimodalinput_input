/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "joystick_event_normalize.h"

#include "input_device_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickEventNormalize"

namespace OHOS {
namespace MMI {
std::shared_ptr<IJoystickEventNormalize> IJoystickEventNormalize::GetInstance()
{
    return JoystickEventNormalize::GetInstance();
}

JoystickEventNormalize::InputDeviceObserver::InputDeviceObserver(std::shared_ptr<JoystickEventNormalize> parent)
    : parent_(parent) {}

void JoystickEventNormalize::InputDeviceObserver::OnDeviceAdded(int32_t deviceId)
{
    if (auto parent = parent_.lock(); parent != nullptr) {
        parent->OnDeviceAdded(deviceId);
    }
}

void JoystickEventNormalize::InputDeviceObserver::OnDeviceRemoved(int32_t deviceId)
{
    if (auto parent = parent_.lock(); parent != nullptr) {
        parent->OnDeviceRemoved(deviceId);
    }
}

std::shared_ptr<JoystickEventNormalize> JoystickEventNormalize::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<JoystickEventNormalize> instance_;

    std::call_once(flag, []() {
        instance_ = std::make_shared<JoystickEventNormalize>();
        instance_->SetUpDeviceObserver(instance_);
    });
    return instance_;
}

JoystickEventNormalize::~JoystickEventNormalize()
{
    TearDownDeviceObserver();
}

std::shared_ptr<KeyEvent> JoystickEventNormalize::OnButtonEvent(struct libinput_event *event)
{
    CHKPP(event);
    auto inputDev = libinput_event_get_device(event);
    CHKPP(inputDev);
    auto processor = GetProcessor(inputDev);
    CHKPP(processor);
    return processor->OnButtonEvent(event);
}

std::shared_ptr<PointerEvent> JoystickEventNormalize::OnAxisEvent(struct libinput_event *event)
{
    CHKPP(event);
    auto inputDev = libinput_event_get_device(event);
    CHKPP(inputDev);
    auto processor = GetProcessor(inputDev);
    CHKPP(processor);
    return processor->OnAxisEvent(event);
}

void JoystickEventNormalize::CheckIntention(std::shared_ptr<PointerEvent> pointerEvent,
    std::function<void(std::shared_ptr<KeyEvent>)> handler)
{
    auto processor = FindProcessor(pointerEvent->GetDeviceId());
    if (processor == nullptr) {
        MMI_HILOGE("No processor associated with input device(%{public}d)", pointerEvent->GetDeviceId());
        return;
    }
    processor->CheckIntention(pointerEvent, handler);
}

void JoystickEventNormalize::SetUpDeviceObserver(std::shared_ptr<JoystickEventNormalize> self)
{
    if (inputDevObserver_ == nullptr) {
        inputDevObserver_ = std::make_shared<InputDeviceObserver>(self);
        INPUT_DEV_MGR->Attach(inputDevObserver_);
    }
}

void JoystickEventNormalize::TearDownDeviceObserver()
{
    if (inputDevObserver_ != nullptr) {
        INPUT_DEV_MGR->Detach(inputDevObserver_);
        inputDevObserver_ = nullptr;
    }
}

void JoystickEventNormalize::OnDeviceAdded(int32_t deviceId)
{
    auto inputDev = INPUT_DEV_MGR->GetLibinputDevice(deviceId);
    if (inputDev == nullptr) {
        MMI_HILOGW("No libinput-device attached to device(%{public}d)", deviceId);
        return;
    }
    if (auto iter = processors_.find(inputDev); iter != processors_.end()) {
        MMI_HILOGW("Dirty processor attached to device(%{public}d)", deviceId);
        return;
    }
    processors_.emplace(inputDev, std::make_shared<JoystickEventProcessor>(deviceId));
}

void JoystickEventNormalize::OnDeviceRemoved(int32_t deviceId)
{
    auto iter = std::find_if(processors_.cbegin(), processors_.cend(),
        [deviceId](const auto &item) {
            return ((item.second != nullptr) && (item.second->GetDeviceId() == deviceId));
        });
    if (iter != processors_.end()) {
        MMI_HILOGI("Clear processor attached to device(%{public}d)", deviceId);
        processors_.erase(iter);
    }
}

std::shared_ptr<JoystickEventProcessor> JoystickEventNormalize::GetProcessor(struct libinput_device *inputDev)
{
    if (auto iter = processors_.find(inputDev); iter != processors_.end()) {
        return iter->second;
    }
    auto deviceId = INPUT_DEV_MGR->FindInputDeviceId(inputDev);
    auto [iter, _] = processors_.emplace(inputDev, std::make_shared<JoystickEventProcessor>(deviceId));
    return iter->second;
}

std::shared_ptr<JoystickEventProcessor> JoystickEventNormalize::FindProcessor(int32_t deviceId) const
{
    auto iter = std::find_if(processors_.cbegin(), processors_.cend(),
        [deviceId](const auto &item) {
            return ((item.second != nullptr) && (item.second->GetDeviceId() == deviceId));
        });
    return (iter != processors_.cend() ? iter->second : nullptr);
}
} // namespace MMI
} // namespace OHOS
