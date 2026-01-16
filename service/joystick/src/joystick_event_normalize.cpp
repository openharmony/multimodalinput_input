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

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickEventNormalize"

namespace OHOS {
namespace MMI {
JoystickEventNormalize::JoystickEventNormalize(IInputServiceContext *env)
    : env_(env) {}

bool JoystickEventNormalize::HasJoystick() const
{
    return !processors_.empty();
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

void JoystickEventNormalize::OnDeviceAdded(int32_t deviceId)
{
    auto devMgr = JoystickEventNormalize::GetDeviceManager(env_);
    if (devMgr == nullptr) {
        MMI_HILOGE("No device manager");
        return;
    }
    devMgr->ForDevice(deviceId,
        [this, deviceId](const IInputDeviceManager::IInputDevice &dev) {
            if (!dev.IsJoystick()) {
                MMI_HILOGI("[%{public}s:%{private}d] Not joystick", dev.GetName().c_str(), deviceId);
                return;
            }
            auto inputDev = dev.GetRawDevice();
            if (inputDev == nullptr) {
                MMI_HILOGE("No raw device attached to device(%{private}d)", deviceId);
                return;
            }
            if (auto iter = processors_.find(inputDev); iter != processors_.end()) {
                MMI_HILOGW("Dirty processor attached to device(%{public}d)", deviceId);
                return;
            }
            MMI_HILOGI("[%{public}s:%{private}d] Joystick added", dev.GetName().c_str(), deviceId);
            processors_.emplace(inputDev, std::make_shared<JoystickEventProcessor>(env_, deviceId));
        });
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

std::shared_ptr<ITimerManager> JoystickEventNormalize::GetTimerManager(IInputServiceContext *env)
{
    if (env == nullptr) {
        MMI_HILOGE("Env is null");
        return nullptr;
    }
    return env->GetTimerManager();
}

std::shared_ptr<IInputWindowsManager> JoystickEventNormalize::GetInputWindowsManager(IInputServiceContext *env)
{
    if (env == nullptr) {
        MMI_HILOGE("Env is null");
        return nullptr;
    }
    return env->GetInputWindowsManager();
}

std::shared_ptr<IInputDeviceManager> JoystickEventNormalize::GetDeviceManager(IInputServiceContext *env)
{
    if (env == nullptr) {
        MMI_HILOGE("Env is null");
        return nullptr;
    }
    return env->GetDeviceManager();
}

std::shared_ptr<IKeyMapManager> JoystickEventNormalize::GetKeyMapManager(IInputServiceContext *env)
{
    if (env == nullptr) {
        MMI_HILOGE("Env is null");
        return nullptr;
    }
    return env->GetKeyMapManager();
}

std::shared_ptr<JoystickEventProcessor> JoystickEventNormalize::GetProcessor(struct libinput_device *inputDev)
{
    if (auto iter = processors_.find(inputDev); iter != processors_.end()) {
        return iter->second;
    }
    auto devMgr = JoystickEventNormalize::GetDeviceManager(env_);
    if (devMgr == nullptr) {
        MMI_HILOGE("No device manager");
        return nullptr;
    }
    std::shared_ptr<JoystickEventProcessor> processor;
    devMgr->ForOneDevice(
        [inputDev](int32_t deviceId, const IInputDeviceManager::IInputDevice &dev) {
            return (dev.GetRawDevice() == inputDev);
        },
        [this, &processor](int32_t deviceId, const IInputDeviceManager::IInputDevice &dev) {
            auto inputDev = dev.GetRawDevice();
            if (inputDev == nullptr) {
                return;
            }
            auto [iter, _] = processors_.emplace(inputDev, std::make_shared<JoystickEventProcessor>(env_, deviceId));
            processor = iter->second;
        });
    return processor;
}

std::shared_ptr<JoystickEventProcessor> JoystickEventNormalize::FindProcessor(int32_t deviceId) const
{
    auto iter = std::find_if(processors_.cbegin(), processors_.cend(),
        [deviceId](const auto &item) {
            return ((item.second != nullptr) && (item.second->GetDeviceId() == deviceId));
        });
    return (iter != processors_.cend() ? iter->second : nullptr);
}

extern "C" IJoystickEventNormalize* CreateInstance(IInputServiceContext *env)
{
    return new JoystickEventNormalize(env);
}

extern "C" void DestroyInstance(IJoystickEventNormalize *instance)
{
    if (instance != nullptr) {
        delete instance;
    }
}
} // namespace MMI
} // namespace OHOS
