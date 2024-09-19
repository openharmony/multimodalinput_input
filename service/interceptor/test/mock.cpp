/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "mock.h"

namespace OHOS {
namespace MMI {
std::shared_ptr<InputDeviceManager> InputDeviceManager::instance_ = nullptr;
std::mutex InputDeviceManager::mutex_;

std::shared_ptr<InputDeviceManager> InputDeviceManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<InputDeviceManager>();
        }
    }
    return instance_;
}

void InputDeviceManager::Attach(std::shared_ptr<IDeviceObserver> observer)
{}

void InputDeviceManager::Detach(std::shared_ptr<IDeviceObserver> observer)
{}

void InputDeviceManager::NotifyPointerDevice(bool hasPointerDevice, bool isVisible, bool isHotPlug)
{}

std::shared_ptr<InputDevice> InputDeviceManager::GetInputDevice(int32_t deviceId, bool checked) const
{
    return DfsMessageParcel::messageParcel->GetInputDevice(deviceId, checked);
}

void BytraceAdapter::StartBytrace(std::shared_ptr<KeyEvent> key, HandlerType handlerType)
{}

void BytraceAdapter::StartBytrace(std::shared_ptr<PointerEvent> pointerEvent, TraceBtn traceBtn)
{}
} // namespace MMI
} // namespace OHOS