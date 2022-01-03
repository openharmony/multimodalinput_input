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

#include "input_manager.h"
#include "input_manager_impl.h"
#include "libmmi_util.h"
#include "multimodal_event_handler.h"

namespace OHOS {
namespace MMI {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
        LOG_CORE, MMI_LOG_DOMAIN, "InputManager"
    };
}

InputManager *InputManager::mInstance_ = nullptr;

InputManager *InputManager::GetInstance()
{
    if (mInstance_ == nullptr) {
        mInstance_ = new InputManager();
    }
    return mInstance_;
}

void InputManager::UpdateDisplayInfo(const std::vector<PhysicalDisplayInfo> &physicalDisplays,
    const std::vector<LogicalDisplayInfo> &logicalDisplays)
{
    InputManagerImpl::GetInstance()->UpdateDisplayInfo(physicalDisplays, logicalDisplays);
}

void InputManager::SetInputEventFilter(std::function<bool(std::shared_ptr<PointerEvent> filter)>) {}

void InputManager::SetWindowInputEventConsumer(std::shared_ptr<OHOS::MMI::IInputEventConsumer> inputEventConsumer)
{
    InputManagerImpl::GetInstance()->SetWindowInputEventConsumer(inputEventConsumer);
}

int32_t InputManager::SubscribeKeyEvent(std::shared_ptr<KeyOption> keyOption,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    return 0;
}

void InputManager::UnsubscribeKeyEvent(int32_t subscriberId) {}

int32_t InputManager::AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor)
{
    if (monitor == nullptr) {
        MMI_LOGE("InputManager::%{public}s param should not be null!", __func__);
        return OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER;
    }
    InputManagerImpl::GetInstance()->AddMonitor(monitor);
    return MMI_STANDARD_EVENT_SUCCESS;
}
int32_t InputManager::AddMonitor(std::function<void(std::shared_ptr<PointerEvent>)> monitor)
{
    return 0;
}
int32_t InputManager::AddMonitor(std::function<bool(std::shared_ptr<KeyEvent>)> monitor)
{
    return 0;
}
void InputManager::RemoveMonitor(int32_t monitorId)
{
    InputManagerImpl::GetInstance()->RemoveMonitor(monitorId);
}

int32_t InputManager::AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptorId)
{
    return 0;
}
void InputManager::RemoveInterceptor(int32_t interceptorId) {}

void InputManager::SimulateInputEvent(std::shared_ptr<KeyEvent> keyEvent) {}
void InputManager::SimulateInputEvent(std::list<std::shared_ptr<KeyEvent>> keyEvents) {}
void InputManager::SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    if (MultimodalEventHandler::GetInstance().InjectPointerEvent(pointerEvent) != RET_OK)
        MMI_LOGE("Failed to inject pointer event!");
}
void InputManager::SimulateInputEvent(std::list<std::shared_ptr<PointerEvent>> pointerEvents) {}

void InputManager::GetInputDeviceIdsAsync(std::function<void(std::vector<int32_t>)> callback)
{
    auto& instance = InputDeviceEvent::GetInstance();
    instance.GetInputDeviceIdsAsync(callback);
}

void InputManager::GetInputDeviceAsync(int32_t deviceId,
    std::function<void(std::shared_ptr<InputDeviceEvent::InputDeviceInfo>)> callback)
{
    auto& instance = InputDeviceEvent::GetInstance();
    instance.GetInputDeviceAsync(deviceId, callback);
}
}
}
