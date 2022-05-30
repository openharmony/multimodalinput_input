/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "input_manager.h"

#include "error_multimodal.h"
#include "input_event_monitor_manager.h"
#include "input_manager_impl.h"
#include "define_multimodal.h"
#include "multimodal_event_handler.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputManager" };
} // namespace

InputManager *InputManager::instance_ = new (std::nothrow) InputManager();
InputManager *InputManager::GetInstance()
{
    return instance_;
}

void InputManager::UpdateDisplayInfo(const std::vector<PhysicalDisplayInfo> &physicalDisplays,
    const std::vector<LogicalDisplayInfo> &logicalDisplays)
{
    InputMgrImpl->UpdateDisplayInfo(physicalDisplays, logicalDisplays);
}

int32_t InputManager::AddInputEventFilter(std::function<bool(std::shared_ptr<PointerEvent>)> filter)
{
    return InputMgrImpl->AddInputEventFilter(filter);
}

void InputManager::SetWindowInputEventConsumer(std::shared_ptr<IInputEventConsumer> inputEventConsumer)
{
    InputMgrImpl->SetWindowInputEventConsumer(inputEventConsumer, nullptr);
}

void InputManager::SetWindowInputEventConsumer(std::shared_ptr<IInputEventConsumer> inputEventConsumer,
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
{
    CHKPV(eventHandler);
    InputMgrImpl->SetWindowInputEventConsumer(inputEventConsumer, eventHandler);
}

int32_t InputManager::SubscribeKeyEvent(std::shared_ptr<KeyOption> keyOption,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    return InputMgrImpl->SubscribeKeyEvent(keyOption, callback);
}

void InputManager::UnsubscribeKeyEvent(int32_t subscriberId)
{
    InputMgrImpl->UnsubscribeKeyEvent(subscriberId);
}

int32_t InputManager::AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor)
{
    return InputMgrImpl->AddMonitor(monitor);
}

int32_t InputManager::AddMonitor(std::function<void(std::shared_ptr<PointerEvent>)> monitor)
{
    return InputMgrImpl->AddMonitor(monitor);
}

int32_t InputManager::AddMonitor(std::shared_ptr<IInputEventConsumer> monitor)
{
    return InputMgrImpl->AddMonitor(monitor);
}

void InputManager::RemoveMonitor(int32_t monitorId)
{
    InputMgrImpl->RemoveMonitor(monitorId);
}

void InputManager::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    InputMgrImpl->MarkConsumed(monitorId, eventId);
}

void InputManager::MoveMouse(int32_t offsetX, int32_t offsetY)
{
    InputMgrImpl->MoveMouse(offsetX, offsetY);
}

int32_t InputManager::AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor)
{
    return InputMgrImpl->AddInterceptor(interceptor);
}

int32_t InputManager::AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor)
{
    return InputMgrImpl->AddInterceptor(interceptor);
}

void InputManager::RemoveInterceptor(int32_t interceptorId)
{
    InputMgrImpl->RemoveInterceptor(interceptorId);
}

void InputManager::SimulateInputEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    InputMgrImpl->SimulateInputEvent(keyEvent);
}

void InputManager::SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    InputMgrImpl->SimulateInputEvent(pointerEvent);
}

void InputManager::SupportKeys(int32_t deviceId, std::vector<int32_t> keyCodes,
    std::function<void(std::vector<bool>&)> callback)
{
    InputMgrImpl->SupportKeys(deviceId, keyCodes, callback);
}

int32_t InputManager::SetPointerVisible(bool visible)
{
    return InputMgrImpl->GetInstance()->SetPointerVisible(visible);
}
bool InputManager::IsPointerVisible()
{
    return InputMgrImpl->GetInstance()->IsPointerVisible();
}

void InputManager::GetKeyboardType(int32_t deviceId, std::function<void(int32_t)> callback)
{
    InputMgrImpl->GetKeyboardType(deviceId, callback);
}
} // namespace MMI
} // namespace OHOS
