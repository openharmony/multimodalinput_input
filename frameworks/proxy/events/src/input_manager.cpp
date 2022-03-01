/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "error_multimodal.h"
#include "input_manager.h"
#include "input_event_monitor_manager.h"
#include "interceptor_manager.h"
#include "input_manager_impl.h"
#include "key_event_input_subscribe_manager.h"
#include "libmmi_util.h"
#include "multimodal_event_handler.h"

namespace OHOS {
namespace MMI {
InputManager *InputManager::instance_ = nullptr;

InputManager *InputManager::GetInstance()
{
    if (instance_ == nullptr) {
        instance_ = new (std::nothrow) InputManager();
    }
    return instance_;
}

void InputManager::UpdateDisplayInfo(const std::vector<PhysicalDisplayInfo> &physicalDisplays,
    const std::vector<LogicalDisplayInfo> &logicalDisplays)
{
    InputManagerImpl::GetInstance()->UpdateDisplayInfo(physicalDisplays, logicalDisplays);
}

int32_t InputManager::AddInputEventFilter(std::function<bool(std::shared_ptr<PointerEvent>)> filter)
{
    return InputManagerImpl::GetInstance()->AddInputEventFilter(filter);
}

void InputManager::SetWindowInputEventConsumer(std::shared_ptr<OHOS::MMI::IInputEventConsumer> inputEventConsumer)
{
    InputManagerImpl::GetInstance()->SetWindowInputEventConsumer(inputEventConsumer);
}

int32_t InputManager::SubscribeKeyEvent(std::shared_ptr<KeyOption> keyOption,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    return KeyEventInputSubscribeMgr.SubscribeKeyEvent(keyOption, callback);
}

void InputManager::UnsubscribeKeyEvent(int32_t subscriberId)
{
    KeyEventInputSubscribeMgr.UnSubscribeKeyEvent(subscriberId);
}

int32_t InputManager::AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor)
{
    return InputManagerImpl::GetInstance()->AddMonitor(monitor);
}

int32_t InputManager::AddMonitor(std::function<void(std::shared_ptr<PointerEvent>)> monitor)
{
    return InputManagerImpl::GetInstance()->AddMontior(monitor);
}

int32_t InputManager::AddMonitor(std::shared_ptr<IInputEventConsumer> monitor)
{
    return InputManagerImpl::GetInstance()->AddMonitor(monitor);
}

void InputManager::RemoveMonitor(int32_t monitorId)
{
    InputManagerImpl::GetInstance()->RemoveMonitor(monitorId);
}

void InputManager::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    InputManagerImpl::GetInstance()->MarkConsumed(monitorId, eventId);
}

int32_t InputManager::AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor)
{
    return InputManagerImpl::GetInstance()->AddInterceptor(interceptor);
}

int32_t InputManager::AddInterceptor(int32_t sourceType, std::function<void(std::shared_ptr<PointerEvent>)> interceptor)
{
    return -1;
}

int32_t InputManager::AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor)
{
    return InputManagerImpl::GetInstance()->AddInterceptor(interceptor);
}

void InputManager::RemoveInterceptor(int32_t interceptorId)
{
    InputManagerImpl::GetInstance()->RemoveInterceptor(interceptorId);
}

void InputManager::SimulateInputEvent(std::shared_ptr<KeyEvent> keyEvent) 
{
    InputManagerImpl::GetInstance()->SimulateInputEvent(keyEvent);
}

void InputManager::SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    InputManagerImpl::GetInstance()->SimulateInputEvent(pointerEvent);
}
} // namespace MMI
} // namespace OHOS
