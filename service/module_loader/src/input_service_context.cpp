/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "input_service_context.h"
#include "input_event_handler.h"
#include "input_device_manager.h"
#include "key_map_manager.h"
#include "timer_manager.h"
#include "cursor_drawing_component.h"
#include "input_device_manager.h"

namespace OHOS {
namespace MMI {
std::shared_ptr<IDelegateInterface> InputServiceContext::GetDelegateInterface() const
{
    return delegate_.lock();
}

IUdsServer* InputServiceContext::GetUDSServer() const
{
    return InputHandler->GetUDSServer();
}

std::shared_ptr<IInputEventHandler> InputServiceContext::GetEventNormalizeHandler() const
{
    return InputHandler->GetEventNormalizeHandler();
}

std::shared_ptr<IInputEventHandler> InputServiceContext::GetMonitorHandler() const
{
    return InputHandler->GetMonitorHandler();
}

std::shared_ptr<IInputEventHandler> InputServiceContext::GetDispatchHandler() const
{
    return InputHandler->GetEventDispatchHandler();
}

std::shared_ptr<ITimerManager> InputServiceContext::GetTimerManager() const
{
    return TimerMgr;
}

std::shared_ptr<IInputDeviceManager> InputServiceContext::GetDeviceManager() const
{
    return INPUT_DEV_MGR;
}

std::shared_ptr<IInputWindowsManager> InputServiceContext::GetInputWindowsManager() const
{
    return WIN_MGR;
}

std::shared_ptr<IKeyMapManager> InputServiceContext::GetKeyMapManager() const
{
    return KeyMapMgr;
}

std::shared_ptr<IPreferenceManager> InputServiceContext::GetPreferenceManager() const
{
    return PREFERENCES_MGR;
}

ICursorDrawingComponent* InputServiceContext::GetCursorDrawingComponent() const
{
    return &CursorDrawingComponent::GetInstance();
}

void InputServiceContext::AttachDelegateInterface(std::shared_ptr<IDelegateInterface> delegate)
{
    delegate_ = delegate;
}
} // namespace MMI
} // namespace OHOS
