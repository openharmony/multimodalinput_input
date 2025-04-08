/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "i_pointer_drawing_manager.h"
#include "input_event_handler.h"
#include "mock_input_windows_manager.h"

namespace OHOS {
namespace MMI {
MockInputWindowsManager *g_inputWindowManagerInterface;

MockInputWindowsManager::MockInputWindowsManager()
{
    g_inputWindowManagerInterface = this;
}

MockInputWindowsManager::~MockInputWindowsManager()
{
    g_inputWindowManagerInterface = nullptr;
}

static InputWindowsManagerInterface *GetInputWindowsManagerInterface()
{
    return g_inputWindowManagerInterface;
}

std::shared_ptr<EventNormalizeHandler> InputEventHandler::GetEventNormalizeHandler() const
{
    return GetInputWindowsManagerInterface()->GetEventNormalizeHandler();
}

std::shared_ptr<EventDispatchHandler> InputEventHandler::GetEventDispatchHandler() const
{
    return GetInputWindowsManagerInterface()->GetEventDispatchHandler();
}

UDSServer *InputEventHandler::GetUDSServer() const
{
    return GetInputWindowsManagerInterface()->GetUDSServer();
}

#ifdef OHOS_BUILD_ENABLE_ANCO
bool InputWindowsManager::IsAncoWindow(const WindowInfo &window) const
{
    return GetInputWindowsManagerInterface()->IsAncoWindow(window);
}

void InputWindowsManager::UpdateShellWindow(const WindowInfo &window) {}
#endif  // OHOS_BUILD_ENABLE_ANCO

}  // namespace MMI
}  // namespace OHOS
