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

#ifndef I_INPUT_SERVICE_CONTEXT_H
#define I_INPUT_SERVICE_CONTEXT_H

#include "i_delegate_interface.h"
#include "i_input_device_manager.h"
#include "i_input_event_handler.h"
#include "i_input_windows_manager.h"
#include "i_key_map_manager.h"
#include "i_input_device_manager.h"
#include "i_timer_manager.h"
#include "i_preference_manager.h"
#include "i_cursor_drawing_component.h"
#include "i_uds_server.h"
#include "i_setting_manager.h"
namespace OHOS {
namespace MMI {
class IInputServiceContext {
public:
    IInputServiceContext() = default;
    virtual ~IInputServiceContext() = default;

    virtual std::shared_ptr<IDelegateInterface> GetDelegateInterface() const = 0;
    virtual IUdsServer* GetUDSServer() const = 0;
    virtual std::shared_ptr<IInputEventHandler> GetEventNormalizeHandler() const = 0;
    virtual std::shared_ptr<IInputEventHandler> GetMonitorHandler() const = 0;
    virtual std::shared_ptr<IInputEventHandler> GetDispatchHandler() const = 0;
    virtual std::shared_ptr<ITimerManager> GetTimerManager() const = 0;
    virtual std::shared_ptr<IInputWindowsManager> GetInputWindowsManager() const = 0;
    virtual std::shared_ptr<IInputDeviceManager> GetDeviceManager() const = 0;
    virtual std::shared_ptr<IKeyMapManager> GetKeyMapManager() const = 0;
    virtual std::shared_ptr<IPreferenceManager> GetPreferenceManager() const = 0;
    virtual ICursorDrawingComponent& GetCursorDrawingComponent() const = 0;
    virtual std::shared_ptr<ISettingManager> GetSettingManager() const = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // I_INPUT_SERVICE_CONTEXT_H