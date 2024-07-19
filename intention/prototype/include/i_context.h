/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef I_CONTEXT_H
#define I_CONTEXT_H

#include "i_delegate_tasks.h"
#include "i_device_manager.h"
#include "i_drag_manager.h"
#include "i_dsoftbus_adapter.h"
#include "i_input_adapter.h"
#include "i_socket_session_manager.h"
#include "i_plugin_manager.h"
#include "i_timer_manager.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
struct MouseLocation {
    int32_t physicalX { 0 };
    int32_t physicalY { 0 };
};

class IContext {
public:
    IContext() = default;
    virtual ~IContext() = default;

    virtual IDelegateTasks& GetDelegateTasks() = 0;
    virtual IDeviceManager& GetDeviceManager() = 0;
    virtual ITimerManager& GetTimerManager() = 0;
    virtual IDragManager& GetDragManager() = 0;

    virtual ISocketSessionManager& GetSocketSessionManager() = 0;
    virtual IPluginManager& GetPluginManager() = 0;
    virtual IInputAdapter& GetInput() = 0;
    virtual IDSoftbusAdapter& GetDSoftbus() = 0;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_CONTEXT_H