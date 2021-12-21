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
#include "input_monitor_manager.h"
#include "input_handler_manager.h"

namespace OHOS::MMI {
int32_t InputMonitorManager::AddMonitor(std::shared_ptr<IInputEventConsumer> monitor)
{
    return InputHandlerManager::GetInstance().AddHandler(InputHandlerType::MONITOR, monitor);
}

void InputMonitorManager::RemoveMonitor(int32_t monitorId)
{
    InputHandlerManager::GetInstance().RemoveHandler(monitorId, InputHandlerType::MONITOR);
}
} // namespace OHOS::MMI

