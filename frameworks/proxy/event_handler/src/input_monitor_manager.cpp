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

#include "input_monitor_manager.h"

#include "input_handler_manager.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputMonitorManager" };
} // namespace

int32_t InputMonitorManager::AddMonitor(std::shared_ptr<IInputEventConsumer> monitor)
{
    if (monitor == nullptr) {
        MMI_HILOGE("No monitor was specified.");
        return INVALID_HANDLER_ID;
    }
    return InputHandlerManager::GetInstance().AddHandler(InputHandlerType::MONITOR, monitor);
}

void InputMonitorManager::RemoveMonitor(int32_t monitorId)
{
    InputHandlerManager::GetInstance().RemoveHandler(monitorId, InputHandlerType::MONITOR);
}

void InputMonitorManager::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    InputHandlerManager::GetInstance().MarkConsumed(monitorId, eventId);
}

void InputMonitorManager::MoveMouse(int32_t offsetX, int32_t offsetY)
{
    InputHandlerManager::GetInstance().MoveMouse(offsetX, offsetY);
}
} // namespace MMI
} // namespace OHOS
