/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "multimodal_input_connect_manager.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputMonitorManager"

namespace OHOS {
namespace MMI {
InputMonitorManager::InputMonitorManager() {}
InputMonitorManager::~InputMonitorManager() {}

int32_t InputMonitorManager::AddMonitor(std::shared_ptr<IInputEventConsumer> monitor, HandleEventType eventType)
{
    CHKPR(monitor, INVALID_HANDLER_ID);
    return AddHandler(InputHandlerType::MONITOR, monitor, eventType);
}

int32_t InputMonitorManager::RemoveMonitor(int32_t monitorId)
{
    return RemoveHandler(monitorId, InputHandlerType::MONITOR);
}

void InputMonitorManager::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    MMI_HILOGD("Mark consumed state, monitor:%{public}d,event:%{public}d", monitorId, eventId);
    if (!HasHandler(monitorId)) {
        MMI_HILOGW("Failed to find the monitorId");
        return;
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->MarkEventConsumed(eventId);
    if (ret != RET_OK) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
    }
}
} // namespace MMI
} // namespace OHOS
