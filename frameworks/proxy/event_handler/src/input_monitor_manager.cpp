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

int32_t InputMonitorManager::AddGestureMonitor(
    std::shared_ptr<IInputEventConsumer> consumer, TouchGestureType type, int32_t fingers)
{
    CHKPR(consumer, INVALID_HANDLER_ID);
    return InputHandlerManager::AddGestureMonitor(InputHandlerType::MONITOR,
        consumer, HANDLE_EVENT_TYPE_TOUCH_GESTURE, type, fingers);
}

int32_t InputMonitorManager::RemoveGestureMonitor(int32_t monitorId)
{
    return InputHandlerManager::RemoveGestureMonitor(monitorId, InputHandlerType::MONITOR);
}

int32_t InputMonitorManager::RemoveMonitor(int32_t monitorId)
{
    return RemoveHandler(monitorId, InputHandlerType::MONITOR);
}

int32_t InputMonitorManager::AddMonitor(std::shared_ptr<IInputEventConsumer> monitor,
    std::vector<int32_t> actionsType)
{
    CHKPR(monitor, INVALID_HANDLER_ID);
    return AddHandler(InputHandlerType::MONITOR, monitor, actionsType);
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

bool InputMonitorManager::CheckMonitorValid(TouchGestureType type, int32_t fingers)
{
    if (type == TOUCH_GESTURE_TYPE_NONE ||
        (TOUCH_GESTURE_TYPE_ALL & type) != type) {
        return false;
    }
    TouchGestureType ret = TOUCH_GESTURE_TYPE_NONE;
    if (fingers == ALL_FINGER_COUNT) {
        return true;
    }
    if (((type & TOUCH_GESTURE_TYPE_SWIPE) == TOUCH_GESTURE_TYPE_SWIPE) &&
        (THREE_FINGER_COUNT <= fingers && fingers <= MAX_FINGERS_COUNT)) {
        ret = TOUCH_GESTURE_TYPE_SWIPE;
    } else if (((type & TOUCH_GESTURE_TYPE_PINCH) == TOUCH_GESTURE_TYPE_PINCH) &&
        (FOUR_FINGER_COUNT <= fingers && fingers <= MAX_FINGERS_COUNT)) {
        ret = TOUCH_GESTURE_TYPE_PINCH;
    }
    if (ret != TOUCH_GESTURE_TYPE_NONE) {
        if ((type = type ^ ret) != TOUCH_GESTURE_TYPE_NONE) {
            return CheckMonitorValid(type, fingers);
        }
    } else {
        return false;
    }
    return true;
}
} // namespace MMI
} // namespace OHOS
