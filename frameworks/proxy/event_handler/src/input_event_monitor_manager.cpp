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

#include "input_event_monitor_manager.h"
#include <cinttypes>
#include "define_multimodal.h"
#include "error_multimodal.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputEventMonitorManager" };
} // namespace

InputEventMonitorManager::InputEventMonitorManager() {}

InputEventMonitorManager::~InputEventMonitorManager() {}

int32_t InputEventMonitorManager::AddInputEventMontior(
    std::function<void (std::shared_ptr<KeyEvent>)> keyEventMonitor)
{
    MMI_LOGD("enter");
    CHKPR(keyEventMonitor, INVALID_MONITOR_ID);
    int32_t ret = MMIEventHdl.AddInputEventMontior(InputEvent::EVENT_TYPE_KEY);
    if (ret != RET_OK) {
        MMI_LOGE("MultimodalEventHandler send msg failed");
        return INVALID_MONITOR_ID;
    }
    MonitorItem item;
    item.keyEventMonitor = keyEventMonitor;
    static int32_t monitorId = INVALID_MONITOR_ID;
    item.id = ++monitorId;
    monitors_.push_back(item);
    MMI_LOGD("MonitorId:%{public}d", monitorId);
    return item.id;
}

void InputEventMonitorManager::RemoveInputEventMontior(int32_t monitorId)
{
    MMI_LOGD("enter");
    if (monitorId < 0) {
        MMI_LOGE("MonitorId invalid");
        return;
    }
    MonitorItem item;
    item.id = monitorId;
    auto it = std::find(monitors_.begin(), monitors_.end(), item);
    if (it != monitors_.end()) {
        monitors_.erase(it);
        MMIEventHdl.RemoveInputEventMontior(InputEvent::EVENT_TYPE_KEY);
        MMI_LOGD("MonitorId:%{public}d removed", monitorId);
    }
}

int32_t InputEventMonitorManager::OnMonitorInputEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    for (const auto &monitor : monitors_) {
        monitor.keyEventMonitor(keyEvent);
    }
    return RET_OK;
}

int32_t InputEventMonitorManager::AddInputEventTouchpadMontior(
    std::function<void (std::shared_ptr<PointerEvent>)> TouchPadEventMonitor)
{
    CHKPR(TouchPadEventMonitor, ERROR_NULL_POINTER);
    MonitorItem monitorItem;
    monitorItem.TouchPadEventMonitor = TouchPadEventMonitor;
    static int32_t monitorId = 0;
    monitorItem.id = ++monitorId;
    monitors_.push_back(monitorItem);
    MMI_LOGD("monitorId:%{public}d", monitorId);
    MMIEventHdl.AddInputEventTouchpadMontior(InputEvent::EVENT_TYPE_POINTER);
    MMI_LOGD("leave");
    return monitorItem.id;
}

void InputEventMonitorManager::RemoveInputEventTouchpadMontior(int32_t monitorId)
{
    if (monitorId < 0) {
        MMI_LOGE("MonitorId invalid");
        return;
    }
    MonitorItem monitorItem;
    monitorItem.id = monitorId;
    auto iter = std::find(monitors_.begin(), monitors_.end(), monitorItem);
    if (iter == monitors_.end()) {
        MMI_LOGE("MonitorId does not exist");
    } else {
        iter = monitors_.erase(iter);
        MMIEventHdl.RemoveInputEventTouchpadMontior(InputEvent::EVENT_TYPE_POINTER);
        MMI_LOGD("monitorItem id:%{public}d removed", monitorId);
    }
}

int32_t InputEventMonitorManager::OnTouchpadMonitorInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("enter");
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    std::list<MonitorItem>::iterator iter;
    for (const auto &item : monitors_) {
        MMI_LOGD("send msg");
        item.TouchPadEventMonitor(pointerEvent);
    }
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem)) {
        MMI_LOGE("Get pointer item failed");
        return RET_ERR;
    }
    MMI_LOGD("Monitor-clienteventTouchpad:time:%{public}" PRId64 ","
             "sourceType:%{public}d,action:%{public}d,"
             "pointer:%{public}d,point.x:%{public}d,point.y:%{public}d,press:%{public}d",
             pointerEvent->GetActionTime(), pointerEvent->GetSourceType(), pointerEvent->GetPointerAction(),
             pointerEvent->GetPointerId(), pointerItem.GetGlobalX(), pointerItem.GetGlobalY(), pointerItem.IsPressed());
    return OHOS::MMI_STANDARD_EVENT_SUCCESS;
}
} // namespace MMI
} // namespace OHOS