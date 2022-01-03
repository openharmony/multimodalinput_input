/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "define_multimodal.h"
#include "error_multimodal.h"

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputEventMonitorManager" };
    }

InputEventMonitorManager::InputEventMonitorManager()
{
    MMI_LOGT("InputEventMonitorManager::InputEventMonitorManager enter");
}

InputEventMonitorManager::~InputEventMonitorManager()
{
}

int32_t InputEventMonitorManager::AddInputEventMontior(
    std::function<void (std::shared_ptr<OHOS::MMI::KeyEvent>)> keyEventMonitor)
{
    if (keyEventMonitor == nullptr) {
        MMI_LOGE("InputEventMonitorManager::%{public}s param should not be null!", __func__);
        return OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER;
    }
    static int32_t monitorId = 0;
    MonitorItem monitorItem;
    monitorItem.keyEventMonitor = keyEventMonitor;
    monitorItem.id_ = ++monitorId;
    monitors_.push_back(monitorItem);
    MMI_LOGD("InputEventMonitorManager::%{public}s monitorId = %{public}d", __func__, monitorId);
    MMIEventHdl.AddInputEventMontior(OHOS::MMI::InputEvent::EVENT_TYPE_KEY);
    return OHOS::MMI_STANDARD_EVENT_SUCCESS;
}

void InputEventMonitorManager::RemoveInputEventMontior(int32_t monitorId)
{
	if (monitorId <=0 ) {
		MMI_LOGE("InputEventMonitorManager::%{public}s monitorId invalid", __func__);
	    return;
	}
    MonitorItem monitorItem;
    monitorItem.id_ = monitorId;
    std::list<MonitorItem>::iterator iter;
    iter = std::find(monitors_.begin(), monitors_.end(), monitorItem);
    if (iter == monitors_.end()) {
        MMI_LOGE("InputEventMonitorManager::%{public}s monitorItem does not exist", __func__);
    } else {
        iter = monitors_.erase(iter);
        MMIEventHdl.RemoveInputEventMontior(OHOS::MMI::InputEvent::EVENT_TYPE_KEY);
        MMI_LOGD("InputEventMonitorManager::%{public}s monitorItem id: %{public}d removed", __func__, monitorId);
    }
}

int32_t InputEventMonitorManager::OnMonitorInputEvent(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
{
    if (keyEvent == nullptr) {
        MMI_LOGE("InputEventMonitorManager::%{public}s param should not be null!", __func__);
    }
    std::list<MonitorItem>::iterator iter;
    for (iter = monitors_.begin(); iter != monitors_.end(); iter++) {
        MMI_LOGD("InputEventMonitorManager::%{public}s SendMsg", __func__);
        iter->keyEventMonitor(keyEvent);
    }
    return OHOS::MMI_STANDARD_EVENT_SUCCESS;
}
}
