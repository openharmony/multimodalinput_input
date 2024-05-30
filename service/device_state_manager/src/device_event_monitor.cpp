/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "device_event_monitor.h"

#include "mmi_log.h"
#include "want.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DeviceEventMonitor"

namespace OHOS {
namespace MMI {
DeviceEventMonitor::DeviceEventMonitor() {}
DeviceEventMonitor::~DeviceEventMonitor() {}

class DeviceChangedReceiver : public EventFwk::CommonEventSubscriber {
public:
    explicit DeviceChangedReceiver(const OHOS::EventFwk::CommonEventSubscribeInfo& subscribeInfo)
        : OHOS::EventFwk::CommonEventSubscriber(subscribeInfo)
    {
        MMI_HILOGD("DeviceEventMonitor register");
    }

    virtual ~DeviceChangedReceiver() = default;
    __attribute__((no_sanitize("cfi")))

    void OnReceiveEvent(const EventFwk::CommonEventData &eventData)
    {
        CALL_DEBUG_ENTER;
        std::string action = eventData.GetWant().GetAction();
        if (action.empty()) {
            MMI_HILOGE("action is empty");
            return;
        }
        if (action == EventFwk::CommonEventSupport::COMMON_EVENT_CALL_STATE_CHANGED) {
            int32_t callState = 0;
            DEVICE_MONITOR->SetCallState(eventData, callState);
        } else {
            MMI_HILOGW("Device changed receiver event: unknown");
            return;
        }
    }
};

void DeviceEventMonitor::InitCommonEventSubscriber()
{
    CALL_DEBUG_ENTER;
    if (hasInit_) {
        MMI_HILOGE("current common event has subscribered");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_CALL_STATE_CHANGED);
    EventFwk::CommonEventSubscribeInfo commonEventSubscribeInfo(matchingSkills);
    hasInit_ = OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(
        std::make_shared<DeviceChangedReceiver>(commonEventSubscribeInfo));
}

void DeviceEventMonitor::SetCallState(const EventFwk::CommonEventData &eventData, int32_t callState)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(stateMutex_);
    callState = eventData.GetWant().GetIntParam("state", -1);
    MMI_HILOGI("state %{public}d", callState);
    if (hasHandleRingMute_ && callState_ == CALL_STATUS_INCOMING && callState != CALL_STATUS_INCOMING) {
        MMI_HILOGI("Mute reply success");
        hasHandleRingMute_ = false;
    }
    callState_ = callState;
}

int32_t DeviceEventMonitor::GetCallState()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(stateMutex_);
    return callState_;
}

void DeviceEventMonitor::SetHasHandleRingMute(bool hasHandleRingMute)
{
    hasHandleRingMute_ = hasHandleRingMute;
}

bool DeviceEventMonitor::GetHasHandleRingMute()
{
    return hasHandleRingMute_;
}
} // namespace MMI
} // namespace OHOS