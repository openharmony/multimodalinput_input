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

#include "input_event_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DeviceEventMonitor"

namespace OHOS {
namespace MMI {
const char* SOS_PAGE_CHANGE_EVENTS = "emergencycommunication.event.SOS_EMERGENCY_CALL_ABILITY_PAGE_CHANGE";
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
            MMI_HILOGE("The action is empty");
            return;
        }
        if (action == EventFwk::CommonEventSupport::COMMON_EVENT_CALL_STATE_CHANGED) {
            int32_t callState = 0;
            DEVICE_MONITOR->SetCallState(eventData, callState);
        } else if (action == SOS_PAGE_CHANGE_EVENTS) {
            MMI_HILOGD("Display emergency call page change");
            std::string pageName = eventData.GetWant().GetStringParam("pageName");
            if (pageName.empty()) {
                MMI_HILOGE("StringParam is empty");
                return;
            }
            auto eventKeyCommandHandler = InputHandler->GetKeyCommandHandler();
            CHKPV(eventKeyCommandHandler);
            int32_t ret = eventKeyCommandHandler->SetIsFreezePowerKey(pageName);
            if (ret != RET_OK) {
                MMI_HILOGE("SetIsFreezePowerKey is failed in key command:%{public}d", ret);
                return;
            }
        } else {
            MMI_HILOGW("Device changed receiver event: unknown");
            return;
        }
    }
};

void DeviceEventMonitor::InitCommonEventSubscriber()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(commonEventMutex_);
    if (hasInit_) {
        MMI_HILOGE("Current common event has subscribered");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_CALL_STATE_CHANGED);
    matchingSkills.AddEvent(SOS_PAGE_CHANGE_EVENTS);
    EventFwk::CommonEventSubscribeInfo commonEventSubscribeInfo(matchingSkills);
    commonEventSubscribeInfo.SetPermission("ohos.permission.SET_TELEPHONY_STATE");
    hasInit_ = OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(
        std::make_shared<DeviceChangedReceiver>(commonEventSubscribeInfo));
}

void DeviceEventMonitor::SetCallState(const EventFwk::CommonEventData &eventData, int32_t callState)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(stateMutex_);
    if (eventData.GetWant().GetIntParam("slotId", -1) != -1) {
        int32_t state = eventData.GetWant().GetIntParam("state", -1);
        if (hasHandleRingMute_ && (state == CALL_STATUS_INCOMING || state == CALL_STATUS_DISCONNECTED)) {
            hasHandleRingMute_ = false;
        }
        return;
    }
    callState = eventData.GetWant().GetIntParam("state", -1);
    MMI_HILOGI("The state %{public}d", callState);
    if (hasHandleRingMute_ && (callState_ == CALL_STATUS_INCOMING || callState_ == CALL_STATUS_WAITING)) {
        MMI_HILOGI("Mute reply success");
        hasHandleRingMute_ = false;
    }
    callState_ = callState;
    if (callState_ == StateType::CALL_STATUS_DISCONNECTED) {
        auto subscriberHandler = InputHandler->GetSubscriberHandler();
        CHKPV(subscriberHandler);
        subscriberHandler->ResetSkipPowerKeyUpFlag();
    }
}

int32_t DeviceEventMonitor::GetCallState()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(stateMutex_);
    return callState_;
}

void DeviceEventMonitor::SetHasHandleRingMute(bool hasHandleRingMute)
{
    CALL_INFO_TRACE;
    hasHandleRingMute_ = hasHandleRingMute;
}

bool DeviceEventMonitor::GetHasHandleRingMute()
{
    CALL_INFO_TRACE;
    return hasHandleRingMute_;
}
} // namespace MMI
} // namespace OHOS