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

#ifndef DEVICE_EVENT_MONITOR_H
#define DEVICE_EVENT_MONITOR_H

#include "nocopyable.h"
#include "singleton.h"

#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "want.h"

#include "define_multimodal.h"
#include "mmi_log.h"
#include "util.h"

namespace OHOS {
namespace MMI {
enum StateType {
    CALL_STATUS_ACTIVE = 0,
    CALL_STATUS_HOLDING = 1,
    CALL_STATUS_DIALING = 2,
    CALL_STATUS_ALERTING = 3,
    CALL_STATUS_INCOMING = 4,
    CALL_STATUS_WAITING = 5,
    CALL_STATUS_DISCONNECTED = 6,
    CALL_STATUS_DISCONNECTING = 7,
    CALL_STATUS_IDLE = 8,
    CALL_STATUS_ANSWERED = 9
};

class DeviceEventMonitor final {
    DECLARE_DELAYED_SINGLETON(DeviceEventMonitor);
public:
    DISALLOW_COPY_AND_MOVE(DeviceEventMonitor);

    void InitCommonEventSubscriber();
    void SetCallState(const EventFwk::CommonEventData &eventData, int32_t callState);
    int32_t GetCallState();
    void SetHasHandleRingMute(bool hasHandleRingMute);
    bool GetHasHandleRingMute();
private:
    bool hasInit_ { false };
    int32_t callState_ { -1 };
    bool hasHandleRingMute_ { false };
    std::mutex stateMutex_;
};
#define DEVICE_MONITOR ::OHOS::DelayedSingleton<DeviceEventMonitor>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // DEVICE_EVENT_MONITOR_H
