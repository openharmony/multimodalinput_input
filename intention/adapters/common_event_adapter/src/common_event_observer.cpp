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

#include "common_event_observer.h"

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "CommonEventObserver"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
    std::set<std::string> g_commonEvents = {
        EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON,
        EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF,
        EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED,
        EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED,
        EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_LOW,
        EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_OKAY
    };
}

std::shared_ptr<CommonEventObserver> CommonEventObserver::CreateCommonEventObserver(CommonEventHandleType handle)
{
    CALL_DEBUG_ENTER;
    EventFwk::MatchingSkills skill;
    for (const auto &action : g_commonEvents) {
        skill.AddEvent(action);
    }
    return std::make_shared<CommonEventObserver>(EventFwk::CommonEventSubscribeInfo(skill), handle);
}

void CommonEventObserver::OnReceiveEvent(const EventFwk::CommonEventData &event)
{
    CHKPV(handle_);
    const auto want = event.GetWant();
    const auto action = want.GetAction();
    if (g_commonEvents.find(action) == g_commonEvents.end()) {
        FI_HILOGE("Unexpected action:%{public}s", action.c_str());
        return;
    }
    handle_(action);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS