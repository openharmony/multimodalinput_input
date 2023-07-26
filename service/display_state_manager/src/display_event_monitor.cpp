/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "display_event_monitor.h"

#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "define_multimodal.h"
#include "fingersense_manager.h"
#include "fingersense_wrapper.h"
#include "mmi_log.h"
#include "want.h"

namespace OHOS {
namespace MMI {
namespace {
#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "DisplayEventMonitor" };
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
} // namespace

DisplayEventMonitor::DisplayEventMonitor() {}
DisplayEventMonitor::~DisplayEventMonitor() {}

#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
class DisplyChangedReceiver : public EventFwk::CommonEventSubscriber {
public:
    explicit DisplyChangedReceiver(const OHOS::EventFwk::CommonEventSubscribeInfo& subscribeInfo)
        : OHOS::EventFwk::CommonEventSubscriber(subscribeInfo)
    {
        MMI_HILOGD("DisplyChangedReceiver register");
    }

    virtual ~DisplyChangedReceiver() = default;

    void OnReceiveEvent(const EventFwk::CommonEventData &eventData)
    {
        CALL_DEBUG_ENTER;
        std::string action = eventData.GetWant().GetAction();
        if (action.empty()) {
            MMI_HILOGE("action is empty");
            return;
        }
        if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) {
            MMI_HILOGD("display screen on");
            if (FINGERSENSE_WRAPPER->enableFingersense_ != nullptr) {
                MMI_HILOGD("start enable fingersense");
                FINGERSENSE_WRAPPER->enableFingersense_();
            }
        } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
            MMI_HILOGD("display screen off");
            if (FINGERSENSE_WRAPPER->disableFingerSense_ != nullptr) {
                FINGERSENSE_WRAPPER->disableFingerSense_();
            }
        } else {
            MMI_HILOGW("Screen changed receiver event: unknown");
            return;
        }
    }
};

void DisplayEventMonitor::InitCommonEventSubscriber()
{
    CALL_DEBUG_ENTER;
    if (hasInit_) {
        MMI_HILOGE("current common event has subscribered");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventSubscribeInfo commonEventSubscribeInfo(matchingSkills);
    hasInit_ = OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(
        std::make_shared<DisplyChangedReceiver>(commonEventSubscribeInfo));
}
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
} // namespace AppExecFwk
} // namespace OHOS