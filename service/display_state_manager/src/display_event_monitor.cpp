/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "delegate_interface.h"
#include "input_event_handler.h"
#include "input_windows_manager.h"
#include "input_event_handler.h"
#include "key_subscriber_handler.h"
#include "cursor_drawing_component.h"
#include "setting_datashare.h"
#include "system_ability_definition.h"

#ifdef OHOS_BUILD_ENABLE_COMBINATION_KEY
#include "stylus_key_handler.h"
#endif // OHOS_BUILD_ENABLE_COMBINATION_KEY

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DisplayEventMonitor"

namespace OHOS {
namespace MMI {
#ifdef __aarch64__
static constexpr uint32_t MMI_OBJECT_MASK = 0xffffffff;
#else
static constexpr uint32_t MMI_OBJECT_MASK = 0xffffff;
#endif

DisplayEventMonitor::DisplayEventMonitor()
{
    MMI_HILOGI("DisplayEventMonitor constructor, addr:%{public}u",
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(this) & MMI_OBJECT_MASK));
}
DisplayEventMonitor::~DisplayEventMonitor()
{
    MMI_HILOGI("~DisplayEventMonitor destructor, addr:%{public}u",
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(this) & MMI_OBJECT_MASK));
}

#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
class DisplyChangedReceiver : public EventFwk::CommonEventSubscriber {
public:
    explicit DisplyChangedReceiver(const OHOS::EventFwk::CommonEventSubscribeInfo& subscribeInfo)
        : OHOS::EventFwk::CommonEventSubscriber(subscribeInfo)
    {
        MMI_HILOGD("DisplyChangedReceiver register");
    }

    virtual ~DisplyChangedReceiver() = default;
    __attribute__((no_sanitize("cfi")))
    void OnReceiveEvent(const EventFwk::CommonEventData &eventData)
    {
        CALL_DEBUG_ENTER;
        std::string action = eventData.GetWant().GetAction();
        if (action.empty()) {
            MMI_HILOGE("The action is empty");
            return;
        }
        MMI_HILOGD("Received screen status:%{public}s", action.c_str());
        JudgeAction(action);
    }

    void JudgeAction(std::string &action)
    {
        if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) {
            MMI_HILOGI("Display screen on");
            DISPLAY_MONITOR->SetScreenStatus(action);
#ifdef OHOS_BUILD_ENABLE_COMBINATION_KEY
            STYLUS_HANDLER->IsLaunchAbility();
#endif // OHOS_BUILD_ENABLE_COMBINATION_KEY
            CHKPV(FINGERSENSE_WRAPPER);
            if (FINGERSENSE_WRAPPER->enableFingersense_ != nullptr) {
                MMI_HILOGI("Start enable fingersense");
                FINGERSENSE_WRAPPER->enableFingersense_();
            }
            DISPLAY_MONITOR->UpdateShieldStatusOnScreenOn();
        } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
            MMI_HILOGD("Display screen off");
            DISPLAY_MONITOR->SetScreenStatus(action);
            CHKPV(FINGERSENSE_WRAPPER);
            if (FINGERSENSE_WRAPPER->disableFingerSense_ != nullptr) {
                MMI_HILOGI("Disable fingersense");
                FINGERSENSE_WRAPPER->disableFingerSense_();
            }
            DISPLAY_MONITOR->UpdateShieldStatusOnScreenOff();
        } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED) {
            MMI_HILOGD("Display screen locked");
            DISPLAY_MONITOR->SetScreenLocked(true);
            DISPLAY_MONITOR->SendCancelEventWhenLock();
        } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) {
            MMI_HILOGD("Display screen unlocked");
            DISPLAY_MONITOR->SetScreenLocked(false);
        } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_DATA_SHARE_READY) {
            MMI_HILOGI("Received data share ready event");
            if (SettingDataShare::GetInstance(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID).CheckIfSettingsDataReady()) {
                MMI_HILOGI("Data share has readyed");
                CursorDrawingComponent::GetInstance().InitPointerObserver();
                auto keySubscriberHandler = InputHandler->GetSubscriberHandler();
                CHKPV(keySubscriberHandler);
                keySubscriberHandler->InitDataShareListener();
                auto keyHandler = InputHandler->GetKeyCommandHandler();
                if (keyHandler != nullptr) {
                    keyHandler->InitKeyObserver();
                }
            }
        } else {
            MMI_HILOGW("Screen changed receiver event: unknown");
        }
    }
};

void DisplayEventMonitor::UpdateShieldStatusOnScreenOn()
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("Shield mode before screen on:%{public}d", shieldModeBeforeSreenOff_);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    if (shieldModeBeforeSreenOff_ != SHIELD_MODE::UNSET_MODE) {
        KeyEventHdr->SetCurrentShieldMode(shieldModeBeforeSreenOff_);
    } else {
        MMI_HILOGD("Shield mode before screen on:%{public}d", shieldModeBeforeSreenOff_);
    }
#else
    MMI_HILOGW("Keyboard device does not support");
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

void DisplayEventMonitor::UpdateShieldStatusOnScreenOff()
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("Shield mode before screen off:%{public}d", shieldModeBeforeSreenOff_);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    shieldModeBeforeSreenOff_ = KeyEventHdr->GetCurrentShieldMode();
    if (shieldModeBeforeSreenOff_ != SHIELD_MODE::UNSET_MODE) {
        KeyEventHdr->SetCurrentShieldMode(SHIELD_MODE::UNSET_MODE);
    } else {
        MMI_HILOGD("Shield mode before screen off:%{public}d", shieldModeBeforeSreenOff_);
    }
#else
    MMI_HILOGW("Keyboard device does not support");
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

void DisplayEventMonitor::InitCommonEventSubscriber()
{
    CALL_DEBUG_ENTER;
    if (hasInit_) {
        MMI_HILOGE("Current common event has subscribered");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_DATA_SHARE_READY);
    EventFwk::CommonEventSubscribeInfo commonEventSubscribeInfo(matchingSkills);
    hasInit_ = OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(
        std::make_shared<DisplyChangedReceiver>(commonEventSubscribeInfo));
}

bool DisplayEventMonitor::IsCommonEventSubscriberInit()
{
    return hasInit_;
}

void DisplayEventMonitor::SendCancelEventWhenLock()
{
    CHKPV(delegateProxy_);
    delegateProxy_->OnPostSyncTask([] {
        WIN_MGR->SendCancelEventWhenLock();
        return RET_OK;
    });
}
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
} // namespace AppExecFwk
} // namespace OHOS