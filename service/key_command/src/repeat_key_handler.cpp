/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "repeat_key_handler.h"

#include "ability_launcher.h"
#include "bundle_name_parser.h"
#include "bytrace_adapter.h"
#include "device_event_monitor.h"
#include "dfx_hisysevent.h"
#include "input_screen_capture_agent.h"
#include "key_command_handler_util.h"
#include "timer_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "RepeatKeyHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int64_t SOS_INTERVAL_TIMES { 300000 };
constexpr int32_t DEFAULT_TIMER_ID { -1 };
} // namespace

bool RepeatKeyHandler::HandleRepeatKeys(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (context_.repeatKeys_->empty()) {
        MMI_HILOGD("No sequences configuration data");
        return false;
    }

    bool waitRepeatKey = false;

    for (RepeatKey& item : *context_.repeatKeys_) {
        if (CheckSpecialRepeatKey(item, keyEvent)) {
            context_.launchAbilityCount_ = 0;
            MMI_HILOGI("Skip repeatKey");
            return false;
        }
        if (HandleKeyUpCancel(item, keyEvent)) {
            MMI_HILOGI("Cancel repeatKey");
            DfxHisysevent::ReportKeyEvent("cancel");
            return false;
        }
        if (HandleRepeatKeyCount(item, keyEvent)) {
            break;
        }
    }

    for (RepeatKey& item : *context_.repeatKeys_) {
        bool isRepeatKey = HandleRepeatKey(item, keyEvent);
        if (isRepeatKey) {
            waitRepeatKey = true;
        }
    }
    MMI_HILOGI("Handle repeat key, waitRepeatKey:%{public}d", waitRepeatKey);
    return waitRepeatKey;
}
  
bool RepeatKeyHandler::HandleRepeatKey(const RepeatKey& item, const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    auto powerKeyLogger = [keyEvent, &item] () {
        if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER) {
            MMI_HILOGI("Add ability, bundleName:%{public}s", item.ability.bundleName.c_str());
        }
    };
    CHKPF(keyEvent);
    if (keyEvent->GetKeyCode() != item.keyCode) {
        return false;
    }

    if (!context_.isDownStart_) {
        return false;
    }
    if (keyEvent->GetKeyAction() != KeyEvent::KEY_ACTION_DOWN ||
        (context_.count_ > context_.maxCount_ && keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER)) {
        if (context_.isDownStart_) {
            service_.HandleSpecialKeys(keyEvent->GetKeyCode(), keyEvent->GetKeyAction());
        }
        return true;
    }
    auto it = context_.repeatKeyCountMap_.find(item.ability.bundleName);
    auto sosBundleName = BUNDLE_NAME_PARSER.GetBundleName("SOS_BUNDLE_NAME");
    if (it == context_.repeatKeyCountMap_.end()) {
        lastDownActionTime_ = downActionTime_;
        if (item.ability.bundleName != sosBundleName ||
            downActionTime_ - context_.lastVolumeDownActionTime_ > SOS_INTERVAL_TIMES) {
            context_.repeatKeyCountMap_.emplace(item.ability.bundleName, 1);
            powerKeyLogger();
            MMI_HILOGI("bundleName:%{public}s", item.ability.bundleName.c_str());
            return true;
        }
        return false;
    }
    HandleRepeatKeyOwnCount(item);
    lastDownActionTime_ = downActionTime_;
    if (context_.repeatKeyCountMap_[item.ability.bundleName] == item.times) {
        powerKeyLogger();
        if (!item.statusConfig.empty()) {
            bool statusValue = true;
            auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
                .GetBoolValue(item.statusConfig, statusValue);
            if (ret != RET_OK) {
                MMI_HILOGE("Get value from setting data fail");
                DfxHisysevent::ReportFailHandleKey("HandleRepeatKey", keyEvent->GetKeyCode(),
                    DfxHisysevent::KEY_ERROR_CODE::ERROR_RETURN_VALUE);
                return false;
            }
            if (!statusValue) {
                MMI_HILOGE("Get value from setting data, result is false");
                return false;
            }
        }
        if (context_.repeatKeyMaxTimes_.find(item.keyCode) != context_.repeatKeyMaxTimes_.end()) {
            context_.launchAbilityCount_ = context_.count_;
            if (item.times < context_.repeatKeyMaxTimes_[item.keyCode]) {
                return HandleRepeatKeyAbility(item, keyEvent, false);
            }
            return HandleRepeatKeyAbility(item, keyEvent, true);
        }
    }
    if (context_.count_ > item.times &&
        context_.repeatKeyMaxTimes_.find(item.keyCode) != context_.repeatKeyMaxTimes_.end() &&
        repeatKeyTimerIds_.find(item.ability.bundleName) != repeatKeyTimerIds_.end()) {
        if (context_.count_ < context_.repeatKeyMaxTimes_[item.keyCode] &&
            repeatKeyTimerIds_[item.ability.bundleName] >= 0) {
            TimerMgr->RemoveTimer(repeatKeyTimerIds_[item.ability.bundleName]);
            repeatKeyTimerIds_.erase(item.ability.bundleName);
            powerKeyLogger();
            return true;
        }
    }
    MMI_HILOGI("[HandleRepeatKey] bundleName:%{public}s", item.ability.bundleName.c_str());
    return true;
}

void RepeatKeyHandler::HandleRepeatKeyOwnCount(const RepeatKey &item)
{
    auto sosBundleName = BUNDLE_NAME_PARSER.GetBundleName("SOS_BUNDLE_NAME");
    if (item.ability.bundleName == sosBundleName) {
        if (downActionTime_ - lastDownActionTime_ < item.delay) {
            context_.repeatKeyCountMap_[item.ability.bundleName]++;
        }
    } else if (downActionTime_ - upActionTime_ < item.delay) {
        context_.repeatKeyCountMap_[item.ability.bundleName]++;
    }
}

bool RepeatKeyHandler::HandleRepeatKeyCount(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (keyEvent->GetKeyCode() == item.keyCode && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        return HandleRepeatKeyCountUp(item, keyEvent);
    }

    if (keyEvent->GetKeyCode() == item.keyCode && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        return HandleRepeatKeyCountDown(item, keyEvent);
    }
    return false;
}

bool RepeatKeyHandler::HandleRepeatKeyCountDown(const RepeatKey &item,
    const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (context_.repeatKey_.keyCode != item.keyCode) {
        context_.count_ = 1;
        context_.repeatKey_.keyCode = item.keyCode;
        context_.repeatKey_.keyAction = keyEvent->GetKeyAction();
    } else {
        if (context_.repeatKey_.keyAction == keyEvent->GetKeyAction()) {
            MMI_HILOGD("Repeat key, reset down status");
            context_.count_ = 0;
            context_.isDownStart_ = false;
            context_.repeatKeyCountMap_.clear();
            return true;
        } else {
            context_.repeatKey_.keyAction = keyEvent->GetKeyAction();
            context_.count_++;
            MMI_HILOGD("Repeat count:%{public}d", context_.count_);
        }
    }
    context_.isDownStart_ = true;
    downActionTime_ = keyEvent->GetActionTime();
    if ((downActionTime_ - upActionTime_) < context_.intervalTime_) {
        if (repeatTimerId_ >= 0) {
            TimerMgr->RemoveTimer(repeatTimerId_);
            repeatTimerId_ = DEFAULT_TIMER_ID;
            context_.isHandleSequence_ = false;
        }
    }
    return true;
}

bool RepeatKeyHandler::HandleRepeatKeyCountUp(const RepeatKey &item,
    const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    upActionTime_ = keyEvent->GetActionTime();
    context_.repeatKey_.keyCode = item.keyCode;
    context_.repeatKey_.keyAction = keyEvent->GetKeyAction();
    int64_t intervalTime = context_.intervalTime_;
    if (item.keyCode == KeyEvent::KEYCODE_POWER) {
        intervalTime = context_.intervalTime_ - (upActionTime_ - downActionTime_);
        if (context_.walletLaunchDelayTimes_ != 0) {
            intervalTime = context_.walletLaunchDelayTimes_;
        }
    }
    MMI_HILOGD("IntervalTime:%{public}" PRId64, intervalTime);
    repeatTimerId_ = TimerMgr->AddTimer(intervalTime / SECONDS_SYSTEM, 1, [this] () {
        SendKeyEvent();
        repeatTimerId_ = -1;
    }, "RepeatKeyHandler-HandleRepeatKeyCount");
    if (repeatTimerId_ < 0) {
        return false;
    }
    return true;
}
  
bool RepeatKeyHandler::HandleRepeatKeyAbility(const RepeatKey &item,
    const std::shared_ptr<KeyEvent> keyEvent, bool isMaxTimes)
{
    if (!isMaxTimes) {
        PreNotify(item);
        int64_t delaytime = context_.intervalTime_ - (downActionTime_ - upActionTime_);
        int32_t timerId = TimerMgr->AddTimer(
            delaytime / SECONDS_SYSTEM, 1, [this, item, keyEvent] () {
            LAUNCHER_ABILITY->LaunchRepeatKeyAbility(item, keyEvent);
            auto it = repeatKeyTimerIds_.find(item.ability.bundleName);
            if (it != repeatKeyTimerIds_.end()) {
                repeatKeyTimerIds_.erase(it);
            }
        }, "RepeatKeyHandler-HandleRepeatKeyAbility");
        if (timerId < 0) {
            DfxHisysevent::ReportFailHandleKey("HandleRepeatKeyAbility", keyEvent->GetKeyCode(),
                DfxHisysevent::KEY_ERROR_CODE::FAILED_TIMER);
            return false;
        }
        if (repeatTimerId_ >= 0) {
            TimerMgr->RemoveTimer(repeatTimerId_);
            repeatTimerId_ = DEFAULT_TIMER_ID;
            context_.isHandleSequence_ = false;
        }
        if (repeatKeyTimerIds_.find(item.ability.bundleName) == repeatKeyTimerIds_.end()) {
            repeatKeyTimerIds_.emplace(item.ability.bundleName, timerId);
            return true;
        }
        repeatKeyTimerIds_[item.ability.bundleName] = timerId;
        return true;
    }
    LAUNCHER_ABILITY->LaunchRepeatKeyAbility(item, keyEvent);
    return true;
}
  
bool RepeatKeyHandler::HandleKeyUpCancel(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (keyEvent->GetKeyCode() == item.keyCode && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_CANCEL) {
        isKeyCancel_ = true;
        context_.isDownStart_ = false;
        context_.count_ = 0;
        context_.repeatKeyCountMap_.clear();
        DfxHisysevent::ReportKeyEvent("cancel");
        return true;
    }
    return false;
}
  
bool RepeatKeyHandler::CheckSpecialRepeatKey(RepeatKey& item, const std::shared_ptr<KeyEvent> keyEvent)
{
    if (item.keyCode != keyEvent->GetKeyCode()) {
        return false;
    }
    if (item.keyCode != KeyEvent::KEYCODE_VOLUME_DOWN) {
        return false;
    }
    std::string bundleName = item.ability.bundleName;
    std::string matchName = ".camera";
    if (bundleName.find(matchName) == std::string::npos) {
        return false;
    }
    if (keyEvent->GetKeyCode() == item.keyCode && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        context_.repeatKey_.keyCode = item.keyCode;
        context_.repeatKey_.keyAction = keyEvent->GetKeyAction();
        MMI_HILOGI("Update repeatkey status");
    }
    std::string screenStatus = DISPLAY_MONITOR->GetScreenStatus();
    bool isScreenLocked = DISPLAY_MONITOR->GetScreenLocked();
    if (WIN_MGR->JudgeCameraInFore() &&
        (screenStatus != EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF && isScreenLocked)) {
            return true;
    }
    if (IsCallScene()) {
        return true;
    }
    MMI_HILOGI("ScreenStatus:%{public}s, isScreenLocked:%{public}d", screenStatus.c_str(), isScreenLocked);
    if ((screenStatus == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF || isScreenLocked) &&
        !IsMusicActivate()) {
        if (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
#ifdef OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
            service_.CallMistouchPrevention();
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
            MMI_HILOGI("CheckSpecialRepeatKey yes");
        }
        return false;
    }
    return true;
}

void RepeatKeyHandler::SendKeyEvent()
{
    CALL_DEBUG_ENTER;
    if (!context_.isHandleSequence_) {
        MMI_HILOGD("Launch ability count:%{public}d count:%{public}d",
            context_.launchAbilityCount_, context_.count_);
        for (int32_t i = context_.launchAbilityCount_; i < context_.count_; i++) {
            int32_t keycode = context_.repeatKey_.keyCode;
            if (IsSpecialType(keycode, SpecialType::KEY_DOWN_ACTION)) {
                service_.HandleSpecialKeys(keycode, KeyEvent::KEY_ACTION_UP);
            }
            if (context_.count_ == context_.repeatKeyMaxTimes_[keycode] - 1 &&
                keycode == KeyEvent::KEYCODE_POWER) {
                auto keyEventCancel = CreateKeyEvent(keycode, KeyEvent::KEY_ACTION_CANCEL, false);
                CHKPV(keyEventCancel);
                auto handler = InputHandler->GetSubscriberHandler();
                CHKPV(handler);
                handler->HandleKeyEvent(keyEventCancel);
                continue;
            }
            if (i != 0) {
                auto keyEventDown = CreateKeyEvent(keycode, KeyEvent::KEY_ACTION_DOWN, true);
                CHKPV(keyEventDown);
                auto handler = InputHandler->GetSubscriberHandler();
                CHKPV(handler);
                handler->HandleKeyEvent(keyEventDown);
            }
            auto keyEventUp = CreateKeyEvent(keycode, KeyEvent::KEY_ACTION_UP, false);
            CHKPV(keyEventUp);
            auto handler = InputHandler->GetSubscriberHandler();
            CHKPV(handler);
            handler->HandleKeyEvent(keyEventUp);
        }
    }
    context_.count_ = 0;
    context_.repeatKeyCountMap_.clear();
    context_.isDownStart_ = false;
    context_.isHandleSequence_ = false;
    context_.launchAbilityCount_ = 0;
}

bool RepeatKeyHandler::IsMusicActivate()
{
    return InputScreenCaptureAgent::GetInstance().IsMusicActivate();
}

void RepeatKeyHandler::PreNotify(const RepeatKey &item)
{
    if (!item.preNotifyAbility.bundleName.empty()) {
        MMI_HILOGI("PreNotify config bundleName:%{public}s", item.preNotifyAbility.bundleName.c_str());
        LAUNCHER_ABILITY->LaunchAbility(item.preNotifyAbility);
    }
}

std::shared_ptr<KeyEvent> RepeatKeyHandler::CreateKeyEvent(int32_t keyCode,
    int32_t keyAction, bool isPressed)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    KeyEvent::KeyItem item;
    item.SetKeyCode(keyCode);
    item.SetPressed(isPressed);
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(keyAction);
    keyEvent->AddPressedKeyItems(item);
    return keyEvent;
}

bool RepeatKeyHandler::IsCallScene()
{
    auto callState = DEVICE_MONITOR->GetCallState();
    auto voipCallState = DEVICE_MONITOR->GetVoipCallState();
    if (callState == StateType::CALL_STATUS_ACTIVE || callState == StateType::CALL_STATUS_HOLDING ||
        callState == StateType::CALL_STATUS_INCOMING || callState == StateType::CALL_STATUS_ANSWERED ||
        callState == StateType::CALL_STATUS_ALERTING) {
        return true;
    }
    if (voipCallState == StateType::CALL_STATUS_ACTIVE || voipCallState == StateType::CALL_STATUS_HOLDING ||
        voipCallState == StateType::CALL_STATUS_INCOMING || voipCallState == StateType::CALL_STATUS_ANSWERED ||
        voipCallState == StateType::CALL_STATUS_ALERTING) {
        return true;
    }
    return false;
}
} // namespace MMI
} // namespace OHOS