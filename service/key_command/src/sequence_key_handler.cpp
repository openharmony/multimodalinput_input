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

#include "sequence_key_handler.h"

#include "ability_launcher.h"
#include "bytrace_adapter.h"
#include "device_event_monitor.h"
#include "dfx_hisysevent.h"
#include "key_command_handler_util.h"
#include "timer_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SequenceKeyHandler"

namespace OHOS {
namespace MMI {
bool SequenceKeyHandler::HandleSequences(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    std::string screenStatus = DISPLAY_MONITOR->GetScreenStatus();
    if (screenStatus == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
        if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER) {
            MMI_HILOGI("The screen is currently off and the power button needs to respond");
            return false;
        }
    }
    if (IsActiveSequenceRepeating(keyEvent)) {
        MMI_HILOGD("Skip repeating key(%{private}d) in active sequence", keyEvent->GetKeyCode());
        return true;
    }
    MarkActiveSequence(false);
    if (matchedSequence_.timerId >= 0 && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        MMI_HILOGD("Remove matchedSequence timer:%{public}d", matchedSequence_.timerId);
        TimerMgr->RemoveTimer(matchedSequence_.timerId);
        matchedSequence_.timerId = -1;
    }
    if (context_.sequences_->empty()) {
        MMI_HILOGD("No sequences configuration data");
        return false;
    }

    if (!AddSequenceKey(keyEvent)) {
        MMI_HILOGD("Add new sequence key failed");
        return false;
    }

    if (filterSequences_.empty()) {
        filterSequences_ = *context_.sequences_;
    }

    bool isLaunchAbility = false;
    for (auto iter = filterSequences_.begin(); iter != filterSequences_.end();) {
        int32_t timerId = iter->timerId;
        if (!HandleSequence((*iter), isLaunchAbility)) {
            if (TimerMgr->IsExist(timerId)) {
                MMI_HILOGW("Remove timer, id: %{public}d", timerId);
                TimerMgr->RemoveTimer(timerId);
            }
            iter = filterSequences_.erase(iter);
            continue;
        }
        ++iter;
    }

    if (filterSequences_.empty()) {
        MMI_HILOGD("No sequences matched");
        keys_.clear();
        return false;
    }

    if (isLaunchAbility) {
        MarkActiveSequence(true);
        for (const auto& item : keys_) {
            if (IsSpecialType(item.keyCode, SpecialType::KEY_DOWN_ACTION)) {
                service_.HandleSpecialKeys(item.keyCode, item.keyAction);
            }
            auto handler = InputHandler->GetSubscriberHandler();
            CHKPF(handler);
            handler->RemoveSubscriberKeyUpTimer(item.keyCode);
            RemoveSubscribedTimer(item.keyCode);
        }
    }
    return isLaunchAbility;
}
  
bool SequenceKeyHandler::AddSequenceKey(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    SequenceKey sequenceKey;
    sequenceKey.keyCode = keyEvent->GetKeyCode();
    sequenceKey.keyAction = keyEvent->GetKeyAction();
    sequenceKey.actionTime = keyEvent->GetActionTime();
    size_t size = keys_.size();
    if (size > 0) {
        if (keys_[size - 1].actionTime > sequenceKey.actionTime) {
            MMI_HILOGE("The current event time is greater than the last event time");
            ResetSequenceKeys();
            return false;
        }
        if ((sequenceKey.actionTime - keys_[size - 1].actionTime) > MAX_DELAY_TIME) {
            MMI_HILOGD("The delay time is greater than the maximum delay time");
            ResetSequenceKeys();
        } else {
            if (IsRepeatKeyEvent(sequenceKey)) {
                MMI_HILOGD("This is a repeat key event, don't add");
                return false;
            }
            keys_[size - 1].delay = sequenceKey.actionTime - keys_[size - 1].actionTime;
            InterruptTimers();
        }
    }
    if (size > MAX_SEQUENCEKEYS_NUM) {
        DfxHisysevent::ReportFailHandleKey("AddSequenceKey", keyEvent->GetKeyCode(),
            DfxHisysevent::KEY_ERROR_CODE::INVALID_PARAMETER);
        MMI_HILOGD("The save key size more than the max size");
        return false;
    }
    keys_.push_back(sequenceKey);
    return true;
}

bool SequenceKeyHandler::HandleSequence(Sequence& sequence, bool &isLaunchAbility)
{
    CALL_DEBUG_ENTER;
    size_t keysSize = keys_.size();
    size_t sequenceKeysSize = sequence.sequenceKeys.size();
    if (!sequence.statusConfigValue) {
        return false;
    }
    if (keysSize > sequenceKeysSize) {
        MMI_HILOGI("The save sequence not matching ability sequence");
        return false;
    }
    for (size_t i = 0; i < keysSize; ++i) {
        if (keys_[i] != sequence.sequenceKeys[i]) {
            MMI_HILOGD("KeyAction not matching");
            return false;
        }
        int64_t delay = sequence.sequenceKeys[i].delay;
        if (((i + 1) != keysSize) && (delay != 0) && (keys_[i].delay >= delay)) {
            MMI_HILOGD("Delay is not matching");
            return false;
        }
    }

    if (keysSize == sequenceKeysSize) {
        std::ostringstream oss;
        oss << sequence;
        MMI_HILOGI("SequenceKey matched:%{private}s", oss.str().c_str());
        return HandleMatchedSequence(sequence, isLaunchAbility);
    }
    return true;
}

bool SequenceKeyHandler::HandleMatchedSequence(Sequence& sequence, bool &isLaunchAbility)
{
    std::string screenStatus = DISPLAY_MONITOR->GetScreenStatus();
    bool isScreenLocked = DISPLAY_MONITOR->GetScreenLocked();
    MMI_HILOGI("The screenStatus:%{public}s, isScreenLocked:%{public}d", screenStatus.c_str(), isScreenLocked);
    std::string bundleName = sequence.ability.bundleName;
    std::string matchName = ".screenshot";
    if (bundleName.find(matchName) != std::string::npos) {
        bundleName = bundleName.substr(bundleName.size() - matchName.size());
    }
    if (screenStatus == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
        if (bundleName == matchName) {
            MMI_HILOGI("Screen off, screenshot invalid");
            return false;
        }
    } else {
        if (bundleName == matchName && isScreenLocked) {
            MMI_HILOGI("Screen On and locked, screenshot delay 100 milisecond");
            return HandleScreenLocked(sequence, isLaunchAbility);
        }
    }
    return HandleNormalSequence(sequence, isLaunchAbility);
}

bool SequenceKeyHandler::HandleScreenLocked(Sequence& sequence, bool &isLaunchAbility)
{
    std::string bundleName = sequence.ability.bundleName;
    std::string matchName = ".screenshot";
    if (bundleName.find(matchName) != std::string::npos &&
        !service_.HasScreenCapturePermission(SHORTCUT_KEY_SCREENSHOT)) {
        MMI_HILOGI("shortcut_key_screenshot is skipped in HandleNormalSequence, "
                   "screenCapturePermission:%{public}d", service_.GetScreenCapturePermission());
        isLaunchAbility = true;
        return true;
    }
    sequence.timerId = TimerMgr->AddTimer(LONG_ABILITY_START_DELAY, 1, [this, &sequence] () {
        MMI_HILOGI("Timer callback, screenshot delay %{public}d milisecond", LONG_ABILITY_START_DELAY);
        LaunchSequenceAbility(sequence);
        sequence.timerId = -1;
    }, "SequenceKeyHandler-HandleScreenLocked");
    if (sequence.timerId < 0) {
        MMI_HILOGE("Add Timer failed");
        return false;
    }
    MMI_HILOGI("Add timer success");
    matchedSequence_ = sequence;
    isLaunchAbility = true;
    return true;
}

bool SequenceKeyHandler::HandleNormalSequence(Sequence& sequence, bool &isLaunchAbility)
{
    std::string bundleName = sequence.ability.bundleName;
    std::string matchName = ".screenshot";
    uint32_t screenCapturePermission = service_.GetScreenCapturePermission();
    if (bundleName.find(matchName) != std::string::npos &&
        !service_.HasScreenCapturePermission(SHORTCUT_KEY_SCREENSHOT)) {
        MMI_HILOGI("shortcut_key_screenshot is skipped in HandleNormalSequence, "
                   "screenCapturePermission:%{public}d", screenCapturePermission);
        isLaunchAbility = true;
        return true;
    }
    matchName = ".screenrecorder";
    if (bundleName.find(matchName) != std::string::npos &&
        !service_.HasScreenCapturePermission(SHORTCUT_KEY_SCREEN_RECORDING)) {
        MMI_HILOGI("shortcut_key_screen_recording is skipped in HandleNormalSequence, "
                   "screenCapturePermission:%{public}d", screenCapturePermission);
        isLaunchAbility = true;
        return true;
    }
    if (sequence.abilityStartDelay == 0) {
        MMI_HILOGI("Start launch ability immediately");
        LaunchSequenceAbility(sequence);
        isLaunchAbility = true;
        return true;
    }
    sequence.timerId = TimerMgr->AddTimer(sequence.abilityStartDelay, 1, [this, &sequence] () {
        MMI_HILOGI("Timer callback");
        LaunchSequenceAbility(sequence);
        sequence.timerId = -1;
    }, "SequenceKeyHandler-HandleNormalSequence");
    if (sequence.timerId < 0) {
        MMI_HILOGE("Add Timer failed");
        DfxHisysevent::ReportFailLaunchAbility(sequence.ability.bundleName,
            DfxHisysevent::KEY_ERROR_CODE::FAILED_TIMER);
        return false;
    }
    MMI_HILOGI("Add timer success");
    isLaunchAbility = true;
    return true;
}

bool SequenceKeyHandler::IsRepeatKeyEvent(const SequenceKey &sequenceKey)
{
    for (size_t i = keys_.size(); i > 0; --i) {
        if (keys_[i-1].keyCode == sequenceKey.keyCode) {
            if (keys_[i-1].keyAction == sequenceKey.keyAction) {
                MMI_HILOGI("Is repeat key:%{private}d", sequenceKey.keyCode);
                return true;
            }
            MMI_HILOGI("Is not repeat key");
            return false;
        }
    }
    return false;
}

bool SequenceKeyHandler::IsActiveSequenceRepeating(std::shared_ptr<KeyEvent> keyEvent) const
{
    return (sequenceOccurred_ && !keys_.empty() &&
            (keys_.back().keyCode == keyEvent->GetKeyCode()) &&
            (keys_.back().keyAction == KeyEvent::KEY_ACTION_DOWN) &&
            (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN));
}
  
void SequenceKeyHandler::MarkActiveSequence(bool active)
{
    sequenceOccurred_ = active;
}

void SequenceKeyHandler::ResetSequenceKeys()
{
    keys_.clear();
    filterSequences_.clear();
}

void SequenceKeyHandler::InterruptTimers()
{
    for (Sequence& item : filterSequences_) {
        if (item.timerId >= 0) {
            MMI_HILOGD("The key sequence change, close the timer");
            TimerMgr->RemoveTimer(item.timerId);
            item.timerId = -1;
        }
    }
}

void SequenceKeyHandler::RemoveSubscribedTimer(int32_t keyCode)
{
    CALL_DEBUG_ENTER;
    auto iter = context_.specialTimers_.find(keyCode);
    if (iter != context_.specialTimers_.end()) {
        for (auto& item : iter->second) {
            TimerMgr->RemoveTimer(item);
        }
        context_.specialTimers_.erase(keyCode);
        MMI_HILOGI("Remove timer success");
    }
}

void SequenceKeyHandler::LaunchSequenceAbility(const Sequence &sequence)
{
    BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_SEQUENCE, sequence.ability.bundleName);
    LAUNCHER_ABILITY->LaunchAbility(sequence.ability, sequence.abilityStartDelay);
    DfxHisysevent::ReportKeyEvent(sequence.ability.bundleName);
    BytraceAdapter::StopLaunchAbility();
}
} // namespace MMI
} // namespace OHOS