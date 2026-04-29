/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "trigger_event_dispatcher.h"

#include <algorithm>
#include <chrono>
#include <thread>
#include "key_event.h"
#include "mmi_log.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TriggerEventDispatcher"

namespace OHOS {
namespace MMI {

TriggerEventDispatcher* TriggerEventDispatcher::GetInstance()
{
    static TriggerEventDispatcher instance;
    return &instance;
}

bool TriggerEventDispatcher::ShouldDispatch(std::shared_ptr<KeyOption> keyOption,
    std::shared_ptr<KeyEvent> keyEvent)
{
    if (keyOption == nullptr || keyEvent == nullptr) {
        MMI_HILOGE("keyOption or keyEvent is nullptr");
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    int32_t triggerType = keyOption->GetTriggerType();
    switch (triggerType) {
        case PRESSED:
            return ShouldDispatchPRESSED(keyOption, keyEvent);
        case REPEAT_PRESSED:
            return ShouldDispatchREPEAT_PRESSED(keyOption, keyEvent);
        case ALL_RELEASED:
            return ShouldDispatchALL_RELEASED(keyOption, keyEvent);
        default:
            MMI_HILOGE("Invalid triggerType:%{public}d", triggerType);
            return false;
    }
}

bool TriggerEventDispatcher::ShouldConsume(std::shared_ptr<KeyOption> keyOption,
    std::shared_ptr<KeyEvent> keyEvent)
{
    if (keyOption == nullptr || keyEvent == nullptr) {
        MMI_HILOGE("keyOption or keyEvent is nullptr");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t triggerType = keyOption->GetTriggerType();
    int32_t keyCode = keyEvent->GetKeyCode();
    int32_t action = keyEvent->GetKeyAction();
    if (triggerType == PRESSED) {
        if (keyCode == keyOption->GetFinalKey()) {
            MMI_HILOGD("PRESSED mode: consuming finalKey event");
            return true;
        }
        const auto& preKeys = keyOption->GetPreKeys();
        if (preKeys.find(keyCode) != preKeys.end() && action == KeyEvent::KEY_ACTION_UP) {
            MMI_HILOGD("PRESSED mode: consuming preKey up event");
            return true;
        }
    }
    if (triggerType == REPEAT_PRESSED) {
        if (keyCode == keyOption->GetFinalKey()) {
            MMI_HILOGD("REPEAT_PRESSED mode: consuming finalKey event");
            return true;
        }
        const auto& preKeys = keyOption->GetPreKeys();
        if (preKeys.find(keyCode) != preKeys.end() && action == KeyEvent::KEY_ACTION_UP) {
            MMI_HILOGD("REPEAT_PRESSED mode: consuming preKey up event");
            return true;
        }
    }
    if (triggerType == ALL_RELEASED) {
        std::string subscribeKey = GenerateSubscribeKey(keyOption);
        auto it = allReleasedDispatchStates_.find(subscribeKey);
        if (it != allReleasedDispatchStates_.end() && it->second.comboActivated) {
            if (keyCode == keyOption->GetFinalKey() ||
                keyOption->GetPreKeys().count(keyCode) > 0) {
                MMI_HILOGI("ALL_RELEASED mode: consuming combo key event KC:%{private}d", keyCode);
                return true;
            }
        }
    }
    MMI_HILOGD("Event not consumed");
    return false;
}

void TriggerEventDispatcher::ClearSubscribeState(const std::string& subscribeKey)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter1 = firstDownSent_.find(subscribeKey);
    if (iter1 != firstDownSent_.end()) {
        firstDownSent_.erase(iter1);
    }
    auto iter2 = downStartTime_.find(subscribeKey);
    if (iter2 != downStartTime_.end()) {
        downStartTime_.erase(iter2);
    }
    auto iter3 = durationPassed_.find(subscribeKey);
    if (iter3 != durationPassed_.end()) {
        durationPassed_.erase(iter3);
    }
    auto iter4 = hasOtherKey_.find(subscribeKey);
    if (iter4 != hasOtherKey_.end()) {
        hasOtherKey_.erase(iter4);
    }
    auto iter5 = allReleasedDispatchStates_.find(subscribeKey);
    if (iter5 != allReleasedDispatchStates_.end()) {
        allReleasedDispatchStates_.erase(iter5);
    }
    MMI_HILOGI("Subscribe state cleared for %{public}s", subscribeKey.c_str());
}

void TriggerEventDispatcher::ClearSubscribeState(std::shared_ptr<KeyOption> keyOption)
{
    if (keyOption == nullptr) {
        MMI_HILOGE("keyOption is nullptr");
        return;
    }
    std::string subscribeKey = GenerateSubscribeKey(keyOption);
    ClearSubscribeState(subscribeKey);
}

bool TriggerEventDispatcher::ShouldDispatchPRESSED(std::shared_ptr<KeyOption> keyOption,
    std::shared_ptr<KeyEvent> keyEvent)
{
    int32_t keyCode = keyEvent->GetKeyCode();
    int32_t action = keyEvent->GetKeyAction();

    if (keyCode != keyOption->GetFinalKey()) {
        return false;
    }
    if (action != KeyEvent::KEY_ACTION_DOWN) {
        return false;
    }
    if (!MatchPreKeys(keyOption, keyEvent)) {
        return false;
    }
    if (!CheckDuration(keyOption, keyEvent)) {
        return false;
    }
    std::string subscribeKey = GenerateSubscribeKey(keyOption);
    if (firstDownSent_[subscribeKey]) {
        MMI_HILOGD("First down already sent, ignore auto-repeat");
        return false;
    }
    firstDownSent_[subscribeKey] = true;

    MMI_HILOGI("PRESSED mode: dispatching first down event");
    return true;
}

std::string TriggerEventDispatcher::GenerateSubscribeKey(std::shared_ptr<KeyOption> keyOption)
{
    std::string key;
    const auto& preKeys = keyOption->GetPreKeys();
    for (const auto& preKey : preKeys) {
        key.append(std::to_string(preKey)).append(",");
    }
    key.append(std::to_string(keyOption->GetFinalKey())).append(",");
    key.append(std::to_string(keyOption->GetTriggerType())).append(",");
    key.append(std::to_string(keyOption->GetFinalKeyDownDuration()));
    return key;
}

bool TriggerEventDispatcher::ShouldDispatchREPEAT_PRESSED(std::shared_ptr<KeyOption> keyOption,
    std::shared_ptr<KeyEvent> keyEvent)
{
    int32_t keyCode = keyEvent->GetKeyCode();
    int32_t action = keyEvent->GetKeyAction();

    if (keyCode != keyOption->GetFinalKey()) {
        return false;
    }
    if (action != KeyEvent::KEY_ACTION_DOWN) {
        return false;
    }
    if (!MatchPreKeys(keyOption, keyEvent)) {
        return false;
    }
    if (!CheckDuration(keyOption, keyEvent)) {
        return false;
    }
    MMI_HILOGI("REPEAT_PRESSED mode: dispatching down event (including auto-repeat)");
    return true;
}

bool TriggerEventDispatcher::ShouldDispatchALL_RELEASED(std::shared_ptr<KeyOption> keyOption,
    std::shared_ptr<KeyEvent> keyEvent)
{
    int32_t keyCode = keyEvent->GetKeyCode();
    int32_t action = keyEvent->GetKeyAction();
    int32_t finalKey = keyOption->GetFinalKey();
    const auto& preKeys = keyOption->GetPreKeys();
    std::string subscribeKey = GenerateSubscribeKey(keyOption);

    auto& state = allReleasedDispatchStates_[subscribeKey];

    // If combo already activated: dispatch all combo key events
    if (state.comboActivated) {
        bool isComboKey = (keyCode == finalKey) || (preKeys.count(keyCode) > 0);
        if (!isComboKey) {
            MMI_HILOGD("ALL_RELEASED: non-combo key event KC:%{private}d, skip", keyCode);
            return false;
        }
        MMI_HILOGI("ALL_RELEASED: combo activated, dispatch KC:%{private}d action:%{public}d",
                   keyCode, action);
        if (action == KeyEvent::KEY_ACTION_DOWN) {
            state.pressedComboKeys.insert(keyCode);
        } else if (action == KeyEvent::KEY_ACTION_UP) {
            state.pressedComboKeys.erase(keyCode);
            if (state.pressedComboKeys.empty()) {
                MMI_HILOGI("ALL_RELEASED: all keys released, resetting dispatch state");
                state.comboActivated = false;
            }
        }
        return true;
    }

    // Not yet activated: check if this is the finalKey DOWN with preKeys matching
    if (keyCode == finalKey && action == KeyEvent::KEY_ACTION_DOWN) {
        if (!MatchPreKeys(keyOption, keyEvent)) {
            MMI_HILOGD("ALL_RELEASED: preKeys not matched on finalKey DOWN");
            return false;
        }
        if (!CheckDuration(keyOption, keyEvent)) {
            return false;
        }
        state.comboActivated = true;
        state.pressedComboKeys.clear();
        state.pressedComboKeys.insert(finalKey);
        for (const auto& preKey : preKeys) {
            state.pressedComboKeys.insert(preKey);
        }
        MMI_HILOGI("ALL_RELEASED: combo activated, dispatching finalKey DOWN KC:%{private}d", keyCode);
        return true;
    }
    MMI_HILOGD("ALL_RELEASED: not activated, skip KC:%{private}d action:%{public}d", keyCode, action);
    return false;
}

bool TriggerEventDispatcher::MatchPreKeys(std::shared_ptr<KeyOption> keyOption,
    std::shared_ptr<KeyEvent> keyEvent)
{
    const auto& preKeys = keyOption->GetPreKeys();
    if (preKeys.empty()) {
        return true;
    }

    std::vector<KeyEvent::KeyItem> keyItems = keyEvent->GetKeyItems();
    if (keyItems.empty()) {
        MMI_HILOGE("Key items is empty");
        return false;
    }

    for (int32_t preKey : preKeys) {
        bool found = false;
        for (const auto& item : keyItems) {
            if (item.GetKeyCode() == preKey && item.IsPressed()) {
                found = true;
                break;
            }
        }
        if (!found) {
            MMI_HILOGD("PreKey not matched: %{public}d", preKey);
            return false;
        }
    }
    MMI_HILOGI("All preKeys matched");
    return true;
}

bool TriggerEventDispatcher::CheckDurationWindowPassed(const std::string& subscribeKey)
{
    CALL_DEBUG_ENTER;
    auto iter = durationPassed_.find(subscribeKey);
    if (iter == durationPassed_.end()) {
        return false;
    }
    if (iter->second) {
        MMI_HILOGD("Duration window already passed");
        return true;
    } else {
        MMI_HILOGD("Duration window not yet passed");
        return false;
    }
}

bool TriggerEventDispatcher::CheckDurationWindowWithOtherKey(const std::string& subscribeKey)
{
    CALL_DEBUG_ENTER;
    if (!HasOtherKeyPressedInWindow(subscribeKey)) {
        MMI_HILOGD("No other key pressed in window");
        return true;
    } else {
        MMI_HILOGD("Other key pressed during duration window");
        return false;
    }
}

bool TriggerEventDispatcher::CheckDuration(std::shared_ptr<KeyOption> keyOption,
    std::shared_ptr<KeyEvent> keyEvent)
{
    int32_t duration = keyOption->GetFinalKeyDownDuration();
    if (duration == 0) {
        MMI_HILOGD("Duration is 0, immediate trigger");
        return true;
    }

    std::string subscribeKey = GenerateSubscribeKey(keyOption);
    if (downStartTime_.find(subscribeKey) == downStartTime_.end()) {
        StartDurationWindow(subscribeKey, duration);
        MMI_HILOGD("Duration window started, will wait %{public}d microseconds", duration);
        return false;
    }
    if (CheckDurationWindowPassed(subscribeKey)) {
        return CheckDurationWindowWithOtherKey(subscribeKey);
    }
    return false;
}

bool TriggerEventDispatcher::HasOtherKeyPressedInWindow(const std::string& subscribeKey)
{
    auto iter = hasOtherKey_.find(subscribeKey);
    if (iter != hasOtherKey_.end()) {
        return iter->second;
    }
    return false;
}

void TriggerEventDispatcher::StartDurationWindow(const std::string& subscribeKey, int32_t duration)
{
    downStartTime_[subscribeKey] = GetSysClockTime();
    hasOtherKey_[subscribeKey] = false;

    std::thread([this, subscribeKey, duration]() {
        std::this_thread::sleep_for(std::chrono::microseconds(duration));

        std::lock_guard<std::mutex> lock(mutex_);

        if (!hasOtherKey_[subscribeKey]) {
            durationPassed_[subscribeKey] = true;
            MMI_HILOGD("Duration window passed for %{public}s", subscribeKey.c_str());
        } else {
            MMI_HILOGD("Duration window canceled due to other key for %{public}s", subscribeKey.c_str());
        }
    }).detach();
}
void TriggerEventDispatcher::MarkDurationPassed(const std::string& subscribeKey)
{
    std::lock_guard<std::mutex> lock(mutex_);
    durationPassed_[subscribeKey] = true;
    MMI_HILOGD("Mark duration passed for %{public}s", subscribeKey.c_str());
}
} // namespace MMI
} // namespace OHOS
