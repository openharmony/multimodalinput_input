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
            MMI_HILOGE("Unknown triggerType: %{public}d", triggerType);
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
    // 1. PRESSED 模式：消费所有相关事件
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
    // 2. REPEAT_PRESSED 模式：消费所有相关事件
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
    // 3. ALL_RELEASED 模式：消费所有相关事件
    if (triggerType == ALL_RELEASED) {
        if (keyCode == keyOption->GetFinalKey()) {
            MMI_HILOGD("ALL_RELEASED mode: consuming finalKey event");
            return true;
        }
        const auto& preKeys = keyOption->GetPreKeys();
        if (preKeys.find(keyCode) != preKeys.end()) {
            MMI_HILOGD("ALL_RELEASED mode: consuming preKey event");
            return true;
        }
    }
    MMI_HILOGD("Event not consumed");
    return false;
}

void TriggerEventDispatcher::ClearSubscribeState(const std::string& subscribeKey)
{
    std::lock_guard<std::mutex> lock(mutex_);

    // 1. 清理 firstDownSent 状态
    auto iter1 = firstDownSent_.find(subscribeKey);
    if (iter1 != firstDownSent_.end()) {
        firstDownSent_.erase(iter1);
    }

    // 2. 清理 downStartTime 状态
    auto iter2 = downStartTime_.find(subscribeKey);
    if (iter2 != downStartTime_.end()) {
        downStartTime_.erase(iter2);
    }

    // 3. 清理 durationPassed 状态
    auto iter3 = durationPassed_.find(subscribeKey);
    if (iter3 != durationPassed_.end()) {
        durationPassed_.erase(iter3);
    }

    // 4. 清理 hasOtherKey 状态
    auto iter4 = hasOtherKey_.find(subscribeKey);
    if (iter4 != hasOtherKey_.end()) {
        hasOtherKey_.erase(iter4);
    }

    MMI_HILOGD("Subscribe state cleared for %{public}s", subscribeKey.c_str());
}

bool TriggerEventDispatcher::ShouldDispatchPRESSED(std::shared_ptr<KeyOption> keyOption,
    std::shared_ptr<KeyEvent> keyEvent)
{
    int32_t keyCode = keyEvent->GetKeyCode();
    int32_t action = keyEvent->GetKeyAction();  // 0=down, 1=up, 2=cancel

    // 1. 只处理 finalKey 的事件
    if (keyCode != keyOption->GetFinalKey()) {
        return false;
    }

    // 2. 只处理 down 事件
    if (action != KeyEvent::KEY_ACTION_DOWN) {
        return false;
    }

    // 3. 检查 preKeys 是否匹配
    if (!MatchPreKeys(keyOption, keyEvent)) {
        return false;
    }

    // 4. 检查是否满足 finalKeyDownDuration 条件
    if (!CheckDuration(keyOption, keyEvent)) {
        return false;
    }

    // 5. 生成订阅键
    std::string subscribeKey = GenerateSubscribeKey(keyOption);
    // 6. 检查是否已发送过首次 down
    if (firstDownSent_[subscribeKey]) {
        MMI_HILOGD("First down already sent, ignore auto-repeat");
        return false;  // 已发送过，后续的自动重复不发送
    }

    // 7. 标记已发送首次 down
    firstDownSent_[subscribeKey] = true;

    MMI_HILOGD("PRESSED mode: dispatching first down event");
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

    // 1. 只处理 finalKey 的事件
    if (keyCode != keyOption->GetFinalKey()) {
        return false;
    }

    // 2. 只处理 down 事件
    if (action != KeyEvent::KEY_ACTION_DOWN) {
        return false;
    }

    // 3. 检查 preKeys 是否匹配
    if (!MatchPreKeys(keyOption, keyEvent)) {
        return false;
    }

    // 4. 检查是否满足 finalKeyDownDuration 条件
    if (!CheckDuration(keyOption, keyEvent)) {
        return false;
    }

    // 5. 所有 down 事件都分发（包括自动重复）
    MMI_HILOGD("REPEAT_PRESSED mode: dispatching down event (including auto-repeat)");
    return true;
}

bool TriggerEventDispatcher::ShouldDispatchALL_RELEASED(std::shared_ptr<KeyOption> keyOption,
    std::shared_ptr<KeyEvent> keyEvent)
{
    int32_t keyCode = keyEvent->GetKeyCode();
    int32_t action = keyEvent->GetKeyAction();

    // 1. 处理 finalKey 的事件
    if (keyCode == keyOption->GetFinalKey()) {
        // 1.1 检查 down 事件的条件
        if (action == 0) {  // down
            if (!MatchPreKeys(keyOption, keyEvent)) {
                return false;
            }
            if (!CheckDuration(keyOption, keyEvent)) {
                return false;
            }
        }

        // 1.2 所有 finalKey 事件都分发（down 和 up）
        MMI_HILOGD("ALL_RELEASED mode: dispatching finalKey event (action: %{public}d)", action);
        return true;
    }

    // 2. 处理 preKeys 的事件
    const auto& preKeys = keyOption->GetPreKeys();
    if (preKeys.find(keyCode) != preKeys.end()) {
        // 2.1 只分发 up 事件
        if (action == KeyEvent::KEY_ACTION_UP) {
            MMI_HILOGD("ALL_RELEASED mode: dispatching preKey up event (keyCode: %{public}d)", keyCode);
            return true;
        }
    }

    return false;
}

bool TriggerEventDispatcher::MatchPreKeys(std::shared_ptr<KeyOption> keyOption,
    std::shared_ptr<KeyEvent> keyEvent)
{
    const auto& preKeys = keyOption->GetPreKeys();
    if (preKeys.empty()) {
        return true;  // 没有 preKeys，自动匹配
    }

    // 获取所有按键项
    std::vector<KeyEvent::KeyItem> keyItems;
    if (!keyEvent->GetKeyItems(keyItems)) {
        MMI_HILOGE("Failed to get key items");
        return false;
    }

    // 检查是否包含所有 preKeys，且都处于 down 状态
    for (int32_t preKey : preKeys) {
        bool found = false;
        for (const auto& item : keyItems) {
            if (item.GetKeyCode() == preKey && item.GetAction() == KeyEvent::KEY_ACTION_DOWN) {
                found = true;
                break;
            }
        }
        if (!found) {
            MMI_HILOGD("PreKey not matched: %{public}d", preKey);
            return false;
        }
    }

    MMI_HILOGD("All preKeys matched");
    return true;
}

bool TriggerEventDispatcher::CheckDuration(std::shared_ptr<KeyOption> keyOption,
    std::shared_ptr<KeyEvent> keyEvent)
{
    int32_t duration = keyOption->GetFinalKeyDownDuration();
    // 1. 如果 duration 为 0，立即满足条件
    if (duration == 0) {
        MMI_HILOGD("Duration is 0, immediate trigger");
        return true;
    // 2. 生成订阅键
    std::string subscribeKey = GenerateSubscribeKey(keyOption);
    // 3. 检查是否在 duration 窗口内
    if (durationPassed_.find(subscribeKey) != durationPassed_.end()) {
        // duration 窗口已通过
        if (durationPassed_[subscribeKey]) {
            MMI_HILOGD("Duration window already passed");
            // 检查窗口内是否有其他按键
            if (!HasOtherKeyPressedInWindow(subscribeKey)) {
                MMI_HILOGD("No other key pressed in window");
                return true;
            } else {
                MMI_HILOGD("Other key pressed during duration window");
                return false;
            }
        } else {
            MMI_HILOGD("Duration window not yet passed");
            return false;
        }
    }

    // 4. 首次检查，启动 duration 窗口
    if (downStartTime_.find(subscribeKey) == downStartTime_.end()) {
        StartDurationWindow(subscribeKey, duration);
        MMI_HILOGD("Duration window started, will wait %{public}d microseconds", duration);
        return false;  // 等待定时器到期
    }

    // 5. duration 窗口还未到期
    MMI_HILOGD("Duration window not yet passed");
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
    // 1. 记录开始时间
    downStartTime_[subscribeKey] = GetSysClockTime();
    hasOtherKey_[subscribeKey] = false;

    // 2. 启动定时器（异步）
    std::thread([this, subscribeKey, duration]() {
        std::this_thread::sleep_for(std::chrono::microseconds(duration));

        std::lock_guard<std::mutex> lock(mutex_);

        // 检查窗口内是否有其他按键
        if (!hasOtherKey_[subscribeKey]) {
            // 没有其他按键，标记窗口通过
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
