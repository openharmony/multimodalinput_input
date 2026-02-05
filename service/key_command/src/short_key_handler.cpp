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

#include "short_key_handler.h"

#include "ability_launcher.h"
#include "bytrace_adapter.h"
#include "event_log_helper.h"
#include "dfx_hisysevent.h"
#include "i_input_windows_manager.h"
#include "key_command_handler_util.h"
#include "key_shortcut_manager.h"
#include "timer_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ShortKeyHandler"

namespace OHOS {
namespace MMI {
bool ShortKeyHandler::HandleShortKeys(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (context_.shortcutKeys_->empty()) {
        MMI_HILOGD("No shortkeys configuration data");
        return false;
    }
    if (!lastMatchedKeys_.empty()) {
        auto it = context_.shortcutKeys_->find(*lastMatchedKeys_.begin());
        if (it != context_.shortcutKeys_->end()) {
            MMI_HILOGD("it:%{public}s", it->first.c_str());
            if (IsKeyMatch(it->second, keyEvent)) {
                MMI_HILOGD("The same key is waiting timeout, skip");
                return true;
            }
        }
    }
    if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_VCR2 && WIN_MGR->JudgeCameraInFore()) {
        MMI_HILOGD("The camera has been activated");
        return false;
    }
    if (currentLaunchAbilityKey_.timerId >= 0 && IsKeyMatch(currentLaunchAbilityKey_, keyEvent)) {
        MMI_HILOGD("repeat, current key %d has launched ability", currentLaunchAbilityKey_.finalKey);
        return true;
    }
    DfxHisysevent::GetComboStartTime();
    for (const auto &lastkey : lastMatchedKeys_) {
        auto it = context_.shortcutKeys_->find(lastkey);
        if (it == context_.shortcutKeys_->end()) {
            continue;
        }
        auto &matchKey = it->second;
        if (matchKey.timerId >= 0) {
            MMI_HILOGD("Remove timer:%{public}d", matchKey.timerId);
            TimerMgr->RemoveTimer(matchKey.timerId);
            matchKey.timerId = -1;
        }
    }
    lastMatchedKeys_.clear();
    if (MatchShortcutKeys(keyEvent)) {
        return true;
    }
    return HandleConsumedKeyEvent(keyEvent);
}

bool ShortKeyHandler::MatchShortcutKeys(const std::shared_ptr<KeyEvent> keyEvent)
{
#ifdef SHORTCUT_KEY_RULES_ENABLED
    if ((keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) &&
        KEY_SHORTCUT_MGR->HaveShortcutConsumed(keyEvent)) {
        return false;
    }
#endif  // SHORTCUT_KEY_RULES_ENABLED
    bool result = false;
    std::vector<ShortcutKey> upAbilities;

    for (auto &item : *context_.shortcutKeys_) {
        result = MatchShortcutKey(keyEvent, item.second, upAbilities) || result;
    }
    if (!upAbilities.empty()) {
        std::sort(upAbilities.begin(), upAbilities.end(),
                  [](const ShortcutKey &lShortcutKey, const ShortcutKey &rShortcutKey) -> bool {
                      return lShortcutKey.keyDownDuration > rShortcutKey.keyDownDuration;
                  });
        ShortcutKey tmpShorteKey = upAbilities.front();
        MMI_HILOGI("Start launch ability immediately");
#ifdef SHORTCUT_KEY_RULES_ENABLED
        KEY_SHORTCUT_MGR->MarkShortcutConsumed(tmpShorteKey);
#endif  // SHORTCUT_KEY_RULES_ENABLED
        LaunchShortcutKeyAbility(tmpShorteKey);
    }
    if (result) {
        if (currentLaunchAbilityKey_.finalKey == keyEvent->GetKeyCode() &&
            keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
            ResetCurrentLaunchAbilityKey();
        }
    }
    return result;
}

bool ShortKeyHandler::MatchShortcutKey(std::shared_ptr<KeyEvent> keyEvent, ShortcutKey &shortcutKey,
                                       std::vector<ShortcutKey> &upAbilities)
{
    CALL_DEBUG_ENTER;
    if (!shortcutKey.statusConfigValue) {
        return false;
    }
    if (!IsKeyMatch(shortcutKey, keyEvent)) {
        MMI_HILOGD("Not key matched, next");
        return false;
    }
    int32_t delay = GetKeyDownDurationFromXml(shortcutKey.businessId);
    if (delay >= MIN_SHORT_KEY_DOWN_DURATION && delay <= MAX_SHORT_KEY_DOWN_DURATION) {
        MMI_HILOGD("User defined new short key down duration:%{public}d", delay);
        shortcutKey.keyDownDuration = delay;
    }

    if (shortcutKey.triggerType == KeyEvent::KEY_ACTION_DOWN) {
        return HandleKeyDown(shortcutKey);
    } else if (shortcutKey.triggerType == KeyEvent::KEY_ACTION_UP) {
        bool handleResult = HandleKeyUp(keyEvent, shortcutKey);
        if (handleResult && shortcutKey.keyDownDuration > 0) {
            upAbilities.push_back(shortcutKey);
        }
        return handleResult;
    } else {
        return HandleKeyCancel(shortcutKey);
    }
}

bool ShortKeyHandler::IsKeyMatch(const ShortcutKey &shortcutKey, const std::shared_ptr<KeyEvent> &key)
{
    CALL_DEBUG_ENTER;
    CHKPF(key);
    if ((key->GetKeyCode() != shortcutKey.finalKey) || (shortcutKey.triggerType != key->GetKeyAction())) {
        DfxHisysevent::ReportFailHandleKey("IsKeyMatch", key->GetKeyCode(),
            DfxHisysevent::KEY_ERROR_CODE::INVALID_PARAMETER);
        return false;
    }
    if ((shortcutKey.preKeys.size() + 1) != key->GetKeyItems().size()) {
        return false;
    }
    for (const auto &item : key->GetKeyItems()) {
        int32_t keyCode = item.GetKeyCode();
        if (SkipFinalKey(keyCode, key)) {
            continue;
        }
        if (shortcutKey.preKeys.find(keyCode) == shortcutKey.preKeys.end()) {
            return false;
        }
    }
    MMI_HILOGD("Leave, key matched");
    return true;
}

bool ShortKeyHandler::SkipFinalKey(const int32_t keyCode, const std::shared_ptr<KeyEvent> &key)
{
    CHKPF(key);
    return keyCode == key->GetKeyCode();
}

bool ShortKeyHandler::HandleKeyDown(ShortcutKey &shortcutKey)
{
    CALL_DEBUG_ENTER;
    if (shortcutKey.keyDownDuration == 0) {
        MMI_HILOGI("Start launch ability immediately");
#ifdef SHORTCUT_KEY_RULES_ENABLED
        KEY_SHORTCUT_MGR->MarkShortcutConsumed(shortcutKey);
#endif  // SHORTCUT_KEY_RULES_ENABLED
        LaunchShortcutKeyAbility(shortcutKey);
        return true;
    }
    shortcutKey.timerId = TimerMgr->AddTimer(shortcutKey.keyDownDuration, 1, [this, &shortcutKey]() {
            MMI_HILOGI("Timer callback");
#ifdef SHORTCUT_KEY_RULES_ENABLED
            KEY_SHORTCUT_MGR->MarkShortcutConsumed(shortcutKey);
#endif  // SHORTCUT_KEY_RULES_ENABLED
            currentLaunchAbilityKey_ = shortcutKey;
            shortcutKey.timerId = -1;
            LaunchShortcutKeyAbility(shortcutKey);
        }, "ShortKeyHandler-HandleKeyDown");
    if (shortcutKey.timerId < 0) {
        MMI_HILOGE("Add Timer failed");
        DfxHisysevent::ReportFailLaunchAbility(shortcutKey.ability.bundleName,
            DfxHisysevent::KEY_ERROR_CODE::FAILED_TIMER);
        return false;
    }
    MMI_HILOGI("Add timer success");
    lastMatchedKeys_.insert(shortcutKey.key);
    auto handler = InputHandler->GetSubscriberHandler();
    CHKPF(handler);
    if (handler->IsKeyEventSubscribed(shortcutKey.finalKey, shortcutKey.triggerType)) {
        MMI_HILOGI("Current shortcutKey %d is subSubcribed", shortcutKey.finalKey);
        return false;
    }
    return true;
}

bool ShortKeyHandler::HandleKeyUp(const std::shared_ptr<KeyEvent> &keyEvent, const ShortcutKey &shortcutKey)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (shortcutKey.keyDownDuration == 0) {
        MMI_HILOGI("Start launch ability immediately");
        LaunchShortcutKeyAbility(shortcutKey);
        return true;
    }
    std::optional<KeyEvent::KeyItem> keyItem = keyEvent->GetKeyItem();
    if (!keyItem) {
        MMI_HILOGE("The keyItem is nullopt");
        return false;
    }
    auto upTime = keyEvent->GetActionTime();
    auto downTime = keyItem->GetDownTime();
    MMI_HILOGI("The upTime:%{public}" PRId64 ",downTime:%{public}" PRId64 ",keyDownDuration:%{public}d", upTime,
               downTime, shortcutKey.keyDownDuration);
    int64_t frequency = 1000;
    if (upTime - downTime <= static_cast<int64_t>(shortcutKey.keyDownDuration) * frequency) {
        MMI_HILOGI("Skip, upTime - downTime <= duration");
        return false;
    }
    return true;
}

bool ShortKeyHandler::HandleKeyCancel(ShortcutKey &shortcutKey)
{
    CALL_DEBUG_ENTER;
    if (shortcutKey.timerId < 0) {
        DfxHisysevent::ReportFailHandleKey("HandleKeyCancel", shortcutKey.finalKey,
            DfxHisysevent::KEY_ERROR_CODE::INVALID_PARAMETER);
        MMI_HILOGE("Skip, timerid less than 0");
    }
    auto timerId = shortcutKey.timerId;
    shortcutKey.timerId = -1;
    TimerMgr->RemoveTimer(timerId);
    MMI_HILOGI("The timerId:%{public}d", timerId);
    return false;
}

bool ShortKeyHandler::HandleConsumedKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (currentLaunchAbilityKey_.finalKey == keyEvent->GetKeyCode() &&
        keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        MMI_HILOGI("Handle consumed key event, cancel opration");
        ResetCurrentLaunchAbilityKey();
        context_.repeatKey_.keyCode = -1;
        context_.repeatKey_.keyAction = -1;
        auto keyEventCancel = std::make_shared<KeyEvent>(*keyEvent);
        keyEventCancel->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
        auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
        CHKPF(inputEventNormalizeHandler);
        inputEventNormalizeHandler->HandleKeyEvent(keyEventCancel);
        return true;
    }
    return false;
}

void ShortKeyHandler::ResetCurrentLaunchAbilityKey()
{
    currentLaunchAbilityKey_.preKeys.clear();
    currentLaunchAbilityKey_.finalKey = -1;
    currentLaunchAbilityKey_.timerId = -1;
    currentLaunchAbilityKey_.keyDownDuration = 0;
}

int32_t ShortKeyHandler::GetKeyDownDurationFromXml(const std::string &businessId)
{
    CALL_DEBUG_ENTER;
    return PREFERENCES_MGR->GetShortKeyDuration(businessId);
}

void ShortKeyHandler::LaunchShortcutKeyAbility(const ShortcutKey &shortcutKey)
{
    BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_SHORTKEY, shortcutKey.ability.bundleName);
    LAUNCHER_ABILITY->LaunchAbility(shortcutKey.ability, shortcutKey.keyDownDuration);
    DfxHisysevent::ReportKeyEvent(shortcutKey.ability.bundleName);
    BytraceAdapter::StopLaunchAbility();
}
}  // namespace MMI
}  // namespace OHOS