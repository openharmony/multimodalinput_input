/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "key_shortcut_manager.h"

#include <config_policy_utils.h>

#include "app_state_observer.h"
#include "define_multimodal.h"
#include "key_command_handler_util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyShortcutManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t SINGLE_MODIFIER { 1 };
constexpr size_t MAX_N_PRINTABLE_ITEMS { 3 };
constexpr int32_t MAXIMUM_LONG_PRESS_TIME { 60000 }; // 60s
constexpr int32_t REPEAT_ONCE { 1 };
}

std::mutex KeyShortcutManager::mutex_;
std::shared_ptr<KeyShortcutManager> KeyShortcutManager::instance_;

const std::map<int32_t, uint32_t> KeyShortcutManager::modifiers_ {
    { KeyEvent::KEYCODE_ALT_LEFT, SHORTCUT_MODIFIER_ALT },
    { KeyEvent::KEYCODE_ALT_RIGHT, SHORTCUT_MODIFIER_ALT },
    { KeyEvent::KEYCODE_SHIFT_LEFT, SHORTCUT_MODIFIER_SHIFT },
    { KeyEvent::KEYCODE_SHIFT_RIGHT, SHORTCUT_MODIFIER_SHIFT },
    { KeyEvent::KEYCODE_CTRL_LEFT, SHORTCUT_MODIFIER_CTRL },
    { KeyEvent::KEYCODE_CTRL_RIGHT, SHORTCUT_MODIFIER_CTRL },
    { KeyEvent::KEYCODE_META_LEFT, SHORTCUT_MODIFIER_LOGO },
    { KeyEvent::KEYCODE_META_RIGHT, SHORTCUT_MODIFIER_LOGO }
};

bool KeyShortcutManager::SystemKey::operator<(const SystemKey &other) const
{
    uint32_t modifier1 = (modifiers & SHORTCUT_MODIFIER_MASK);
    uint32_t modifier2 = (other.modifiers & SHORTCUT_MODIFIER_MASK);
    if (modifier1 != modifier2) {
        return (modifier1 < modifier2);
    }
    return (finalKey < other.finalKey);
}

bool KeyShortcutManager::ExceptionalSystemKey::operator<(const ExceptionalSystemKey &other) const
{
    if (finalKey != other.finalKey) {
        return (finalKey < other.finalKey);
    }
    if (longPressTime != other.longPressTime) {
        return (longPressTime < other.longPressTime);
    }
    if (triggerType != other.triggerType) {
        return (triggerType < other.triggerType);
    }
    return (preKeys < other.preKeys);
}

std::shared_ptr<KeyShortcutManager> KeyShortcutManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<KeyShortcutManager>();
        }
    }
    return instance_;
}

KeyShortcutManager::KeyShortcutManager()
{
    LoadSystemKeys();
    LoadExceptionalSystemKeys();
}

int32_t KeyShortcutManager::RegisterSystemKey(const SystemShortcutKey &key)
{
    KeyShortcut shortcut {};

    if (!CheckSystemKey(key, shortcut)) {
        MMI_HILOGE("Not system key ([%{public}s],FinalKey:%{public}d,PressTime:%{public}d,TriggerType:%{public}d)",
            FormatModifiers(key.modifiers).c_str(), key.finalKey, key.longPressTime, key.triggerType);
        ExceptionalSystemKey eSysKey {
            .preKeys = key.modifiers,
            .finalKey = key.finalKey,
            .longPressTime = key.longPressTime,
            .triggerType = key.triggerType,
        };
        if (IsExceptionalSystemKey(eSysKey)) {
            auto shortcutId = GenerateId();
            MMI_HILOGI("Register exceptional system key [No.%{public}d]"
                "([%{public}s],FinalKey:%{public}d,PressTime:%{public}d,TriggerType:%{public}d)",
                shortcutId, FormatModifiers(key.modifiers).c_str(), key.finalKey, key.longPressTime, key.triggerType);
            return shortcutId;
        }
        return KEY_SHORTCUT_ERROR_COMBINATION_KEY;
    }
    if (IsReservedSystemKey(shortcut)) {
        MMI_HILOGE("Can not register reserved system key ([%{public}s],%{public}d)",
            FormatModifiers(key.modifiers).c_str(), key.finalKey);
        return KEY_SHORTCUT_ERROR_COMBINATION_KEY;
    }
    auto [iter, _] = shortcuts_.emplace(GenerateId(), shortcut);
    MMI_HILOGI("Register system key [No.%{public}d](0x%{public}x,%{public}d,%{public}d,%{public}d,%{public}d)",
        iter->first, shortcut.modifiers, shortcut.finalKey, shortcut.longPressTime,
        shortcut.triggerType, shortcut.session);
    return iter->first;
}

void KeyShortcutManager::UnregisterSystemKey(int32_t shortcutId)
{
    auto iter = shortcuts_.find(shortcutId);
    if (iter == shortcuts_.end()) {
        MMI_HILOGI("There is no system key(%{public}d)", shortcutId);
        return;
    }
    const KeyShortcut &key = iter->second;
    MMI_HILOGI("Unregister system key(0x%{public}x,%{public}d,%{public}d,%{public}d,SESSION:%{public}d)",
        key.modifiers, key.finalKey, key.longPressTime, key.triggerType, key.session);
    ResetTriggering(shortcutId);
    shortcuts_.erase(iter);
}

int32_t KeyShortcutManager::RegisterHotKey(const HotKey &key)
{
    KeyShortcut globalKey {};

    if (!CheckGlobalKey(key, globalKey)) {
        MMI_HILOGE("Not global shortcut key");
        return KEY_SHORTCUT_ERROR_COMBINATION_KEY;
    }
    if (HaveRegisteredGlobalKey(globalKey)) {
        MMI_HILOGE("Global key (0x%{public}x, %{public}d) has been taken", globalKey.modifiers, globalKey.finalKey);
        return KEY_SHORTCUT_ERROR_TAKEN;
    }
    auto [iter, _] = shortcuts_.emplace(GenerateId(), globalKey);
    MMI_HILOGI("Register global key [No.%{public}d](0x%{public}x,%{public}d,SESSION:%{public}d)",
        iter->first, globalKey.modifiers, globalKey.finalKey, globalKey.session);
    return iter->first;
}

void KeyShortcutManager::UnregisterHotKey(int32_t shortcutId)
{
    auto iter = shortcuts_.find(shortcutId);
    if (iter == shortcuts_.end()) {
        MMI_HILOGI("There is no global key(%{public}d)", shortcutId);
        return;
    }
    const KeyShortcut &key = iter->second;
    MMI_HILOGI("Unregister global key(0x%{public}x,%{public}d,SESSION:%{public}d)",
        key.modifiers, key.finalKey, key.session);
    shortcuts_.erase(iter);
}

bool KeyShortcutManager::HandleEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    MMI_HILOGI("Handle key event(No.%{public}d,KC:%{public}d,KA:%{public}d,PressedKeys:[%{public}s])",
        keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetKeyAction(), FormatPressedKeys(keyEvent).c_str());
    ResetTriggering(keyEvent);
    if (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        return HandleKeyDown(keyEvent);
    } else if (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        return HandleKeyUp(keyEvent);
    } else if (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_CANCEL) {
        return HandleKeyCancel(keyEvent);
    }
    return false;
}

void KeyShortcutManager::LoadSystemKeys()
{
    char cfgName[] { "etc/multimodalinput/system_keys_config.json" };
    char buf[MAX_PATH_LEN] {};
    char *cfgPath = ::GetOneCfgFile(cfgName, buf, sizeof(buf));

    if (cfgPath == nullptr) {
        MMI_HILOGE("No '%{public}s' was found", cfgPath);
        return;
    }
    MMI_HILOGI("Config of system keys:%{public}s", cfgPath);
    ReadSystemKeys(std::string(cfgPath));
}

void KeyShortcutManager::ReadSystemKeys(const std::string &cfgPath)
{
    std::string cfg = ReadJsonFile(cfgPath);
    JsonParser parser;
    parser.json_ = cJSON_Parse(cfg.c_str());
    if (!cJSON_IsObject(parser.json_)) {
        MMI_HILOGE("Not json format");
        return;
    }
    cJSON* jsonSysKeys = cJSON_GetObjectItemCaseSensitive(parser.json_, "SystemKeys");
    if (!cJSON_IsArray(jsonSysKeys)) {
        MMI_HILOGE("jsonSysKeys is not array");
        return;
    }
    int32_t nSysKeys = cJSON_GetArraySize(jsonSysKeys);
    for (int32_t index = 0; index < nSysKeys; ++index) {
        cJSON *jsonSysKey = cJSON_GetArrayItem(jsonSysKeys, index);
        ReadSystemKey(jsonSysKey);
    }
}

int32_t KeyShortcutManager::ReadSystemKey(cJSON *jsonSysKey)
{
    if (!cJSON_IsObject(jsonSysKey)) {
        MMI_HILOGE("Not json object");
        return KEY_SHORTCUT_ERROR_CONFIG;
    }
    cJSON *jsonPreKeys = cJSON_GetObjectItem(jsonSysKey, "preKeys");
    if (!cJSON_IsArray(jsonPreKeys)) {
        MMI_HILOGE("Expect array for PreKeys");
        return KEY_SHORTCUT_ERROR_CONFIG;
    }
    std::set<int32_t> preKeys;
    int32_t nPreKeys = cJSON_GetArraySize(jsonPreKeys);

    for (int32_t index = 0; index < nPreKeys; ++index) {
        cJSON *jsonPreKey = cJSON_GetArrayItem(jsonPreKeys, index);
        if (!cJSON_IsNumber(jsonPreKey)) {
            MMI_HILOGE("Expect number for PreKey");
            return KEY_SHORTCUT_ERROR_CONFIG;
        }
        preKeys.insert(static_cast<int32_t>(cJSON_GetNumberValue(jsonPreKey)));
    }
    cJSON *jsonFinalKey = cJSON_GetObjectItem(jsonSysKey, "finalKey");
    if (!cJSON_IsNumber(jsonFinalKey)) {
        MMI_HILOGE("Expect number for FinalKey");
        return KEY_SHORTCUT_ERROR_CONFIG;
    }
    int32_t finalKey = static_cast<int32_t>(cJSON_GetNumberValue(jsonFinalKey));
    return AddSystemKey(preKeys, finalKey);
}

int32_t KeyShortcutManager::AddSystemKey(const std::set<int32_t> &preKeys, int32_t finalKey)
{
    SystemShortcutKey sysKey {
        .modifiers = preKeys,
        .finalKey = finalKey,
    };
    KeyShortcut shortcut {};

    if (!CheckSystemKey(sysKey, shortcut)) {
        MMI_HILOGE("Not system key ([%{public}s],%{public}d)", FormatModifiers(preKeys).c_str(), finalKey);
        return KEY_SHORTCUT_ERROR_COMBINATION_KEY;
    }
    systemKeys_.emplace(SystemKey {
        .modifiers = shortcut.modifiers,
        .finalKey = shortcut.finalKey,
    });
    return RET_OK;
}

void KeyShortcutManager::LoadExceptionalSystemKeys()
{
    char cfgName[] { "etc/multimodalinput/exceptional_system_keys_config.json" };
    char buf[MAX_PATH_LEN] {};
    char *cfgPath = ::GetOneCfgFile(cfgName, buf, sizeof(buf));

    if (cfgPath == nullptr) {
        MMI_HILOGE("No '%{public}s' was found", cfgPath);
        return;
    }
    MMI_HILOGI("Config of exceptional system keys:%{public}s", cfgPath);
    ReadExceptionalSystemKeys(std::string(cfgPath));
}

void KeyShortcutManager::ReadExceptionalSystemKeys(const std::string &cfgPath)
{
    std::string cfg = ReadJsonFile(cfgPath);
    JsonParser parser;
    parser.json_ = cJSON_Parse(cfg.c_str());
    if (!cJSON_IsObject(parser.json_)) {
        MMI_HILOGE("Not json format");
        return;
    }
    cJSON* jsonSysKeys = cJSON_GetObjectItemCaseSensitive(parser.json_, "ExceptionalSystemKeys");
    if (!cJSON_IsArray(jsonSysKeys)) {
        MMI_HILOGE("jsonSysKeys is not array");
        return;
    }
    int32_t nSysKeys = cJSON_GetArraySize(jsonSysKeys);
    for (int32_t index = 0; index < nSysKeys; ++index) {
        cJSON *jsonSysKey = cJSON_GetArrayItem(jsonSysKeys, index);
        ReadExceptionalSystemKey(jsonSysKey);
    }
}

int32_t KeyShortcutManager::ReadExceptionalSystemKey(cJSON *jsonSysKey)
{
    if (!cJSON_IsObject(jsonSysKey)) {
        MMI_HILOGE("Not json object");
        return KEY_SHORTCUT_ERROR_CONFIG;
    }
    ExceptionalSystemKey sysKey {};
    cJSON *jsonPreKeys = cJSON_GetObjectItem(jsonSysKey, "preKeys");
    if (!cJSON_IsArray(jsonPreKeys)) {
        MMI_HILOGE("Expect array for PreKeys");
        return KEY_SHORTCUT_ERROR_CONFIG;
    }
    int32_t nPreKeys = cJSON_GetArraySize(jsonPreKeys);

    for (int32_t index = 0; index < nPreKeys; ++index) {
        cJSON *jsonPreKey = cJSON_GetArrayItem(jsonPreKeys, index);
        if (!cJSON_IsNumber(jsonPreKey)) {
            MMI_HILOGE("Expect number for PreKey");
            return KEY_SHORTCUT_ERROR_CONFIG;
        }
        sysKey.preKeys.insert(static_cast<int32_t>(cJSON_GetNumberValue(jsonPreKey)));
    }
    cJSON *jsonFinalKey = cJSON_GetObjectItem(jsonSysKey, "finalKey");
    if (!cJSON_IsNumber(jsonFinalKey)) {
        MMI_HILOGE("Expect number for FinalKey");
        return KEY_SHORTCUT_ERROR_CONFIG;
    }
    sysKey.finalKey = static_cast<int32_t>(cJSON_GetNumberValue(jsonFinalKey));

    cJSON *jsonPressTime = cJSON_GetObjectItem(jsonSysKey, "longPressTime");
    if (!cJSON_IsNumber(jsonPressTime)) {
        MMI_HILOGE("Expect number for LongPressTime");
        return KEY_SHORTCUT_ERROR_CONFIG;
    }
    sysKey.longPressTime = static_cast<int32_t>(cJSON_GetNumberValue(jsonPressTime));

    cJSON *jsonTriggerType = cJSON_GetObjectItem(jsonSysKey, "triggerType");
    char *triggerType = cJSON_GetStringValue(jsonTriggerType);
    if ((triggerType == nullptr) ||
        ((std::strcmp(triggerType, "down") != 0) && (std::strcmp(triggerType, "up") != 0))) {
        MMI_HILOGE("Expect down/up for TriggerType");
        return KEY_SHORTCUT_ERROR_CONFIG;
    }
    sysKey.triggerType = (std::strcmp(triggerType, "down") == 0 ?
                          SHORTCUT_TRIGGER_TYPE_DOWN : SHORTCUT_TRIGGER_TYPE_UP);

    AddExceptionalSystemKey(sysKey);
    return RET_OK;
}

void KeyShortcutManager::AddExceptionalSystemKey(const ExceptionalSystemKey &sysKey)
{
    MMI_HILOGI("Add exceptional system key ([%{public}s],FinalKey:%{public}d,PressTime:%{public}d,%{public}s)",
        FormatModifiers(sysKey.preKeys).c_str(), sysKey.finalKey, sysKey.longPressTime,
        (sysKey.triggerType == SHORTCUT_TRIGGER_TYPE_DOWN ? "down" : "up"));
    exceptSysKeys_.emplace(sysKey);
}

std::string KeyShortcutManager::FormatModifiers(const std::set<int32_t> &modifiers) const
{
    std::ostringstream sModifiers;
    size_t nModifiers = 0;

    if (auto iter = modifiers.cbegin(); iter != modifiers.cend()) {
        sModifiers << *iter;
        ++nModifiers;

        for (++iter; iter != modifiers.cend(); ++iter) {
            if (nModifiers > MAX_N_PRINTABLE_ITEMS) {
                sModifiers << ",...";
                break;
            }
            sModifiers << "," << *iter;
            ++nModifiers;
        }
    }
    return sModifiers.str();
}

int32_t KeyShortcutManager::GenerateId() const
{
    static int32_t baseId {};
    return ++baseId;
}

bool KeyShortcutManager::IsExceptionalSystemKey(const ExceptionalSystemKey &sysKey) const
{
    return (exceptSysKeys_.find(sysKey) != exceptSysKeys_.cend());
}

bool KeyShortcutManager::IsModifier(int32_t keyCode) const
{
    return (modifiers_.find(keyCode) != modifiers_.cend());
}

bool KeyShortcutManager::IsValid(const ShortcutTriggerType triggerType) const
{
    return ((triggerType == SHORTCUT_TRIGGER_TYPE_DOWN) ||
            (triggerType == SHORTCUT_TRIGGER_TYPE_UP));
}

bool KeyShortcutManager::IsReservedSystemKey(const KeyShortcut &shortcut) const
{
    return (systemKeys_.find(SystemKey {
        .modifiers = shortcut.modifiers,
        .finalKey = shortcut.finalKey,
    }) != systemKeys_.cend());
}

bool KeyShortcutManager::CheckSystemKey(const SystemShortcutKey &key, KeyShortcut &shortcut) const
{
    size_t nModifiers = 0;
    uint32_t modifiers = 0U;

    for (auto keyCode : key.modifiers) {
        auto iter = modifiers_.find(keyCode);
        if (iter == modifiers_.end()) {
            MMI_HILOGE("Key code (%{public}d) is not modifier", keyCode);
            return false;
        }
        if ((modifiers & iter->second) != iter->second) {
            modifiers |= iter->second;
            ++nModifiers;
        }
    }
    if (nModifiers < SINGLE_MODIFIER) {
        MMI_HILOGE("Require modifier(s)");
        return false;
    }
    if (key.finalKey == SHORTCUT_PURE_MODIFIERS) {
        if ((nModifiers == SINGLE_MODIFIER) && (modifiers != SHORTCUT_MODIFIER_LOGO)) {
            MMI_HILOGE("Only 'Logo' can be one-key shortcut");
            return false;
        }
    } else if (IsModifier(key.finalKey)) {
        MMI_HILOGE("Modifier as final key");
        return false;
    }
    if (!IsValid(key.triggerType)) {
        MMI_HILOGE("Invalid trigger type(%{public}d)", key.triggerType);
        return false;
    }
    if ((key.longPressTime < 0) || (key.longPressTime > MAXIMUM_LONG_PRESS_TIME)) {
        MMI_HILOGE("Long-press time(%{public}d) is out of range [0,%{public}d]",
            key.longPressTime, MAXIMUM_LONG_PRESS_TIME);
        return false;
    }
    shortcut = KeyShortcut {
        .modifiers = modifiers,
        .finalKey = key.finalKey,
        .longPressTime = key.longPressTime,
        .triggerType = key.triggerType,
        .session = key.session,
        .callback = key.callback,
    };
    return true;
}

bool KeyShortcutManager::CheckGlobalKey(const HotKey &key, KeyShortcut &shortcut) const
{
    size_t nModifiers = 0;
    uint32_t modifiers = 0U;

    for (auto keyCode : key.modifiers) {
        auto iter = modifiers_.find(keyCode);
        if (iter == modifiers_.end()) {
            MMI_HILOGE("Key code (%{public}d) is not modifier", keyCode);
            return false;
        }
        if ((modifiers & iter->second) != iter->second) {
            modifiers |= iter->second;
            ++nModifiers;
        }
    }
    if (IsModifier(key.finalKey)) {
        MMI_HILOGE("FinalKey(%{public}d) should not be modifier", key.finalKey);
        return false;
    }
    if (key.finalKey == SHORTCUT_PURE_MODIFIERS) {
        MMI_HILOGE("Expect FinalKey");
        return false;
    }
    if (modifiers & SHORTCUT_MODIFIER_LOGO) {
        MMI_HILOGE("'LOGO' is not allowed for GlobalKey");
        return false;
    }
    if (nModifiers < SINGLE_MODIFIER) {
        MMI_HILOGE("Require modifier(s)");
        return false;
    }
    shortcut = KeyShortcut {
        .modifiers = modifiers,
        .finalKey = key.finalKey,
        .triggerType = SHORTCUT_TRIGGER_TYPE_DOWN,
        .session = key.session,
        .callback = key.callback,
    };
    return true;
}

bool KeyShortcutManager::HaveRegisteredGlobalKey(const KeyShortcut &key) const
{
    return (
        std::any_of(shortcuts_.cbegin(), shortcuts_.cend(),
            [&key](const auto &item) {
                return ((item.second.modifiers == key.modifiers) &&
                        (item.second.finalKey == key.finalKey));
            }) ||
        std::any_of(systemKeys_.cbegin(), systemKeys_.cend(),
            [&key](const auto &item) {
                return ((item.modifiers == key.modifiers) &&
                        (item.finalKey == key.finalKey));
            })
    );
}

std::string KeyShortcutManager::FormatPressedKeys(std::shared_ptr<KeyEvent> keyEvent) const
{
    auto pressedKeys = keyEvent->GetPressedKeys();
    std::ostringstream sPressedKeys;
    size_t nPressedKeys = 0;

    if (auto iter = pressedKeys.cbegin(); iter != pressedKeys.cend()) {
        sPressedKeys << *iter;
        ++nPressedKeys;

        for (++iter; iter != pressedKeys.cend(); ++iter) {
            if (nPressedKeys > MAX_N_PRINTABLE_ITEMS) {
                sPressedKeys << ",...";
                break;
            }
            sPressedKeys << "," << *iter;
            ++nPressedKeys;
        }
    }
    return sPressedKeys.str();
}

std::set<int32_t> KeyShortcutManager::GetForegroundPids() const
{
    std::vector<AppExecFwk::AppStateData> foregroundApps = APP_OBSERVER_MGR->GetForegroundAppData();
    std::set<int32_t> foregroundPids;

    for (auto &item : foregroundApps) {
        foregroundPids.insert(item.pid);
    }
    std::set<int32_t> tForegroundPids;

    for (const auto &shortcut : shortcuts_) {
        if (foregroundPids.find(shortcut.second.session) != foregroundPids.cend()) {
            tForegroundPids.insert(shortcut.second.session);
        }
    }
    std::ostringstream sPids;

    if (auto iter = tForegroundPids.cbegin(); iter != tForegroundPids.cend()) {
        sPids << *iter;
        for (++iter; iter != tForegroundPids.cend(); ++iter) {
            sPids << "," << *iter;
        }
    }
    MMI_HILOGI("Foreground pids: [%{public}s]", sPids.str().c_str());
    return tForegroundPids;
}

bool KeyShortcutManager::HandleKeyDown(std::shared_ptr<KeyEvent> keyEvent)
{
    bool handled = false;
    std::set<int32_t> foregroundPids = GetForegroundPids();

    for (auto &item : shortcuts_) {
        KeyShortcut &shortcut = item.second;
        if (shortcut.triggerType != SHORTCUT_TRIGGER_TYPE_DOWN) {
            continue;
        }
        if (!foregroundPids.empty() &&
            (foregroundPids.find(shortcut.session) == foregroundPids.cend())) {
            continue;
        }
        if (!CheckCombination(keyEvent, shortcut)) {
            continue;
        }
        MMI_HILOGI("Matched shortcut[No.%{public}d]"
            "(0x%{public}x,%{public}d,%{public}d,%{public}d,SESSION:%{public}d)",
            item.first, shortcut.modifiers, shortcut.finalKey, shortcut.longPressTime,
            shortcut.triggerType, shortcut.session);
        TriggerDown(keyEvent, item.first, shortcut);
        handled = true;
    }
    return handled;
}

bool KeyShortcutManager::HandleKeyUp(std::shared_ptr<KeyEvent> keyEvent)
{
    bool handled = false;
    std::set<int32_t> foregroundPids = GetForegroundPids();

    for (auto &item : shortcuts_) {
        KeyShortcut &shortcut = item.second;
        if (shortcut.triggerType != SHORTCUT_TRIGGER_TYPE_UP) {
            continue;
        }
        if (!foregroundPids.empty() &&
            (foregroundPids.find(shortcut.session) == foregroundPids.cend())) {
            continue;
        }
        if (!CheckCombination(keyEvent, shortcut)) {
            continue;
        }
        MMI_HILOGI("Matched shortcut(0x%{public}x,%{public}d,%{public}d,%{public}d,SESSION:%{public}d)",
            shortcut.modifiers, shortcut.finalKey, shortcut.longPressTime, shortcut.triggerType, shortcut.session);
        TriggerUp(keyEvent, item.first, shortcut);
        handled = true;
    }
    return handled;
}

bool KeyShortcutManager::HandleKeyCancel(std::shared_ptr<KeyEvent> keyEvent)
{
    ResetAll();
    return false;
}

bool KeyShortcutManager::CheckCombination(std::shared_ptr<KeyEvent> keyEvent, const KeyShortcut &shortcut) const
{
    return (((shortcut.finalKey == SHORTCUT_PURE_MODIFIERS) && CheckPureModifiers(keyEvent, shortcut)) ||
            ((shortcut.finalKey == keyEvent->GetKeyCode()) && CheckModifiers(keyEvent, shortcut)));
}

bool KeyShortcutManager::CheckPureModifiers(std::shared_ptr<KeyEvent> keyEvent, const KeyShortcut &shortcut) const
{
    auto iter = modifiers_.find(keyEvent->GetKeyCode());
    if (iter == modifiers_.cend()) {
        return false;
    }
    uint32_t modifiers = (shortcut.modifiers & ~iter->second);
    auto pressedKeys = keyEvent->GetPressedKeys();

    for (auto keyCode : pressedKeys) {
        if (auto iter = modifiers_.find(keyCode); iter != modifiers_.cend()) {
            modifiers &= ~iter->second;
        }
    }
    return (modifiers == 0U);
}

bool KeyShortcutManager::CheckModifiers(std::shared_ptr<KeyEvent> keyEvent, const KeyShortcut &shortcut) const
{
    uint32_t modifiers = shortcut.modifiers;
    auto pressedKeys = keyEvent->GetPressedKeys();

    for (auto keyCode : pressedKeys) {
        if (auto iter = modifiers_.find(keyCode); iter != modifiers_.cend()) {
            modifiers &= ~iter->second;
        }
    }
    return (modifiers == 0U);
}

void KeyShortcutManager::TriggerDown(
    std::shared_ptr<KeyEvent> keyEvent, int32_t shortcutId, const KeyShortcut &shortcut)
{
    if (shortcut.longPressTime <= 0) {
        MMI_HILOGI("Run shortcut[No.%{public}d]", shortcutId);
        if (shortcut.callback != nullptr) {
            shortcut.callback(keyEvent);
        }
    } else {
        if (triggering_.find(shortcutId) != triggering_.cend()) {
            MMI_HILOGI("Shortcut[No.%{public}d]"
                "(0x%{public}x,%{public}d,%{public}d,%{public}d,SESSION:%{public}d) is pending",
                shortcutId, shortcut.modifiers, shortcut.finalKey, shortcut.longPressTime,
                shortcut.triggerType, shortcut.session);
            return;
        }
        auto timerId = TimerMgr->AddTimer(shortcut.longPressTime, REPEAT_ONCE,
            [this, tKeyEvent = KeyEvent::Clone(keyEvent), shortcutId]() {
                triggering_.erase(shortcutId);
                RunShortcut(tKeyEvent, shortcutId);
            });
        if (timerId < 0) {
            MMI_HILOGE("AddTimer fail");
            return;
        }
        triggering_.emplace(shortcutId, timerId);
    }
}

void KeyShortcutManager::RunShortcut(std::shared_ptr<KeyEvent> keyEvent, int32_t shortcutId)
{
    if (auto iter = shortcuts_.find(shortcutId); iter != shortcuts_.end()) {
        std::set<int32_t> foregroundPids = GetForegroundPids();
        if (!foregroundPids.empty() &&
            (foregroundPids.find(iter->second.session) == foregroundPids.cend())) {
            MMI_HILOGI("Session(%{public}d) is not foreground, skip running shortcut[%{public}d]",
                iter->second.session, shortcutId);
            return;
        }
        MMI_HILOGI("Run shortcut[No.%{public}d]", shortcutId);
        if (iter->second.callback != nullptr) {
            iter->second.callback(keyEvent);
        }
    }
}

void KeyShortcutManager::TriggerUp(
    std::shared_ptr<KeyEvent> keyEvent, int32_t shortcutId, const KeyShortcut &shortcut)
{
    if (shortcut.longPressTime > 0) {
        std::optional<KeyEvent::KeyItem> keyItem = keyEvent->GetKeyItem();
        if (!keyItem) {
            MMI_HILOGE("Corrupted key event");
            return;
        }
        auto upTime = keyEvent->GetActionTime();
        auto downTime = keyItem->GetDownTime();
        if (upTime - downTime < MS2US(shortcut.longPressTime)) {
            MMI_HILOGE("upTime - downTime < duration");
            return;
        }
    }
    if (shortcut.callback != nullptr) {
        shortcut.callback(keyEvent);
    }
}

void KeyShortcutManager::ResetAll()
{
    for (auto &item : triggering_) {
        TimerMgr->RemoveTimer(item.second);
    }
    triggering_.clear();
}

bool KeyShortcutManager::HaveShortcutConsumed(std::shared_ptr<KeyEvent> keyEvent)
{
    return (shortcutConsumed_.find(keyEvent->GetKeyCode()) != shortcutConsumed_.cend());
}

void KeyShortcutManager::UpdateShortcutConsumed(std::shared_ptr<KeyEvent> keyEvent)
{
    if (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        shortcutConsumed_.erase(keyEvent->GetKeyCode());
    }
}

void KeyShortcutManager::MarkShortcutConsumed(const ShortcutKey &shortcut)
{
    std::for_each(shortcut.preKeys.cbegin(), shortcut.preKeys.cend(),
        [this](auto keyCode) {
            shortcutConsumed_.emplace(keyCode);
        });
    if (shortcut.triggerType == KeyEvent::KEY_ACTION_DOWN) {
        shortcutConsumed_.emplace(shortcut.finalKey);
    }
}

void KeyShortcutManager::MarkShortcutConsumed(const KeyOption &shortcut)
{
    auto preKeys = shortcut.GetPreKeys();

    std::for_each(preKeys.cbegin(), preKeys.cend(),
        [this](auto keyCode) {
            shortcutConsumed_.emplace(keyCode);
        });
    if (shortcut.IsFinalKeyDown()) {
        shortcutConsumed_.emplace(shortcut.GetFinalKey());
    }
    shortcutConsumed_.erase(KeyEvent::KEYCODE_VOLUME_UP);
    shortcutConsumed_.erase(KeyEvent::KEYCODE_VOLUME_DOWN);
    shortcutConsumed_.erase(KeyEvent::KEYCODE_POWER);
}

void KeyShortcutManager::ResetTriggering(std::shared_ptr<KeyEvent> keyEvent)
{
    if (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        for (auto iter = triggering_.cbegin(); iter != triggering_.cend();) {
            auto shortcutIter = shortcuts_.find(iter->first);
            if ((shortcutIter != shortcuts_.cend()) &&
                WillResetOnKeyDown(keyEvent->GetKeyCode(), shortcutIter->second)) {
                MMI_HILOGI("Reset triggering shortcut[%{public}d]", iter->first);
                TimerMgr->RemoveTimer(iter->second);
                iter = triggering_.erase(iter);
            } else {
                ++iter;
            }
        }
    } else {
        for (auto iter = triggering_.cbegin(); iter != triggering_.cend();) {
            auto shortcutIter = shortcuts_.find(iter->first);
            if ((shortcutIter != shortcuts_.cend()) &&
                WillResetOnKeyUp(keyEvent->GetKeyCode(), shortcutIter->second)) {
                MMI_HILOGI("Reset triggering shortcut[%{public}d]", iter->first);
                TimerMgr->RemoveTimer(iter->second);
                iter = triggering_.erase(iter);
            } else {
                ++iter;
            }
        }
    }
}

bool KeyShortcutManager::WillResetOnKeyDown(int32_t keyCode, const KeyShortcut &shortcut) const
{
    if (keyCode == shortcut.finalKey) {
        return false;
    }
    auto modIter = modifiers_.find(keyCode);
    return ((modIter == modifiers_.cend()) || ((modIter->second & shortcut.modifiers) == 0U));
}

bool KeyShortcutManager::WillResetOnKeyUp(int32_t keyCode, const KeyShortcut &shortcut) const
{
    if (keyCode == shortcut.finalKey) {
        return true;
    }
    auto modIter = modifiers_.find(keyCode);
    return ((modIter != modifiers_.cend()) && ((modIter->second & shortcut.modifiers) != 0U));
}

void KeyShortcutManager::ResetTriggering(int32_t shortcutId)
{
    if (auto iter = triggering_.find(shortcutId); iter != triggering_.cend()) {
        TimerMgr->RemoveTimer(iter->second);
        triggering_.erase(iter);
    }
}
} // namespace MMI
} // namespace OHOS
