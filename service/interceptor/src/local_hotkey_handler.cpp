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

#include "local_hotkey_handler.h"

#include <fstream>
#include "cJSON.h"
#include "config_policy_utils.h"
#include "init_param.h"

#include "define_multimodal.h"
#include "key_shortcut_manager.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "LocalHotKeyHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr uint32_t LOCAL_HOT_KEY_WITH_ALL_MODIFIERS_OPTIONAL { 0x10000000U };
constexpr std::uintmax_t MAX_SIZE_OF_LOCAL_HOT_KEYS_CONFIG { 8192 };
const std::string DEFAULT_KEYEVENT_INTERCEPT_WHITELIST { "2722;41;40;0;22;17;16;23;2841;9;2089;2083;" };
} // namespace

enum class ModifierKeyAction {
    ANY,
    DOWN,
    NONE,
};

struct LocalHotKeyConfig {
    int32_t keyCode_ { KeyEvent::KEYCODE_UNKNOWN };
    uint32_t modifiers_ { 0U };
    uint32_t optionalModifiers_ { 0U };
    LocalHotKeyAction action_ { LocalHotKeyAction::INTERCEPT };
};

bool LocalHotKey::operator<(const LocalHotKey &other) const
{
    if (keyCode_ != other.keyCode_) {
        return (keyCode_ < other.keyCode_);
    }
    return (modifiers_ < other.modifiers_);
}

static bool ReadHotKeyCode(int32_t index, cJSON *jsonHotKey, int32_t &keyCode)
{
    cJSON *jsonKeyCode = cJSON_GetObjectItemCaseSensitive(jsonHotKey, "KEYCODE");
    if (jsonKeyCode == nullptr) {
        MMI_HILOGE("The 'LOCAL_HOT_KEYS[%{public}d].KEYCODE' is missing", index);
        return false;
    }
    if (!cJSON_IsNumber(jsonKeyCode)) {
        MMI_HILOGE("The 'LOCAL_HOT_KEYS[%{public}d].KEYCODE' is not number", index);
        return false;
    }
    auto sKeyCode = std::unique_ptr<char, std::function<void(char *)>>(
        cJSON_Print(jsonKeyCode),
        [](char *data) {
            if (data != nullptr) {
                cJSON_free(data);
            }
        });
    CHKPF(sKeyCode);
    if (!IsInteger(sKeyCode.get())) {
        MMI_HILOGE("The 'LOCAL_HOT_KEYS[%{public}d].KEYCODE' is not integer", index);
        return false;
    }
    if (KeyShortcutManager::IsModifier(static_cast<int32_t>(cJSON_GetNumberValue(jsonKeyCode)))) {
        MMI_HILOGE("The 'LOCAL_HOT_KEYS[%{public}d].KEYCODE' is modifier", index);
        return false;
    }
    keyCode = static_cast<int32_t>(cJSON_GetNumberValue(jsonKeyCode));
    return true;
}

static bool ReadModifiers(int32_t index, cJSON *jsonHotKey, const std::map<std::string, uint32_t> &names,
    uint32_t &modifiers, uint32_t &optModifiers)
{
    cJSON *jsonModifiers = cJSON_GetObjectItemCaseSensitive(jsonHotKey, "MODIFIERS");
    if (jsonModifiers == nullptr) {
        MMI_HILOGE("The 'LOCAL_HOT_KEYS[%{public}d].MODIFIERS' is missing", index);
        return false;
    }
    if (!cJSON_IsObject(jsonModifiers)) {
        MMI_HILOGE("The 'LOCAL_HOT_KEYS[%{public}d].MODIFIERS' is not object", index);
        return false;
    }
    const std::map<std::string, ModifierKeyAction> modifierActions {
        { "ANY", ModifierKeyAction::ANY },
        { "DOWN", ModifierKeyAction::DOWN },
        { "NONE", ModifierKeyAction::NONE },
    };
    for (const auto &[name, modifierBit] : names) {
        cJSON *jsonModifier = cJSON_GetObjectItemCaseSensitive(jsonModifiers, name.c_str());
        if (jsonModifier == nullptr) {
            MMI_HILOGW("The 'LOCAL_HOT_KEYS[%{public}d].MODIFIERS.%{public}s' is missing", index, name.c_str());
            return false;
        }
        const char *sModifier = cJSON_GetStringValue(jsonModifier);
        if (sModifier == nullptr) {
            MMI_HILOGE("The 'LOCAL_HOT_KEYS[%{public}d].MODIFIERS.%{public}s' is not string", index, name.c_str());
            return false;
        }
        auto iter = modifierActions.find(sModifier);
        if (iter == modifierActions.cend()) {
            MMI_HILOGE("The 'LOCAL_HOT_KEYS[%{public}d].MODIFIERS.%{public}s' is invalid", index, name.c_str());
            return false;
        }
        if (iter->second == ModifierKeyAction::ANY) {
            optModifiers |= modifierBit;
        } else if (iter->second == ModifierKeyAction::DOWN) {
            modifiers |= modifierBit;
        }
    }
    return true;
}

static bool ReadHotKeyModifiers(int32_t index, cJSON *jsonHotKey, std::set<uint32_t> &modifiers)
{
    const std::map<std::string, uint32_t> modifierNames {
        { "CTRL", KeyShortcutManager::SHORTCUT_MODIFIER_CTRL },
        { "SHIFT", KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT },
        { "ALT", KeyShortcutManager::SHORTCUT_MODIFIER_ALT },
        { "META", KeyShortcutManager::SHORTCUT_MODIFIER_LOGO },
    };
    uint32_t uModifiers { 0U };
    uint32_t uOptModifiers { 0U };

    if (!ReadModifiers(index, jsonHotKey, modifierNames, uModifiers, uOptModifiers)) {
        return false;
    }
    if (uOptModifiers == KeyShortcutManager::SHORTCUT_MODIFIER_MASK) {
        modifiers.emplace(uOptModifiers | LOCAL_HOT_KEY_WITH_ALL_MODIFIERS_OPTIONAL);
        return true;
    }
    modifiers.emplace(uModifiers);

    for (const auto &[_, modifierBit] : modifierNames) {
        if ((uOptModifiers & modifierBit) == 0U) {
            continue;
        }
        std::set<uint32_t> tModifiers;

        for (const auto &mod : modifiers) {
            tModifiers.emplace(mod | modifierBit);
        }
        modifiers.merge(std::move(tModifiers));
    }
    return true;
}

static bool ReadHotKeyAction(int32_t index, cJSON *jsonHotKey, LocalHotKeyAction &hotKeyAction)
{
    cJSON *jsonAction = cJSON_GetObjectItemCaseSensitive(jsonHotKey, "ACTION");
    if (jsonAction == nullptr) {
        MMI_HILOGE("The 'LOCAL_HOT_KEYS[%{public}d].ACTION' is missing", index);
        return false;
    }
    const char *sAction = cJSON_GetStringValue(jsonAction);
    if (sAction == nullptr) {
        MMI_HILOGE("The 'LOCAL_HOT_KEYS[%{public}d].ACTION' is not string", index);
        return false;
    }
    std::map<std::string, LocalHotKeyAction> hotKeyActions {
        { "INTERCEPT", LocalHotKeyAction::INTERCEPT },
        { "COPY", LocalHotKeyAction::COPY },
        { "OVER", LocalHotKeyAction::OVER },
    };
    auto iter = hotKeyActions.find(sAction);
    if (iter == hotKeyActions.cend()) {
        MMI_HILOGE("The 'LOCAL_HOT_KEYS[%{public}d].ACTION' is invalid", index);
        return false;
    }
    hotKeyAction = iter->second;
    return true;
}

static void ReadLocalHotKey(cJSON *jsonHotKeys, int32_t index, LocalHotKeyMap &hotKeys)
{
    cJSON *jsonHotKey = cJSON_GetArrayItem(jsonHotKeys, index);
    if (!cJSON_IsObject(jsonHotKey)) {
        MMI_HILOGE("The 'LOCAL_HOT_KEYS[%{public}d]' is not object", index);
        return;
    }
    int32_t keyCode { KeyEvent::KEYCODE_UNKNOWN };
    if (!ReadHotKeyCode(index, jsonHotKey, keyCode)) {
        return;
    }
    std::set<uint32_t> modifiers;
    if (!ReadHotKeyModifiers(index, jsonHotKey, modifiers)) {
        return;
    }
    LocalHotKeyAction hotKeyAction {};
    if (!ReadHotKeyAction(index, jsonHotKey, hotKeyAction)) {
        return;
    }
    for (const auto &mod : modifiers) {
        LocalHotKey hotKey {
            .keyCode_ = keyCode,
            .modifiers_ = mod,
        };
        auto [_, isNew] = hotKeys.emplace(hotKey, hotKeyAction);
        if (!isNew) {
            MMI_HILOGE("Duplicate local hot key at LOCAL_HOT_KEYS[%{public}d]", index);
        }
    }
}

static void ReadLocalHotKeys(cJSON *jsonCfg, LocalHotKeyMap &hotKeys)
{
    if (!cJSON_IsObject(jsonCfg)) {
        MMI_HILOGE("Not json format");
        return;
    }
    cJSON *jsonHotKeys = cJSON_GetObjectItemCaseSensitive(jsonCfg, "LOCAL_HOT_KEYS");
    if (!cJSON_IsArray(jsonHotKeys)) {
        MMI_HILOGE("The 'LOCAL_HOT_KEYS' is not array");
        return;
    }
    int32_t nHotKeys = cJSON_GetArraySize(jsonHotKeys);
    for (int32_t index = 0; index < nHotKeys; ++index) {
        ReadLocalHotKey(jsonHotKeys, index, hotKeys);
    }
}

static void ReadLocalHotKeys(std::ifstream &ifs, LocalHotKeyMap &hotKeys)
{
    std::string cfg { std::istream_iterator<char>(ifs), std::istream_iterator<char>() };
    auto jsonHotKeys = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_Parse(cfg.c_str()),
        [](cJSON *jsonCfg) {
            if (jsonCfg != nullptr) {
                cJSON_Delete(jsonCfg);
            }
        });
    CHKPV(jsonHotKeys);
    ReadLocalHotKeys(jsonHotKeys.get(), hotKeys);
}

static void PickSystemHotKeys(LocalHotKeyMap &hotKeys, std::set<int32_t> &systemHotKeys)
{
    for (auto iter = hotKeys.begin(); iter != hotKeys.end();) {
        if ((iter->first.modifiers_ & ~KeyShortcutManager::SHORTCUT_MODIFIER_MASK) == 0U) {
            ++iter;
            continue;
        }
        if (iter->first.modifiers_ & LOCAL_HOT_KEY_WITH_ALL_MODIFIERS_OPTIONAL) {
            systemHotKeys.emplace(iter->first.keyCode_);
            MMI_HILOGD("Pick system hot key: %{private}d", iter->first.keyCode_);
        }
        iter = hotKeys.erase(iter);
    }
}

void LocalHotKeySteward::LoadLocalHotKeys()
{
    char cfgName[] { "etc/multimodalinput/local_hot_keys.json" };
    char buf[MAX_PATH_LEN] {};
    char *cfgPath = ::GetOneCfgFile(cfgName, buf, sizeof(buf));
    if (cfgPath == nullptr) {
        MMI_HILOGE("No local_hot_keys config was found");
        return;
    }
    auto realPath = std::unique_ptr<char, std::function<void(char *)>>(
        ::realpath(cfgPath, nullptr),
        [](auto arr) {
            if (arr != nullptr) {
                ::free(arr);
            }
        });
    if (realPath == nullptr) {
        MMI_HILOGI("No local_hot_keys config");
        return;
    }
    std::error_code ec {};
    auto fsize = std::filesystem::file_size(realPath.get(), ec);
    if (ec || (fsize > MAX_SIZE_OF_LOCAL_HOT_KEYS_CONFIG)) {
        MMI_HILOGE("Unexpected size of local_hot_keys config");
        return;
    }
    std::ifstream ifs(realPath.get());
    if (!ifs.is_open()) {
        MMI_HILOGE("Can not open local_hot_keys config");
        return;
    }
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        ReadLocalHotKeys(ifs, localHotKeys_);
        PickSystemHotKeys(localHotKeys_, systemHotKeys_);
    }
}

static void ReadSystemLocalHotKeys(const std::string &paramName, std::string &paramValue)
{
    uint32_t size = 0;
    auto ret = ::SystemReadParam(paramName.c_str(), nullptr, &size);
    if (ret != 0) {
        MMI_HILOGE("SystemReadParam fail, error: %{public}d", ret);
        return;
    }
    std::vector<char> value(size + 1);
    ret = ::SystemReadParam(paramName.c_str(), value.data(), &size);
    if (ret != 0) {
        MMI_HILOGW("Use default due to SystemReadParam failure, error: %{public}d", ret);
        paramValue = DEFAULT_KEYEVENT_INTERCEPT_WHITELIST;
    } else {
        paramValue = std::string(value.data());
    }
    MMI_HILOGD("System white list of no interception: %{private}s", paramValue.c_str());
}

static void ParseSystemLocalHotKeys(const std::string &paramValue, std::set<int32_t> &systemHotKeys)
{
    for (std::string::size_type sPos = 0, size = paramValue.size(); sPos < size;) {
        std::string::size_type tPos = paramValue.find(';', sPos);
        if (tPos == std::string::npos) {
            break;
        }
        if (tPos > sPos) {
            std::string value = paramValue.substr(sPos, tPos - sPos);
            if (IsInteger(value.c_str())) {
                systemHotKeys.insert(std::stoi(value));
            }
        }
        sPos = tPos + 1;
    }
}

void LocalHotKeySteward::LoadSystemLocalHotKeys()
{
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        if (!localHotKeys_.empty() || !systemHotKeys_.empty()) {
            MMI_HILOGW("No need to read system paramter due to existing config");
            return;
        }
    }
    std::string paramName { "const.multimodalinput.keyevent_intercept_whitelist" };
    std::string paramValue {};

    ReadSystemLocalHotKeys(paramName, paramValue);
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        ParseSystemLocalHotKeys(paramValue, systemHotKeys_);
    }
}

LocalHotKeyAction LocalHotKeySteward::QueryAction(const LocalHotKey &hotKey) const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (auto iter = localHotKeys_.find(hotKey); iter != localHotKeys_.end()) {
        return iter->second;
    }
    if (systemHotKeys_.find(hotKey.keyCode_) != systemHotKeys_.end()) {
        return LocalHotKeyAction::OVER;
    }
    return LocalHotKeyAction::INTERCEPT;
}

static void UpdateLocalHotKeyConfig(const LocalHotKey &hotKey, LocalHotKeyAction action,
    std::vector<LocalHotKeyConfig> &hotKeyConfigs)
{
    for (auto &config : hotKeyConfigs) {
        if (((config.modifiers_ | hotKey.modifiers_) == config.modifiers_) &&
            (config.action_ == action)) {
            config.optionalModifiers_ |= (config.modifiers_ ^ hotKey.modifiers_);
            return;
        }
    }
    hotKeyConfigs.emplace_back(LocalHotKeyConfig {
        .keyCode_ = hotKey.keyCode_,
        .modifiers_ = hotKey.modifiers_,
        .action_ = action,
    });
}

static void ClarifyLocalHotKeys(const LocalHotKeyMap &localHotKeys,
    std::map<int32_t, std::vector<LocalHotKeyConfig>> &hotKeyConfigs)
{
    for (auto iter = localHotKeys.crbegin(); iter != localHotKeys.crend();) {
        auto keyCode = iter->first.keyCode_;
        std::vector<LocalHotKeyConfig> vHotKeys;

        for (; ((iter != localHotKeys.crend()) && (iter->first.keyCode_ == keyCode)); ++iter) {
            UpdateLocalHotKeyConfig(iter->first, iter->second, vHotKeys);
        }
        hotKeyConfigs.emplace(keyCode, std::move(vHotKeys));
    }
}

static void UpdateSystemHotKeyConfig(int32_t hotKey, std::vector<LocalHotKeyConfig> &hotKeyConfigs)
{
    for (auto iter = hotKeyConfigs.begin(); iter != hotKeyConfigs.end();) {
        if ((iter->keyCode_ == hotKey) && (iter->action_ == LocalHotKeyAction::OVER)) {
            iter = hotKeyConfigs.erase(iter);
        } else {
            ++iter;
        }
    }
    hotKeyConfigs.emplace_back(LocalHotKeyConfig {
        .keyCode_ = hotKey,
        .optionalModifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_MASK,
        .action_ = LocalHotKeyAction::OVER,
    });
}

static void ClarifySystemHotKeys(const std::set<int32_t> &systemHotKeys,
    std::map<int32_t, std::vector<LocalHotKeyConfig>> &hotKeyConfigs)
{
    for (const auto &keyCode : systemHotKeys) {
        auto iter = hotKeyConfigs.find(keyCode);
        if (iter == hotKeyConfigs.end()) {
            auto [tIter, _] = hotKeyConfigs.emplace(keyCode, std::vector<LocalHotKeyConfig>());
            iter = tIter;
        }
        UpdateSystemHotKeyConfig(keyCode, iter->second);
    }
}

static const char* DumpModifier(const LocalHotKeyConfig &hotKeyConfig, uint32_t modifierBit)
{
    return ((hotKeyConfig.optionalModifiers_ & modifierBit) ? "ANY" :
            (hotKeyConfig.modifiers_ & modifierBit) ? "DOWN" : "NONE");
}

static const char* DumpLocalHotKeyAction(LocalHotKeyAction action)
{
    switch (action) {
        case LocalHotKeyAction::INTERCEPT: {
            return "INTERCEPT";
        }
        case LocalHotKeyAction::COPY: {
            return "COPY";
        }
        case LocalHotKeyAction::OVER: {
            return "OVER";
        }
        default: {
            break;
        }
    }
    return "UNKNOWN";
}

void LocalHotKeySteward::Dump(int32_t fd, const std::vector<std::string> &args) const
{
    CALL_DEBUG_ENTER;
    std::map<int32_t, std::vector<LocalHotKeyConfig>> hotKeyConfigs;
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        ClarifyLocalHotKeys(localHotKeys_, hotKeyConfigs);
        ClarifySystemHotKeys(systemHotKeys_, hotKeyConfigs);
    }

    mprintf(fd, "local hot keys:");

    for (const auto &[keyCode, hotKeys] : hotKeyConfigs) {
        for (const auto &hotKey : hotKeys) {
            mprintf(fd, "\tKEYCODE:%d, MODIFIERS:{ALT:%s, SHIFT:%s, CTRL:%s, META:%s}, ACTION:%s",
                    keyCode,
                    DumpModifier(hotKey, KeyShortcutManager::SHORTCUT_MODIFIER_ALT),
                    DumpModifier(hotKey, KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT),
                    DumpModifier(hotKey, KeyShortcutManager::SHORTCUT_MODIFIER_CTRL),
                    DumpModifier(hotKey, KeyShortcutManager::SHORTCUT_MODIFIER_LOGO),
                    DumpLocalHotKeyAction(hotKey.action_));
        }
    }
}

LocalHotKeySteward LocalHotKeyHandler::steward_;

bool LocalHotKeyHandler::HandleEvent(std::shared_ptr<KeyEvent> keyEvent,
    std::function<bool(std::shared_ptr<KeyEvent>)> intercept)
{
    CHKPF(keyEvent);
    static std::once_flag flag;

    std::call_once(flag, []() {
        steward_.LoadLocalHotKeys();
        steward_.LoadSystemLocalHotKeys();
    });
    if (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        return HandleKeyDown(keyEvent, intercept);
    }
    return HandleKeyUp(keyEvent, intercept);
}

void LocalHotKeyHandler::MarkProcessed(std::shared_ptr<KeyEvent> keyEvent, LocalHotKeyAction action)
{
    CHKPV(keyEvent);
    if (keyEvent->GetKeyAction() != KeyEvent::KEY_ACTION_DOWN) {
        return;
    }
    auto iter = consumedKeys_.find(keyEvent->GetKeyCode());
    if (iter == consumedKeys_.end()) {
        consumedKeys_.emplace(keyEvent->GetKeyCode(), action);
        return;
    }
    if (action == LocalHotKeyAction::INTERCEPT) {
        if (iter->second == LocalHotKeyAction::OVER) {
            iter->second = LocalHotKeyAction::COPY;
        }
    } else if (action == LocalHotKeyAction::OVER) {
        if (iter->second == LocalHotKeyAction::INTERCEPT) {
            iter->second = LocalHotKeyAction::COPY;
        }
    }
}

void LocalHotKeyHandler::HandleLocalHotKey(std::shared_ptr<KeyEvent> keyEvent, IInputEventHandler &handler)
{
    CHKPV(keyEvent);
    auto event = KeyEvent::Create();
    CHKPV(event);
    std::vector<KeyEvent::KeyItem> pressedKeys;

    for (const auto &keyItem : keyEvent->GetKeyItems()) {
        if (!keyItem.IsPressed() || (keyItem.GetKeyCode() == keyEvent->GetKeyCode())) {
            continue;
        }
        if (KeyShortcutManager::IsModifier(keyItem.GetKeyCode())) {
            pressedKeys.push_back(keyItem);
        } else {
            event->AddPressedKeyItems(keyItem);
        }
    }
    for (auto &keyItem : pressedKeys) {
        if (HasKeyBeenDispatched(keyItem.GetKeyCode())) {
            continue;
        }
        auto actionTime = GetSysClockTime();
        event->SetActionTime(actionTime);
        event->SetKeyCode(keyItem.GetKeyCode());
        event->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
        event->SetDeviceId(keyItem.GetDeviceId());

        keyItem.SetDownTime(actionTime);
        event->AddPressedKeyItems(keyItem);

        handler.HandleKeyEvent(event);
        MarkProcessed(event, LocalHotKeyAction::OVER);
    }
}

void LocalHotKeyHandler::Dump(int32_t fd, const std::vector<std::string> &args) const
{
    steward_.Dump(fd, args);
}

bool LocalHotKeyHandler::HandleKeyDown(std::shared_ptr<KeyEvent> keyEvent,
    std::function<bool(std::shared_ptr<KeyEvent>)> intercept)
{
    auto hotKeyOpt = KeyEvent2LocalHotKey(keyEvent);
    if (!hotKeyOpt) {
        return false;
    }
    auto action = LocalHotKeyAction::INTERCEPT;

    if (auto iter = consumedKeys_.find(keyEvent->GetKeyCode()); iter != consumedKeys_.cend()) {
        action = iter->second;
    } else {
        action = steward_.QueryAction(*hotKeyOpt);
        MarkProcessed(keyEvent, action);
    }
    switch (action) {
        case LocalHotKeyAction::COPY: {
            if (intercept) {
                intercept(keyEvent);
            }
            return true;
        }
        case LocalHotKeyAction::OVER: {
            return true;
        }
        default: {
            break;
        }
    }
    return false;
}

bool LocalHotKeyHandler::HandleKeyUp(std::shared_ptr<KeyEvent> keyEvent,
    std::function<bool(std::shared_ptr<KeyEvent>)> intercept)
{
    CHKPF(keyEvent);
    if (auto iter = consumedKeys_.find(keyEvent->GetKeyCode()); iter != consumedKeys_.cend()) {
        const auto action = iter->second;
        consumedKeys_.erase(iter);
        if ((action == LocalHotKeyAction::COPY) && intercept) {
            intercept(keyEvent);
        }
        return ((action == LocalHotKeyAction::OVER) || (action == LocalHotKeyAction::COPY));
    }
    return false;
}

std::optional<LocalHotKey> LocalHotKeyHandler::KeyEvent2LocalHotKey(std::shared_ptr<KeyEvent> keyEvent) const
{
    if (keyEvent == nullptr) {
        return std::nullopt;
    }
    LocalHotKey hotKey {
        .keyCode_ = keyEvent->GetKeyCode(),
    };
    auto pressedKeys = keyEvent->GetPressedKeys();
    for (const auto &pressedKey : pressedKeys) {
        hotKey.modifiers_ |= KeyShortcutManager::Key2Modifier(pressedKey);
    }
    return hotKey;
}

bool LocalHotKeyHandler::HasKeyBeenDispatched(int32_t keyCode) const
{
    auto iter = consumedKeys_.find(keyCode);
    return ((iter != consumedKeys_.end()) &&
            ((iter->second == LocalHotKeyAction::OVER) || (iter->second == LocalHotKeyAction::COPY)));
}
} // namespace MMI
} // namespace OHOS
