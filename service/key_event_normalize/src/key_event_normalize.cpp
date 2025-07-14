/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "key_event_normalize.h"

#include <linux/input.h>
#include <parameters.h>

#include "display_manager.h"
#include "key_map_manager.h"
#include "key_command_handler_util.h"
#include "key_unicode_transformation.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventNormalize"

namespace OHOS {
namespace MMI {
namespace {
constexpr uint32_t KEYSTATUS { 0 };
constexpr int32_t SWAP_VOLUME_KEYS_ON_FOLD { 0 };
class FoldStatusCallback : public Rosen::DisplayManager::IFoldStatusListener {
public:
    FoldStatusCallback() = default;
    ~FoldStatusCallback() = default;
    void OnFoldStatusChanged(Rosen::FoldStatus foldStatus) override
    {
        std::lock_guard<std::mutex> guard(mutex_);
        foldStatus_ = foldStatus;
    }
    Rosen::FoldStatus GetFoldStatus()
    {
        std::lock_guard<std::mutex> guard(mutex_);
        return foldStatus_;
    }
private:
    std::mutex mutex_;
    Rosen::FoldStatus foldStatus_ { Rosen::FoldStatus::UNKNOWN };
};
sptr<FoldStatusCallback> g_foldStatusCallback { nullptr };
} // namespace

KeyEventNormalize::KeyEventNormalize() {}

KeyEventNormalize::~KeyEventNormalize() {}

void KeyEventNormalize::Init()
{
    g_foldStatusCallback = new (std::nothrow) FoldStatusCallback();
    CHKPV(g_foldStatusCallback);
    Rosen::DisplayManager::GetInstance().RegisterFoldStatusListener(g_foldStatusCallback);
}

std::shared_ptr<KeyEvent> KeyEventNormalize::GetKeyEvent()
{
    if (keyEvent_ == nullptr) {
        keyEvent_ = KeyEvent::Create();
    }
    return keyEvent_;
}

int32_t KeyEventNormalize::Normalize(struct libinput_event *event, std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, PARAM_INPUT_INVALID);
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    keyEvent->UpdateId();
    StartLogTraceId(keyEvent->GetId(), keyEvent->GetEventType(), keyEvent->GetKeyAction());
    auto data = libinput_event_get_keyboard_event(event);
    CHKPR(data, ERROR_NULL_POINTER);

    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
    int32_t deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
    int32_t keyCode = static_cast<int32_t>(libinput_event_keyboard_get_key(data));
    MMI_HILOGD("The linux input keyCode:%{private}d", keyCode);
    keyCode = KeyMapMgr->TransferDeviceKeyValue(device, keyCode);
    if (keyCode == KeyEvent::KEYCODE_UNKNOWN) {
        MMI_HILOGE("The key value is unknown");
        return RET_ERR;
    }
    int32_t keyAction = (libinput_event_keyboard_get_key_state(data) == 0) ?
        (KeyEvent::KEY_ACTION_UP) : (KeyEvent::KEY_ACTION_DOWN);
    keyCode = TransformVolumeKey(device, keyCode, keyAction);
    auto preAction = keyEvent->GetAction();
    if (preAction == KeyEvent::KEY_ACTION_UP) {
        std::optional<KeyEvent::KeyItem> preUpKeyItem = keyEvent->GetKeyItem();
        if (preUpKeyItem) {
            keyEvent->RemoveReleasedKeyItems(*preUpKeyItem);
        } else {
            MMI_HILOGE("The preUpKeyItem is nullopt");
        }
    }
    uint64_t time = libinput_event_keyboard_get_time_usec(data);
    keyEvent->SetActionTime(time);
    keyEvent->SetAction(keyAction);
    keyEvent->SetDeviceId(deviceId);
    keyEvent->SetSourceType(InputEvent::SOURCE_TYPE_UNKNOWN);
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(keyAction);
    StartLogTraceId(keyEvent->GetId(), keyEvent->GetEventType(), keyEvent->GetKeyAction());
    if (keyEvent->GetPressedKeys().empty()) {
        keyEvent->SetActionStartTime(time);
    }

    KeyEvent::KeyItem item;
    bool isKeyPressed = (libinput_event_keyboard_get_key_state(data) != KEYSTATUS);
    item.SetDownTime(time);
    item.SetKeyCode(keyCode);
    item.SetDeviceId(deviceId);
    item.SetPressed(isKeyPressed);
    item.SetUnicode(KeyCodeToUnicode(keyCode, keyEvent));

    HandleKeyAction(device, item, keyEvent);

    int32_t keyIntention = KeyItemsTransKeyIntention(keyEvent->GetKeyItems());
    keyEvent->SetKeyIntention(keyIntention);
    return RET_OK;
}

void KeyEventNormalize::HandleKeyAction(struct libinput_device* device, KeyEvent::KeyItem &item,
    std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(device);
    CHKPV(keyEvent);
    int32_t keyAction = keyEvent->GetAction();
    int32_t keyCode = keyEvent->GetKeyCode();
    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        keyEvent->AddPressedKeyItems(item);
    }
    if (keyAction == KeyEvent::KEY_ACTION_UP) {
        int32_t funcKey = keyEvent->TransitionFunctionKey(keyCode);
        if (funcKey != KeyEvent::UNKNOWN_FUNCTION_KEY) {
            int32_t funKeyState = libinput_get_funckey_state(device, funcKey);
            int32_t ret = keyEvent->SetFunctionKey(funcKey, funKeyState);
            if (ret == funcKey) {
                MMI_HILOGI("Set function key:%{public}d to state:%{public}d succeed",
                           funcKey, funKeyState);
            }
        }
        std::optional<KeyEvent::KeyItem> pressedKeyItem = keyEvent->GetKeyItem(keyCode);
        if (pressedKeyItem) {
            item.SetDownTime(pressedKeyItem->GetDownTime());
        } else {
            MMI_HILOGE("Find pressed key failed, keyCode:%{private}d", keyCode);
        }
        keyEvent->RemoveReleasedKeyItems(item);
        keyEvent->AddPressedKeyItems(item);
    }
}

void KeyEventNormalize::ResetKeyEvent(struct libinput_device* device)
{
    if (INPUT_DEV_MGR->IsKeyboardDevice(device) || INPUT_DEV_MGR->IsPointerDevice(device)) {
        bool newKeyEventJustCreated = false;
        if (keyEvent_ == nullptr) {
            keyEvent_ = KeyEvent::Create();
            newKeyEventJustCreated = true;
        }
        CHKPV(keyEvent_);

        if (!libinput_has_event_led_type(device)) {
            // skip if this device does not have led lights.
            return;
        }

        const std::vector<int32_t> funcKeys = {
            KeyEvent::NUM_LOCK_FUNCTION_KEY,
            KeyEvent::CAPS_LOCK_FUNCTION_KEY,
            KeyEvent::SCROLL_LOCK_FUNCTION_KEY
        };
        if (newKeyEventJustCreated) {
            // if key event just created, set keyevent from this new device.
            MMI_HILOGI("Reset key event function key state based on the new added device's led");
            for (const auto &funcKey : funcKeys) {
                keyEvent_->SetFunctionKey(funcKey, libinput_get_funckey_state(device, funcKey));
            }
        } else {
            // otherwise, set this new device's function key state based on the key event.
            MMI_HILOGI("Reset new added device's led based on the key event");
            for (const auto &funcKey : funcKeys) {
                libinput_set_led_state(device, funcKey, keyEvent_->GetFunctionKey(funcKey));
            }
        }
    }
}

int32_t KeyEventNormalize::SetShieldStatus(int32_t shieldMode, bool isShield)
{
    std::lock_guard<std::mutex> guard(mtx_);
    MMI_HILOGI("Last shield mode:%{public}d, set shield mode:%{public}d, status:%{public}d",
        lastShieldMode_, shieldMode, isShield);
    auto iter = shieldStatus_.find(lastShieldMode_);
    if (isShield) {
        if (lastShieldMode_ == shieldMode) {
            MMI_HILOGI("Last shield mode equal with shield mode");
        } else if (iter != shieldStatus_.end()) {
            iter->second = false;
        } else {
            MMI_HILOGI("Last shield mode unset");
        }
        lastShieldMode_ = shieldMode;
    } else if (lastShieldMode_ != shieldMode) {
        MMI_HILOGI("Shield mode:%{public}d is already false", shieldMode);
    } else {
        MMI_HILOGI("The lastShieldMode_ unset");
        lastShieldMode_ = SHIELD_MODE::UNSET_MODE;
    }
    iter = shieldStatus_.find(shieldMode);
    if (iter == shieldStatus_.end()) {
        MMI_HILOGE("Find shieldMode:%{public}d failed", shieldMode);
        return RET_ERR;
    }
    iter->second = isShield;
    MMI_HILOGI("Last shield mode:%{public}d, set shield mode:%{public}d, status:%{public}d",
        lastShieldMode_, shieldMode, isShield);
    return RET_OK;
}

int32_t KeyEventNormalize::GetShieldStatus(int32_t shieldMode, bool &isShield)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    auto iter = shieldStatus_.find(shieldMode);
    if (iter == shieldStatus_.end()) {
        MMI_HILOGE("Find shieldMode:%{public}d failed", shieldMode);
        return RET_ERR;
    }
    isShield = iter->second;
    MMI_HILOGI("Last shield mode:%{public}d, get shield mode:%{public}d, status:%{public}d",
        lastShieldMode_, shieldMode, isShield);
    return RET_OK;
}

int32_t KeyEventNormalize::GetCurrentShieldMode()
{
    std::lock_guard<std::mutex> guard(mtx_);
    return lastShieldMode_;
}

void KeyEventNormalize::SetCurrentShieldMode(int32_t shieldMode)
{
    std::lock_guard<std::mutex> guard(mtx_);
    lastShieldMode_ = shieldMode;
}

void KeyEventNormalize::ReadProductConfig(InputProductConfig &config) const
{
    config = InputProductConfig {};
    char cfgName[] { "etc/input/input_product_config.json" };
    char buf[MAX_PATH_LEN] {};
    char *cfgPath = ::GetOneCfgFile(cfgName, buf, sizeof(buf));
    if (cfgPath == nullptr) {
        MMI_HILOGE("No '%{private}s' was found", cfgName);
        return;
    }
    MMI_HILOGI("Input product config:%{private}s", cfgPath);
    ReadProductConfig(std::string(cfgPath), config);
}

void KeyEventNormalize::ReadProductConfig(const std::string &cfgPath, InputProductConfig &config) const
{
    std::string cfg = ReadJsonFile(cfgPath);
    JsonParser parser;
    parser.json_ = cJSON_Parse(cfg.c_str());
    if (!cJSON_IsObject(parser.json_)) {
        MMI_HILOGE("Not json format");
        return;
    }
    cJSON *jsonKeyboard = cJSON_GetObjectItemCaseSensitive(parser.json_, "keyboard");
    if (!cJSON_IsObject(jsonKeyboard)) {
        MMI_HILOGE("The jsonKeyboard is not object");
        return;
    }
    cJSON *jsonVolumeSwap = cJSON_GetObjectItemCaseSensitive(jsonKeyboard, "volumeSwap");
    if (!cJSON_IsObject(jsonVolumeSwap)) {
        MMI_HILOGE("The jsonVolumeSwap is not object");
        return;
    }
    cJSON *jsonWhen = cJSON_GetObjectItemCaseSensitive(jsonVolumeSwap, "when");
    if (!cJSON_IsNumber(jsonWhen)) {
        MMI_HILOGE("The jsonWhen is not number");
        return;
    }
    if (static_cast<int32_t>(cJSON_GetNumberValue(jsonWhen)) == SWAP_VOLUME_KEYS_ON_FOLD) {
        config.volumeSwap_ = VolumeSwapConfig::SWAP_ON_FOLD;
    } else {
        config.volumeSwap_ = VolumeSwapConfig::NO_VOLUME_SWAP;
    }
    MMI_HILOGI("keyboard.volumeSwap:%{public}d", static_cast<int32_t>(config.volumeSwap_));
}

void KeyEventNormalize::CheckProductParam(InputProductConfig &productConfig) const
{
    if (productConfig.volumeSwap_ != VolumeSwapConfig::NO_CONFIG) {
        return;
    }
    const std::string theProduct { "UNKNOWN_PRODUCT" };
    std::string product = OHOS::system::GetParameter("const.build.product", "");
    if (product == theProduct) {
        productConfig.volumeSwap_ = VolumeSwapConfig::SWAP_ON_FOLD;
    } else {
        productConfig.volumeSwap_ = VolumeSwapConfig::NO_VOLUME_SWAP;
    }
}

int32_t KeyEventNormalize::TransformVolumeKey(struct libinput_device *dev, int32_t keyCode, int32_t keyAction) const
{
    CHKPR(g_foldStatusCallback, keyCode);
    static std::once_flag flag;
    static std::map<int32_t, Rosen::FoldStatus> displayModes {
        { KeyEvent::KEYCODE_VOLUME_DOWN, Rosen::FoldStatus::UNKNOWN },
        { KeyEvent::KEYCODE_VOLUME_UP, Rosen::FoldStatus::UNKNOWN },
    };
    static InputProductConfig productConfig {};

    std::call_once(flag, [this]() {
        ReadProductConfig(productConfig);
        CheckProductParam(productConfig);
    });
    if (productConfig.volumeSwap_ != VolumeSwapConfig::SWAP_ON_FOLD) {
        return keyCode;
    }
    auto iter = displayModes.find(keyCode);
    if (iter == displayModes.end()) {
        return keyCode;
    }
    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        iter->second = g_foldStatusCallback->GetFoldStatus();
    }
    if (iter->second != Rosen::FoldStatus::FOLDED) {
        return keyCode;
    }
    const char *name = libinput_device_get_name(dev);
    int32_t busType = static_cast<int32_t>(libinput_device_get_id_bustype(dev));
    MMI_HILOGD("Flip volume keys upon fold: Dev:%{public}s, Bus:%{public}d",
        name != nullptr ? name : "(null)", busType);
    if (busType != BUS_HOST) {
        return keyCode;
    }
    return (keyCode == KeyEvent::KEYCODE_VOLUME_DOWN ? KeyEvent::KEYCODE_VOLUME_UP : KeyEvent::KEYCODE_VOLUME_DOWN);
}

bool KeyEventNormalize::IsScreenFold()
{
    CHKPF(g_foldStatusCallback);
    return g_foldStatusCallback->GetFoldStatus() == Rosen::FoldStatus::FOLDED;
}
} // namespace MMI
} // namespace OHOS
