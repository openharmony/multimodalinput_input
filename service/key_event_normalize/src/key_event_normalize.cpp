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
#include "display_manager_lite.h"
#include "key_map_manager.h"
#include "key_command_handler_util.h"
#include "key_unicode_transformation.h"
#include "misc_product_type_parser.h"
#include "libinput_adapter.h"
#include "key_auto_repeat.h"
#include "libinput_adapter.h"
#include "key_auto_repeat.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventNormalize"

namespace OHOS {
namespace MMI {
namespace {
constexpr uint32_t KEYSTATUS { 0 };
constexpr int32_t SWAP_VOLUME_KEYS_ON_FOLD { 0 };
static const std::set<int32_t> g_ModifierKeys = {
    KeyEvent::KEYCODE_ALT_LEFT,
    KeyEvent::KEYCODE_ALT_RIGHT,
    KeyEvent::KEYCODE_SHIFT_LEFT,
    KeyEvent::KEYCODE_SHIFT_RIGHT,
    KeyEvent::KEYCODE_CTRL_LEFT,
    KeyEvent::KEYCODE_CTRL_RIGHT,
    KeyEvent::KEYCODE_META_LEFT,
    KeyEvent::KEYCODE_META_RIGHT,
    KeyEvent::KEYCODE_CAPS_LOCK,
    KeyEvent::KEYCODE_SCROLL_LOCK,
    KeyEvent::KEYCODE_NUM_LOCK
};
constexpr int32_t MAX_TIMEOUT_MS { 10000 };

class FoldStatusCallback : public Rosen::DisplayManagerLite::IFoldStatusListener {
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
    Rosen::DisplayManagerLite::GetInstance().RegisterFoldStatusListener(g_foldStatusCallback);
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
    MMI_HILOGD("The linux input:%{private}d", keyCode);
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
            MMI_HILOGE("Find pressed key failed:%{private}d", keyCode);
        }
        keyEvent->RemoveReleasedKeyItems(item);
        keyEvent->AddPressedKeyItems(item);
    }
}

void KeyEventNormalize::SyncLedStateFromKeyEvent(struct libinput_device* device)
{
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    CHKPV(device);
    if (INPUT_DEV_MGR->IsKeyboardDevice(device) &&
        INPUT_DEV_MGR->IsVirtualKeyboardDeviceEverConnected() && libinput_has_event_led_type(device)) {
        if (keyEvent_ == nullptr) {
            keyEvent_ = KeyEvent::Create();
        }
        CHKPV(keyEvent_);
        const std::vector<int32_t> funcKeys = {
            KeyEvent::NUM_LOCK_FUNCTION_KEY,
            KeyEvent::CAPS_LOCK_FUNCTION_KEY,
            KeyEvent::SCROLL_LOCK_FUNCTION_KEY
        };
        for (const auto &funcKey : funcKeys) {
            LibinputAdapter::DeviceLedUpdate(device, funcKey, keyEvent_->GetFunctionKey(funcKey));
        }
        MMI_HILOGI("Sync led state of added device from keyEvent");
    }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
}

void KeyEventNormalize::ResetKeyEvent(struct libinput_device* device)
{
    if (INPUT_DEV_MGR->IsKeyboardDevice(device) || INPUT_DEV_MGR->IsPointerDevice(device)) {
        if (keyEvent_ == nullptr) {
            keyEvent_ = KeyEvent::Create();
        }
        if (libinput_has_event_led_type(device)) {
            CHKPV(keyEvent_);
            const std::vector<int32_t> funcKeys = {
                KeyEvent::NUM_LOCK_FUNCTION_KEY,
                KeyEvent::CAPS_LOCK_FUNCTION_KEY,
                KeyEvent::SCROLL_LOCK_FUNCTION_KEY
            };
            for (const auto &funcKey : funcKeys) {
                keyEvent_->SetFunctionKey(funcKey, libinput_get_funckey_state(device, funcKey));
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
    JsonParser parser(cfg.c_str());
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("Not json format");
        return;
    }
    cJSON *jsonKeyboard = cJSON_GetObjectItemCaseSensitive(parser.Get(), "keyboard");
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
    std::vector<std::string> flipVolumeProduct;
    if (MISC_PRODUCT_TYPE_PARSER.GetFlipVolumeSupportedProduct(flipVolumeProduct) != RET_OK) {
        MMI_HILOGE("GetFlipVolumeSupportedProduct failed");
    }
    std::string product = OHOS::system::GetParameter("const.build.product", "");
    auto iter = std::find(flipVolumeProduct.begin(), flipVolumeProduct.end(), product);
    if (iter != flipVolumeProduct.end()) {
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

void KeyEventNormalize::SyncSwitchFunctionKeyState(const std::shared_ptr<KeyEvent> &keyEvent, int32_t funcKeyCode)
{
    if (keyEvent == nullptr) {
        MMI_HILOGE("KeyEvent is null");
        return;
    }
    if (functionKey == KeyEvent::UNKNOWN_FUNCTION_KEY) {
        return;
    }
    auto g_keyEvent = KeyEventHdr->GetKeyEvent();
    CHKPV(g_keyEvent);

    std::vector<struct libinput_device*> input_devices;
    int32_t deviceId = -1;
    INPUT_DEV_MGR->GetMultiKeyboardDevice(input_devices);
    if (input_devices.empty()) {
        MMI_HILOGW("No keyboard device is currently available");
        return;
    }
    bool preState = g_keyEvent->GetFunctionKey(functionKey);
    for (auto& device : input_devices) {
        deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
        if (LibinputAdapter::DeviceLedUpdate(device, functionKey, !preState) != RET_OK) {
            MMI_HILOGW("Failed to set the keyboard led, device id %{public}d", deviceId);
            continue;
        }
        int32_t state = libinput_get_funckey_state(device, functionKey);
        if (state != !preState) {
            MMI_HILOGW("Failed to enable the function key, device id %{public}d", deviceId);
        }
    }
    keyEvent->SetFunctionKey(functionKey, !preState);
    g_keyEvent->SetFunctionKey(functionKey, !preState);
    return;
}

bool KeyEventNormalize::HandleModifierKeyDown(const std::shared_ptr<KeyEvent> &keyEvent)
{
    CHKPF(keyEvent);
    auto keyItem = keyEvent->GetKeyItem();
    CHK_KEY_ITEM(keyItem);
    auto g_keyEvent = KeyEventHdr->GetKeyEvent();
    CHKPF(g_keyEvent);

    int32_t keyCode = keyEvent->GetKeyCode();
    int32_t repeatKeyCode = KeyRepeat->GetRepeatKeyCode();
    auto g_preKeyItem = g_keyEvent->GetKeyItem(keyCode);

    keyItem->SetPressed(true);
    if (repeatKeyCode != keyCode) {
        KeyRepeat->RemoveTimer();
        KeyRepeat->SetRepeatKeyCode(keyCode);
    }
    if (g_preKeyItem) {
        if (g_preKeyItem->IsPressed()) {
            g_preKeyItem->SetDownTime(keyItem->GetDownTime());
            return true;
        }
        g_keyEvent->RemoveReleasedKeyItems(*g_preKeyItem);
    }
    int32_t functionKey = g_keyEvent->TransitionFunctionKey(keyCode);
    if (functionKey != KeyEvent::UNKNOWN_FUNCTION_KEY) {
        SyncSwitchFunctionKeyState(keyEvent, functionKey);
    }
    g_keyEvent->AddPressedKeyItems(*keyItem);
    return true;
}

bool KeyEventNormalize::HandleModifierKeyUp(const std::shared_ptr<KeyEvent> &keyEvent)
{
    CHKPF(keyEvent);
    auto keyItem = keyEvent->GetKeyItem();
    CHK_KEY_ITEM(keyItem);
    auto g_keyEvent = KeyEventHdr->GetKeyEvent();
    CHKPF(g_keyEvent);

    int32_t keyCode = keyEvent->GetKeyCode();
    int32_t repeatKeyCode = KeyRepeat->GetRepeatKeyCode();
    auto g_preKeyItem = g_keyEvent->GetKeyItem(keyCode);

    keyItem->SetPressed(false);
    if (!g_preKeyItem) {
        return false;
    }
    if (!g_preKeyItem->IsPressed()) {
        return false;
    }
    g_keyEvent->RemoveReleasedKeyItems(*keyItem);
    g_keyEvent->AddPressedKeyItems(*keyItem);
    if (repeatKeyCode == keyCode) {
        KeyRepeat->RemoveTimer();
        KeyRepeat->SetRepeatKeyCode(keyCode);
    }
    g_keyEvent->AddPressedKeyItems(*keyItem);
    return true;
}

bool KeyEventNormalize::HandleModifierKeyAction(const std::shared_ptr<KeyEvent> &keyEvent)
{
    CHKPF(keyEvent);
    int32_t keyAction = keyEvent->GetKeyAction();
    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        return HandleModifierKeyDown(keyEvent);
    } else if (keyAction == KeyEvent::KEY_ACTION_UP) {
        return HandleModifierKeyUp(keyEvent);
    }
    return false;
}

void KeyEventNormalize::ModifierkeyEventNormalize(const std::shared_ptr<KeyEvent> &keyEvent)
{
    CHKPV(keyEvent);
    if (!keyEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE)) {
        return;
    }
    auto it = find(g_ModifierKeys.begin(), g_ModifierKeys.end(), keyEvent->GetKeyCode());
    if (it == g_ModifierKeys.end()) {
        return;
    }
    if (keyEvent->HasFlag(KeyEvent::EVENT_FLAG_SHELL)) {
        if (!keyStatusRecordSwitch_) {
            return;
        }
        int32_t funcKey = keyEvent->TransitionFunctionKey(keyEvent->GetKeyCode());
        if (funcKey != KeyEvent::UNKNOWN_FUNCTION_KEY) {
            return;
        }
    }
    auto g_keyEvent = KeyEventHdr->GetKeyEvent();
    if (g_keyEvent == nullptr) {
        return;
    }
    g_keyEvent->RemoveReleasedKeyItems();
    if (HandleModifierKeyAction(keyEvent)) {
        int32_t keyAction = keyEvent->GetKeyAction();
        if (keyAction == KeyEvent::KEY_ACTION_DOWN && keyStatusRecordSwitch_
            && keyEvent->HasFlag(KeyEvent::EVENT_FLAG_SHELL)) {
            KeyEventAutoUp(keyEvent, keyStatusRecordTimeout_);
        }
        g_keyEvent->SetKeyCode(keyEvent->GetKeyCode());
        g_keyEvent->SetAction(keyEvent->GetKeyAction());
        g_keyEvent->SetKeyAction(keyEvent->GetKeyAction());
        g_keyEvent->SetDeviceId(keyEvent->GetDeviceId());
        g_keyEvent->SetActionTime(keyEvent->GetActionTime());
        g_keyEvent->SetSourceType(InputEvent::SOURCE_TYPE_UNKNOWN);
    }
}

int32_t KeyEventNormalize::KeyEventAutoUp(const std::shared_ptr<KeyEvent>& keyEvent, int32_t timeout)
{
    if (timeout <= 0 || timeout > MAX_TIMEOUT_MS) {
        timeout = MAX_TIMEOUT_MS;
    }
    int32_t timerId = TimerMgr->AddTimer(timeout, 1, [keyEvent]() {
        CHKPV(keyEvent);
        auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
        CHKPV(inputEventNormalizeHandler);
        int64_t time = GetSysClockTime();
        auto keyItem = keyEvent->GetKeyItem();
        if (keyItem.has_value()) {
            keyItem->SetPressed(false);
            keyItem->SetDownTime(time);
        }
        keyEvent->RemoveReleasedKeyItems(*keyItem);
        keyEvent->AddPressedKeyItems(*keyItem);
        keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
        keyEvent->SetActionTime(time);
        LogTracer lt(keyEvent->GetId(), keyEvent->GetEventType(), keyEvent->GetKeyAction());
        inputEventNormalizeHandler->HandleKeyEvent(keyEvent);
        keyEvent->UpdateId();
    }, "KeyEventAutoUp");
    return timerId;
}

void KeyEventNormalize::SetKeyStatusRecord(bool enable, int32_t timeout)
{
    keyStatusRecordSwitch_ = enable;
    keyStatusRecordTimeout_ = timeout;
}
} // namespace MMI
} // namespace OHOS
