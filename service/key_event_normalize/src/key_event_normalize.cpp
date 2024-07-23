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

#include "input_device_manager.h"
#include "key_map_manager.h"
#include "key_unicode_transformation.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventNormalize"

namespace OHOS {
namespace MMI {
namespace {
constexpr uint32_t KEYSTATUS { 0 };
} // namespace

KeyEventNormalize::KeyEventNormalize() {}

KeyEventNormalize::~KeyEventNormalize() {}

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
    keyCode = KeyMapMgr->TransferDeviceKeyValue(device, keyCode);
    int32_t keyAction = (libinput_event_keyboard_get_key_state(data) == 0) ?
        (KeyEvent::KEY_ACTION_UP) : (KeyEvent::KEY_ACTION_DOWN);
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
            int32_t ret = keyEvent->SetFunctionKey(funcKey, libinput_get_funckey_state(device, funcKey));
            if (ret == funcKey) {
                MMI_HILOGD("Set function key:%{public}d to state:%{public}d succeed",
                           funcKey, keyEvent->GetFunctionKey(funcKey));
            }
        }
        std::optional<KeyEvent::KeyItem> pressedKeyItem = keyEvent->GetKeyItem(keyCode);
        if (pressedKeyItem) {
            item.SetDownTime(pressedKeyItem->GetDownTime());
        } else {
            MMI_HILOGE("Find pressed key failed, keyCode:%{public}d", keyCode);
        }
        keyEvent->RemoveReleasedKeyItems(item);
        keyEvent->AddPressedKeyItems(item);
    }
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
    MMI_HILOGD("Last shield mode:%{public}d, set shield mode:%{public}d, status:%{public}d",
        lastShieldMode_, shieldMode, isShield);
    auto iter = shieldStatus_.find(lastShieldMode_);
    if (isShield) {
        if (lastShieldMode_ == shieldMode) {
            MMI_HILOGD("Last shield mode equal with shield mode");
            return RET_OK;
        } else if (iter != shieldStatus_.end()) {
            iter->second = false;
        } else {
            MMI_HILOGD("Last shield mode unset");
        }
        lastShieldMode_ = shieldMode;
    } else if (lastShieldMode_ != shieldMode) {
        MMI_HILOGD("Shield mode:%{public}d is already false", shieldMode);
        return RET_OK;
    } else {
        MMI_HILOGD("lastShieldMode_ unset");
        lastShieldMode_ = SHIELD_MODE::UNSET_MODE;
    }
    iter = shieldStatus_.find(shieldMode);
    if (iter == shieldStatus_.end()) {
        MMI_HILOGE("Find shieldMode:%{public}d failed", shieldMode);
        return RET_ERR;
    }
    iter->second = isShield;
    MMI_HILOGD("Last shield mode:%{public}d, set shield mode:%{public}d, status:%{public}d",
        lastShieldMode_, shieldMode, isShield);
    return RET_OK;
}

int32_t KeyEventNormalize::GetShieldStatus(int32_t shieldMode, bool &isShield)
{
    CALL_DEBUG_ENTER;
    auto iter = shieldStatus_.find(shieldMode);
    if (iter == shieldStatus_.end()) {
        MMI_HILOGE("Find shieldMode:%{public}d failed", shieldMode);
        return RET_ERR;
    }
    isShield = iter->second;
    MMI_HILOGD("Last shield mode:%{public}d, get shield mode:%{public}d, status:%{public}d",
        lastShieldMode_, shieldMode, isShield);
    return RET_OK;
}

int32_t KeyEventNormalize::GetCurrentShieldMode()
{
    return lastShieldMode_;
}
void KeyEventNormalize::SetCurrentShieldMode(int32_t shieldMode)
{
    lastShieldMode_ = shieldMode;
}
} // namespace MMI
} // namespace OHOS
