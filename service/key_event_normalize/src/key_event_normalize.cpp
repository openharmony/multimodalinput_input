/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "key_event_normalize.h"

#include "input_device_manager.h"
#include "key_map_manager.h"
#include "key_unicode_transformation.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KeyEventNormalize" };
constexpr uint32_t KEYSTATUS = 0;
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
    auto data = libinput_event_get_keyboard_event(event);
    CHKPR(data, ERROR_NULL_POINTER);

    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
    int32_t deviceId = InputDevMgr->FindInputDeviceId(device);
    int32_t keyCode = static_cast<int32_t>(libinput_event_keyboard_get_key(data));
    MMI_HILOGD("The linux input keyCode:%{public}d", keyCode);
    keyCode = KeyMapMgr->TransferDeviceKeyValue(device, keyCode);
    int32_t keyAction = (libinput_event_keyboard_get_key_state(data) == 0) ?
        (KeyEvent::KEY_ACTION_UP) : (KeyEvent::KEY_ACTION_DOWN);
    auto preAction = keyEvent->GetAction();
    if (preAction == KeyEvent::KEY_ACTION_UP) {
        auto preUpKeyItem = keyEvent->GetKeyItem();
        if (preUpKeyItem != nullptr) {
            keyEvent->RemoveReleasedKeyItems(*preUpKeyItem);
        } else {
            MMI_HILOGE("The preUpKeyItem is null");
        }
    }
    int64_t time = GetSysClockTime();
    keyEvent->SetActionTime(time);
    keyEvent->SetAction(keyAction);
    keyEvent->SetDeviceId(deviceId);
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(keyAction);
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

    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        keyEvent->AddPressedKeyItems(item);
    }
    if (keyAction == KeyEvent::KEY_ACTION_UP) {
        int32_t funcKey = keyEvent->TransitionFunctionKey(keyCode);
        if (funcKey != KeyEvent::UNKOWN_FUNCTION_KEY) {
            int32_t ret = keyEvent->SetFunctionKey(funcKey, libinput_get_funckey_state(device, funcKey));
            if (ret == funcKey) {
                MMI_HILOGD("Set function key:%{public}d to state:%{public}d succeed",
                           funcKey, keyEvent->GetFunctionKey(funcKey));
            }
        }
        auto pressedKeyItem = keyEvent->GetKeyItem(keyCode);
        if (pressedKeyItem != nullptr) {
            item.SetDownTime(pressedKeyItem->GetDownTime());
        } else {
            MMI_HILOGE("Find pressed key failed, keyCode:%{public}d", keyCode);
        }
        keyEvent->RemoveReleasedKeyItems(item);
        keyEvent->AddPressedKeyItems(item);
    }
    return RET_OK;
}

void KeyEventNormalize::ResetKeyEvent(struct libinput_device* device)
{
    if (InputDevMgr->IsKeyboardDevice(device) || InputDevMgr->IsPointerDevice(device)) {
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
} // namespace MMI
} // namespace OHOS
