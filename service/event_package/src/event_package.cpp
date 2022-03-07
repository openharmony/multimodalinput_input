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

#include "event_package.h"
#include "input_device_manager.h"
namespace OHOS {
namespace MMI {
namespace {
const std::string VIRTUAL_KEYBOARD = "virtual_keyboard";
constexpr uint32_t SEAT_KEY_COUNT_ONE = 1;
constexpr uint32_t SEAT_KEY_COUNT_ZERO = 0;
}

EventPackage::EventPackage() {}

EventPackage::~EventPackage() {}

int32_t EventPackage::PackageKeyEvent(struct libinput_event *event, EventKeyboard& key)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto data = libinput_event_get_keyboard_event(event);
    CHKPR(data, ERROR_NULL_POINTER);
    key.key = static_cast<int32_t>(libinput_event_keyboard_get_key(data));
    if (libinput_event_keyboard_get_key_state(data) == 0) {
        key.state = KEY_STATE_RELEASED;
    } else {
        key.state = KEY_STATE_PRESSED;
    }
    key.seat_key_count = static_cast<int32_t>(libinput_event_keyboard_get_seat_key_count(data));
    key.time = static_cast<int64_t>(libinput_event_keyboard_get_time_usec(data));
    if (key.state == KEY_STATE_PRESSED && key.seat_key_count != 1) {
        MMI_LOGD("The same button is pressed on multiple devices, state:%{puiblic}d", key.state);
        return MULTIDEVICE_SAME_EVENT_MARK;
    }
    if (key.state == KEY_STATE_RELEASED && key.seat_key_count != 0) {
        MMI_LOGD("Release the same button on multiple devices, state:%{puiblic}d", key.state);
        return MULTIDEVICE_SAME_EVENT_MARK;
    }
    return RET_OK;
}

int32_t EventPackage::PackageKeyEvent(struct libinput_event *event, std::shared_ptr<KeyEvent> kevn)
{
    MMI_LOGD("enter");
    CHKPR(event, PARAM_INPUT_INVALID);
    CHKPR(kevn, ERROR_NULL_POINTER);
    kevn->UpdateId();
    auto data = libinput_event_get_keyboard_event(event);
    CHKPR(data, ERROR_NULL_POINTER);
    auto oKey = KeyValueTransformationInput(libinput_event_keyboard_get_key(data));

    auto device = libinput_event_get_device(event);
    int32_t deviceId = InputDevMgr->FindInputDeviceId(device);
    int32_t keyCode = static_cast<int32_t>(oKey.keyValueOfSys);
    int32_t keyAction = (libinput_event_keyboard_get_key_state(data) == 0) ?
        (KeyEvent::KEY_ACTION_UP) : (KeyEvent::KEY_ACTION_DOWN);
    int64_t actionStartTime = static_cast<int64_t>(libinput_event_keyboard_get_time_usec(data));

    kevn->SetActionTime(GetSysClockTime());
    kevn->SetAction(keyAction);
    kevn->SetActionStartTime(actionStartTime);
    kevn->SetDeviceId(deviceId);
    kevn->SetKeyCode(keyCode);
    kevn->SetKeyAction(keyAction);

    KeyEvent::KeyItem item;
    bool isKeyPressed = (libinput_event_keyboard_get_key_state(data) != KEYSTATUS);
    if (isKeyPressed) {
        int64_t keyDownTime = actionStartTime;
        item.SetDownTime(keyDownTime);
    }
    item.SetKeyCode(keyCode);
    item.SetDeviceId(deviceId);
    item.SetPressed(isKeyPressed);

    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        kevn->AddPressedKeyItems(item);
    } else {
        kevn->RemoveReleasedKeyItems(item);
    }
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t EventPackage::PackageVirtualKeyEvent(VirtualKey& event, EventKeyboard& key)
{
    const std::string uid = GetUUid();
    int32_t ret = memcpy_s(key.uuid, MAX_UUIDSIZE, uid.c_str(), uid.size());
    if (ret != EOK) {
        MMI_LOGE("Memcpy data failed");
        return RET_ERR;
    }
    ret = memcpy_s(key.deviceName, MAX_UUIDSIZE, VIRTUAL_KEYBOARD.c_str(), VIRTUAL_KEYBOARD.size());
    if (ret != EOK) {
        MMI_LOGE("Memcpy data failed");
        return RET_ERR;
    }
    key.time = event.keyDownDuration;
    key.key = event.keyCode;
    key.isIntercepted = event.isIntercepted;
    key.state = (enum KEY_STATE)event.isPressed;
    key.eventType = LIBINPUT_EVENT_KEYBOARD_KEY;
    key.deviceType = DEVICE_TYPE_VIRTUAL_KEYBOARD;
    key.unicode = 0;
    if (event.isPressed) {
        key.seat_key_count = SEAT_KEY_COUNT_ONE;
    } else {
        key.seat_key_count = SEAT_KEY_COUNT_ZERO;
    }
    return RET_OK;
}

int32_t EventPackage::KeyboardToKeyEvent(const EventKeyboard& key, std::shared_ptr<KeyEvent> keyEventPtr)
{
    CHKPR(keyEventPtr, ERROR_NULL_POINTER);
    keyEventPtr->UpdateId();
    KeyEvent::KeyItem keyItem;
    int32_t keyCode = static_cast<int32_t>(key.key);
    int32_t keyAction = (key.state == KEY_STATE_PRESSED) ?
        (KeyEvent::KEY_ACTION_DOWN) : (KeyEvent::KEY_ACTION_UP);
    int32_t deviceId = key.deviceId;
    auto preAction = keyEventPtr->GetAction();
    if (preAction == KeyEvent::KEY_ACTION_UP) {
        auto preUpKeyItem = keyEventPtr->GetKeyItem();
        if (preUpKeyItem != nullptr) {
            keyEventPtr->RemoveReleasedKeyItems(*preUpKeyItem);
        } else {
            MMI_LOGE("preUpKeyItem is null");
        }
    }

    int64_t time = GetSysClockTime();
    keyEventPtr->SetActionTime(time);
    keyEventPtr->SetAction(keyAction);
    keyEventPtr->SetDeviceId(deviceId);
    keyEventPtr->SetKeyCode(keyCode);
    keyEventPtr->SetKeyAction(keyAction);

    if (keyEventPtr->GetPressedKeys().empty()) {
        keyEventPtr->SetActionStartTime(time);
    }

    bool isKeyPressed = (key.state == KEY_STATE_PRESSED) ? (true) : (false);
    keyItem.SetDownTime(time);
    keyItem.SetKeyCode(keyCode);
    keyItem.SetDeviceId(deviceId);
    keyItem.SetPressed(isKeyPressed);

    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        keyEventPtr->AddPressedKeyItems(keyItem);
    } else if (keyAction == KeyEvent::KEY_ACTION_UP) {
        auto pressedKeyItem = keyEventPtr->GetKeyItem(keyCode);
        if (pressedKeyItem != nullptr) {
            keyItem.SetDownTime(pressedKeyItem->GetDownTime());
        } else {
            MMI_LOGE("Find pressed key failed, keyCode:%{public}d", keyCode);
        }
        keyEventPtr->RemoveReleasedKeyItems(keyItem);
        keyEventPtr->AddPressedKeyItems(keyItem);
    } else {
        // nothing to do.
    }
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
