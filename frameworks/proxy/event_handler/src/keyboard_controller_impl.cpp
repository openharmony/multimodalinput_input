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

#include "keyboard_controller_impl.h"

#include <algorithm>

#include "define_multimodal.h"
#include "input_manager.h"
#include "mmi_log.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyboardControllerImpl"

namespace OHOS {
namespace MMI {

namespace {
constexpr int32_t ERROR_CODE_KEY_STATE_ERROR = 4300001;  // Key state error
} // namespace

KeyboardControllerImpl::KeyboardControllerImpl()
{
    MMI_HILOGD("KeyboardControllerImpl created");
}

KeyboardControllerImpl::~KeyboardControllerImpl()
{
    MMI_HILOGD("KeyboardControllerImpl destroying, cleaning up state");

    // Auto cleanup: Release all pressed keys
    // Note: Copy the vector because we'll be modifying pressedKeys_
    std::vector<int32_t> keysToRelease = pressedKeys_;
    for (int32_t keyCode : keysToRelease) {
        MMI_HILOGW("Auto-releasing key %{public}d in destructor", keyCode);

        // Directly create and inject KEY_UP event (bypass state validation)
        auto keyEvent = CreateKeyEvent(KeyEvent::KEY_ACTION_UP, keyCode);
        if (keyEvent != nullptr) {
            int32_t ret = InjectKeyEvent(keyEvent);
            if (ret != RET_OK) {
                MMI_HILOGE("Failed to auto-release key %{public}d, ret=%{public}d", keyCode, ret);
                // Continue trying to release other keys
            }
        } else {
            MMI_HILOGE("Failed to create key event for key %{public}d", keyCode);
        }

        // Remove from state regardless of injection result (force cleanup)
        auto it = std::find(pressedKeys_.begin(), pressedKeys_.end(), keyCode);
        if (it != pressedKeys_.end()) {
            pressedKeys_.erase(it);
        }
        keyDownTimes_.erase(keyCode);
    }

    // Ensure all state is cleared
    pressedKeys_.clear();
    keyDownTimes_.clear();
}

int32_t KeyboardControllerImpl::PressKey(int32_t keyCode)
{
    MMI_HILOGD("PressKey: keyCode=%{public}d", keyCode);

    bool isNewKey = false;
    std::shared_ptr<KeyEvent> keyEvent;

    // Lock scope: state check, modification, and event creation
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // 1. Check if key is already pressed
        auto it = std::find(pressedKeys_.begin(), pressedKeys_.end(), keyCode);
        if (it != pressedKeys_.end()) {
            // Key already pressed, check if it's the last pressed key
            if (pressedKeys_.back() != keyCode) {
                MMI_HILOGE("Key %{public}d already pressed but not last pressed key", keyCode);
                return ERROR_CODE_KEY_STATE_ERROR;
            }
            // Allow repeating the last pressed key (for recording/playback scenario)
            MMI_HILOGD("Repeat press last key: %{public}d", keyCode);
        } else {
            // 2. New key, check if maximum number exceeded
            if (pressedKeys_.size() >= MAX_PRESSED_KEYS) {
                MMI_HILOGE("Maximum %{public}zu keys already pressed", MAX_PRESSED_KEYS);
                return ERROR_CODE_KEY_STATE_ERROR;
            }

            // 3. Add to pressed keys vector and record down time
            pressedKeys_.push_back(keyCode);
            keyDownTimes_[keyCode] = GetSysClockTime();
            isNewKey = true;
        }

        // 4. Create KEY_DOWN event (needs to read state)
        keyEvent = CreateKeyEvent(KeyEvent::KEY_ACTION_DOWN, keyCode);
        if (keyEvent == nullptr) {
            MMI_HILOGE("Failed to create key event");
            // Rollback state
            if (isNewKey) {
                pressedKeys_.pop_back();
                keyDownTimes_.erase(keyCode);
            }
            return RET_ERR;
        }
    }
    // Lock released here

    // 5. Inject event outside lock (may involve IPC)
    int32_t ret = InjectKeyEvent(keyEvent);
    if (ret != RET_OK) {
        // Rollback state on failure
        if (isNewKey) {
            std::lock_guard<std::mutex> lock(mutex_);
            pressedKeys_.pop_back();
            keyDownTimes_.erase(keyCode);
        }
    }

    return ret;
}

int32_t KeyboardControllerImpl::ReleaseKey(int32_t keyCode)
{
    MMI_HILOGD("ReleaseKey: keyCode=%{public}d", keyCode);

    std::shared_ptr<KeyEvent> keyEvent;
    std::vector<int32_t>::iterator it;

    // Lock scope: state check and event creation
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // 1. Check if key is pressed
        it = std::find(pressedKeys_.begin(), pressedKeys_.end(), keyCode);
        if (it == pressedKeys_.end()) {
            MMI_HILOGE("Key %{public}d not pressed", keyCode);
            return ERROR_CODE_KEY_STATE_ERROR;
        }

        // 2. Create KEY_UP event (needs to read state)
        keyEvent = CreateKeyEvent(KeyEvent::KEY_ACTION_UP, keyCode);
        if (keyEvent == nullptr) {
            MMI_HILOGE("Failed to create key event");
            return RET_ERR;
        }
    }
    // Lock released here

    // 3. Inject event outside lock (may involve IPC)
    int32_t ret = InjectKeyEvent(keyEvent);
    if (ret == RET_OK) {
        // 4. Remove from pressed keys vector and clear down time
        std::lock_guard<std::mutex> lock(mutex_);
        // Re-find the iterator since we released the lock
        it = std::find(pressedKeys_.begin(), pressedKeys_.end(), keyCode);
        if (it != pressedKeys_.end()) {
            pressedKeys_.erase(it);
        }
        keyDownTimes_.erase(keyCode);
    }

    return ret;
}

std::shared_ptr<KeyEvent> KeyboardControllerImpl::CreateKeyEvent(int32_t action, int32_t keyCode)
{
    auto keyEvent = KeyEvent::Create();
    if (keyEvent == nullptr) {
        MMI_HILOGE("Failed to create KeyEvent");
        return nullptr;
    }

    // Set basic properties
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(action); // KEY_ACTION_DOWN / KEY_ACTION_UP

    // Set timestamp
    int64_t time = GetSysClockTime();
    keyEvent->SetActionTime(time);

    // Set DeviceId (virtual device)
    keyEvent->SetDeviceId(-1);

    // Mark as simulated event (triggers server-side auto-repeat)
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);

    // Add KeyItem for the current key action
    KeyEvent::KeyItem item;
    item.SetKeyCode(keyCode);
    item.SetPressed(action == KeyEvent::KEY_ACTION_DOWN);
    item.SetDownTime(action == KeyEvent::KEY_ACTION_DOWN ? time : keyDownTimes_[keyCode]);
    item.SetDeviceId(-1);
    keyEvent->AddKeyItem(item);

    // Add all currently pressed keys to the event (excluding the current key)
    // For KEY_DOWN: add other pressed keys
    // For KEY_UP: add all pressed keys except the one being released
    int32_t addedCount = 0;
    for (int32_t pressedKey : pressedKeys_) {
        // Skip the current key (already added via AddKeyItem)
        if (pressedKey == keyCode) {
            // For KEY_DOWN, the current key is in pressedKeys_ and already added
            // For KEY_UP, the current key is still in pressedKeys_ but being released
            if (action == KeyEvent::KEY_ACTION_DOWN) {
                MMI_HILOGD("Skip adding key %{public}d to pressedKeys (already in KeyItem for KEY_DOWN)", keyCode);
                continue;  // Already added via AddKeyItem
            } else {
                MMI_HILOGD("Skip adding key %{public}d to pressedKeys (being released in KEY_UP)", keyCode);
                continue;  // Don't add the key being released to pressed keys
            }
        }

        // Add other pressed keys
        KeyEvent::KeyItem pressedItem;
        pressedItem.SetKeyCode(pressedKey);
        pressedItem.SetPressed(true);
        pressedItem.SetDownTime(keyDownTimes_[pressedKey]);  // Use actual down time
        pressedItem.SetDeviceId(-1);
        keyEvent->AddPressedKeyItems(pressedItem);
        addedCount++;
    }

    MMI_HILOGD("CreateKeyEvent: action=%{public}d, keyCode=%{public}d, added %{public}d other pressed keys",
        action, keyCode, addedCount);

    return keyEvent;
}

int32_t KeyboardControllerImpl::InjectKeyEvent(std::shared_ptr<KeyEvent> event)
{
    if (event == nullptr) {
        MMI_HILOGE("KeyEvent is nullptr");
        return RET_ERR;
    }

    // Add Controller Flag to mark this event uses CONTROL_DEVICE permission check
    event->AddFlag(InputEvent::EVENT_FLAG_CONTROLLER);

    // Inject event using InputManager
    // Note: SimulateInputEvent returns void, so we assume success
    InputManager::GetInstance()->SimulateInputEvent(event);

    return RET_OK;
}

} // namespace MMI
} // namespace OHOS
