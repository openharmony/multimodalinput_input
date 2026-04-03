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

#include "device_state_manager.h"

#include "define_multimodal.h"
#include "input_device_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DeviceStateManager"

namespace OHOS {
namespace MMI {

// DeviceState implementation
DeviceStateManager::DeviceState::DeviceState(int32_t deviceId)
    : deviceId_(deviceId)
{
    MMI_HILOGD("DeviceState created for device %{public}d", deviceId_);
}

DeviceStateManager::DeviceState::DeviceState(DeviceState &&other)
    : deviceId_(other.deviceId_),
      enabled_(other.enabled_),
      isProximity_(other.isProximity_),
      isPressed_(other.isPressed_),
      isAxisBegin_(other.isAxisBegin_),
      touches_(std::move(other.touches_)),
      pressedButtons_(std::move(other.pressedButtons_)),
      pressedKeys_(std::move(other.pressedKeys_)),
      pendingEnableCallback_(std::move(other.pendingEnableCallback_))
{
    other.deviceId_ = -1;
    other.enabled_ = true;
    other.isProximity_ = false;
    other.isPressed_ = false;
    other.isAxisBegin_ = false;
    other.pendingEnableCallback_ = nullptr;
}

DeviceStateManager::DeviceState& DeviceStateManager::DeviceState::operator=(DeviceState &&other)
{
    if (this == &other) {
        return *this;
    }

    deviceId_ = other.deviceId_;
    enabled_ = other.enabled_;
    isProximity_ = other.isProximity_;
    isPressed_ = other.isPressed_;
    isAxisBegin_ = other.isAxisBegin_;
    touches_ = std::move(other.touches_);
    pressedButtons_ = std::move(other.pressedButtons_);
    pressedKeys_ = std::move(other.pressedKeys_);
    pendingEnableCallback_ = std::move(other.pendingEnableCallback_);

    other.deviceId_ = -1;
    other.enabled_ = true;
    other.isProximity_ = false;
    other.isPressed_ = false;
    other.isAxisBegin_ = false;
    other.pendingEnableCallback_ = nullptr;

    return *this;
}

void DeviceStateManager::DeviceState::HandleEvent(struct libinput_event *event)
{
    CHKPV(event);
    auto device = libinput_event_get_device(event);
    CHKPV(device);

    auto eventType = libinput_event_get_type(event);
    switch (eventType) {
        case LIBINPUT_EVENT_TOUCH_DOWN:
        case LIBINPUT_EVENT_TOUCH_UP: {
            HandleTouchEvent(event);
            break;
        }
        case LIBINPUT_EVENT_TOUCHPAD_DOWN:
        case LIBINPUT_EVENT_TOUCHPAD_UP: {
            HandleTouchpadEvent(event);
            break;
        }
        case LIBINPUT_EVENT_POINTER_SCROLL_FINGER_END: {
            HandlePointerAxisEvent(event);
            break;
        }
        case LIBINPUT_EVENT_POINTER_TAP:
        case LIBINPUT_EVENT_POINTER_BUTTON:
        case LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD: {
            HandlePointerButtonEvent(event);
            break;
        }
        case LIBINPUT_EVENT_KEYBOARD_KEY: {
            HandleKeyboardEvent(event);
            break;
        }
        case LIBINPUT_EVENT_TABLET_TOOL_AXIS:
        case LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY:
        case LIBINPUT_EVENT_TABLET_TOOL_TIP:
        case LIBINPUT_EVENT_TABLET_TOOL_BUTTON: {
            HandleTabletToolEvent(event);
            break;
        }
        case LIBINPUT_EVENT_JOYSTICK_BUTTON: {
            HandleJoystickButtonEvent(event);
            break;
        }
        default: {
            break;
        }
    }
}

void DeviceStateManager::DeviceState::AddTouches(const std::set<int32_t> &touches)
{
    touches_.insert(touches.begin(), touches.end());
}

void DeviceStateManager::DeviceState::AddPressedButtons(const std::set<int32_t> &pressedButtons)
{
    pressedButtons_.insert(pressedButtons.begin(), pressedButtons.end());
}

void DeviceStateManager::DeviceState::AddPressedKeys(const std::set<int32_t> &pressedKeys)
{
    pressedKeys_.insert(pressedKeys.begin(), pressedKeys.end());
}

void DeviceStateManager::DeviceState::SetProximity(bool proximity)
{
    isProximity_ = proximity;
}

void DeviceStateManager::DeviceState::SetAxisBegin(bool axisBegin)
{
    isAxisBegin_ = axisBegin;
}

bool DeviceStateManager::DeviceState::HaveActiveOperations() const
{
    return (!touches_.empty() ||
            !pressedButtons_.empty() ||
            !pressedKeys_.empty() ||
            isProximity_ ||
            isPressed_ ||
            isAxisBegin_);
}

void DeviceStateManager::DeviceState::Enable(EnableCallback callback)
{
    enabled_ = true;
    pendingEnableCallback_ = callback;
}

void DeviceStateManager::DeviceState::Disable()
{
    enabled_ = false;
    pendingEnableCallback_ = nullptr;
}

bool DeviceStateManager::DeviceState::IsEnabled() const
{
    return enabled_;
}

void DeviceStateManager::DeviceState::NotifyEnabled()
{
    if (pendingEnableCallback_) {
        pendingEnableCallback_(deviceId_);
    }
}

void DeviceStateManager::DeviceState::HandleTouchEvent(struct libinput_event *event)
{
    CHKPV(event);
    auto touchEvent = libinput_event_get_touch_event(event);
    CHKPV(touchEvent);
    auto eventType = libinput_event_get_type(event);
    auto slot = libinput_event_touch_get_seat_slot(touchEvent);

    switch (eventType) {
        case LIBINPUT_EVENT_TOUCH_DOWN: {
            touches_.insert(slot);
            MMI_HILOGD("Device[%{public}d]: touch down, slot=%{public}d", deviceId_, slot);
            break;
        }
        case LIBINPUT_EVENT_TOUCH_UP: {
            touches_.erase(slot);
            MMI_HILOGD("Device[%{public}d]: touch up, slot=%{public}d", deviceId_, slot);
            break;
        }
        default: {
            break;
        }
    }
}

void DeviceStateManager::DeviceState::HandlePointerAxisEvent(struct libinput_event *event)
{
    CHKPV(event);
    auto eventType = libinput_event_get_type(event);
    switch (eventType) {
        case LIBINPUT_EVENT_POINTER_SCROLL_FINGER_END: {
            isAxisBegin_ = false;
            break;
        }
        default: {
            break;
        }
    }
}

void DeviceStateManager::DeviceState::HandlePointerButtonEvent(struct libinput_event *event)
{
    CHKPV(event);
    auto pointerEvent = libinput_event_get_pointer_event(event);
    CHKPV(pointerEvent);
    uint32_t button = libinput_event_pointer_get_button(pointerEvent);
    auto buttonState = libinput_event_pointer_get_button_state(pointerEvent);
    if (buttonState == LIBINPUT_BUTTON_STATE_PRESSED) {
        pressedButtons_.insert(button);
        MMI_HILOGD("Device[%{public}d]: button pressed, button=%{public}u", deviceId_, button);
    } else {
        pressedButtons_.erase(button);
        MMI_HILOGD("Device[%{public}d]: button released, button=%{public}u", deviceId_, button);
    }
}

void DeviceStateManager::DeviceState::HandleTouchpadEvent(struct libinput_event *event)
{
    auto touchpadEvent = libinput_event_get_touchpad_event(event);
    CHKPV(touchpadEvent);
    auto eventType = libinput_event_get_type(event);
    auto slot = libinput_event_touchpad_get_seat_slot(touchpadEvent);

    switch (eventType) {
        case LIBINPUT_EVENT_TOUCHPAD_DOWN: {
            touches_.insert(slot);
            MMI_HILOGD("Device[%{public}d]: touchpad down, slot=%{public}d", deviceId_, slot);
            break;
        }
        case LIBINPUT_EVENT_TOUCHPAD_UP: {
            touches_.erase(slot);
            MMI_HILOGD("Device[%{public}d]: touchpad up, slot=%{public}d", deviceId_, slot);
            break;
        }
        default: {
            break;
        }
    }
}

void DeviceStateManager::DeviceState::HandleKeyboardEvent(struct libinput_event *event)
{
    CHKPV(event);
    auto keyboardEvent = libinput_event_get_keyboard_event(event);
    CHKPV(keyboardEvent);
    auto key = libinput_event_keyboard_get_key(keyboardEvent);
    auto keyState = libinput_event_keyboard_get_key_state(keyboardEvent);
    if (keyState == LIBINPUT_KEY_STATE_PRESSED) {
        pressedKeys_.insert(key);
        MMI_HILOGD("Device[%{public}d]: key pressed, key=%{public}u", deviceId_, key);
    } else {
        pressedKeys_.erase(key);
        MMI_HILOGD("Device[%{public}d]: key released, key=%{public}u", deviceId_, key);
    }
}

void DeviceStateManager::DeviceState::HandleTabletToolEvent(struct libinput_event *event)
{
    CHKPV(event);
    auto eventType = libinput_event_get_type(event);
    auto tabletEvent = libinput_event_get_tablet_tool_event(event);
    CHKPV(tabletEvent);

    switch (eventType) {
        case LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY: {
            auto proximityState = libinput_event_tablet_tool_get_proximity_state(tabletEvent);
            isProximity_ = (proximityState == LIBINPUT_TABLET_TOOL_PROXIMITY_STATE_IN);
            MMI_HILOGD("Device[%{public}d]: tablet tool proximity=%{public}d", deviceId_, isProximity_);
            break;
        }
        case LIBINPUT_EVENT_TABLET_TOOL_TIP: {
            auto tipState = libinput_event_tablet_tool_get_tip_state(tabletEvent);
            isPressed_ = (tipState == LIBINPUT_TABLET_TOOL_TIP_DOWN);
            MMI_HILOGD("Device[%{public}d]: tablet tool tip pressed=%{public}d", deviceId_, isPressed_);
            break;
        }
        case LIBINPUT_EVENT_TABLET_TOOL_BUTTON: {
            uint32_t button = libinput_event_tablet_tool_get_button(tabletEvent);
            auto buttonState = libinput_event_tablet_tool_get_button_state(tabletEvent);
            if (buttonState == LIBINPUT_BUTTON_STATE_PRESSED) {
                pressedButtons_.insert(button);
                MMI_HILOGD("Device[%{public}d]: tablet button pressed, button=%{public}u", deviceId_, button);
            } else {
                pressedButtons_.erase(button);
                MMI_HILOGD("Device[%{public}d]: tablet button released, button=%{public}u", deviceId_, button);
            }
            break;
        }
        default: {
            break;
        }
    }
}

void DeviceStateManager::DeviceState::HandleJoystickButtonEvent(struct libinput_event *event)
{
    CHKPV(event);
    auto rawBtnEvent = libinput_event_get_joystick_button_event(event);
    CHKPV(rawBtnEvent);
    auto rawCode = libinput_event_joystick_button_get_key(rawBtnEvent);
    auto rawBtnState = libinput_event_joystick_button_get_key_state(rawBtnEvent);
    if (rawBtnState != LIBINPUT_BUTTON_STATE_RELEASED) {
        pressedButtons_.emplace(rawCode);
    } else {
        pressedButtons_.erase(rawCode);
    }
}

std::shared_ptr<DeviceStateManager> DeviceStateManager::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<DeviceStateManager> instance_;

    std::call_once(flag, []() {
        instance_ = std::make_shared<DeviceStateManager>();
    });
    return instance_;
}

void DeviceStateManager::AddTouches(int32_t deviceId, const std::set<int32_t> &touches)
{
    auto it = deviceStates_.find(deviceId);
    if (it != deviceStates_.end()) {
        it->second.AddTouches(touches);
        MMI_HILOGI("Added device[%{public}d] with %{public}zu touches", deviceId, touches.size());
    } else {
        DeviceState state(deviceId);
        state.AddTouches(touches);
        deviceStates_.emplace(deviceId, std::move(state));
        MMI_HILOGI("Added %{public}zu touches to device[%{public}d]", touches.size(), deviceId);
    }
}

void DeviceStateManager::AddPressedButtons(int32_t deviceId, const std::set<int32_t> &pressedButtons)
{
    auto it = deviceStates_.find(deviceId);
    if (it != deviceStates_.end()) {
        it->second.AddPressedButtons(pressedButtons);
        MMI_HILOGI("Added device[%{public}d] with %{public}zu pressed buttons", deviceId, pressedButtons.size());
    } else {
        DeviceState state(deviceId);
        state.AddPressedButtons(pressedButtons);
        deviceStates_.emplace(deviceId, std::move(state));
        MMI_HILOGI("Added %{public}zu pressed buttons to device[%{public}d]", pressedButtons.size(), deviceId);
    }
}

void DeviceStateManager::AddPressedKeys(int32_t deviceId, const std::set<int32_t> &pressedKeys)
{
    auto it = deviceStates_.find(deviceId);
    if (it != deviceStates_.end()) {
        it->second.AddPressedKeys(pressedKeys);
        MMI_HILOGI("Added device[%{public}d] with %{public}zu pressed keys", deviceId, pressedKeys.size());
    } else {
        DeviceState state(deviceId);
        state.AddPressedKeys(pressedKeys);
        deviceStates_.emplace(deviceId, std::move(state));
        MMI_HILOGI("Added %{public}zu pressed keys to device[%{public}d]", pressedKeys.size(), deviceId);
    }
}

void DeviceStateManager::SetProximity(int32_t deviceId, bool proximity)
{
    auto it = deviceStates_.find(deviceId);
    if (it != deviceStates_.end()) {
        it->second.SetProximity(proximity);
        MMI_HILOGI("Set device[%{public}d] with proximity", deviceId);
    } else {
        DeviceState state(deviceId);
        state.SetProximity(proximity);
        deviceStates_.emplace(deviceId, std::move(state));
        MMI_HILOGI("Set proximity to device[%{public}d]", deviceId);
    }
}

void DeviceStateManager::SetAxisBegin(int32_t deviceId, bool axisBegin)
{
    auto it = deviceStates_.find(deviceId);
    if (it != deviceStates_.end()) {
        it->second.SetAxisBegin(axisBegin);
        MMI_HILOGI("Set device[%{public}d] with AxisBegin", deviceId);
    } else {
        DeviceState state(deviceId);
        state.SetAxisBegin(axisBegin);
        deviceStates_.emplace(deviceId, std::move(state));
        MMI_HILOGI("Set AxisBegin to device[%{public}d]", deviceId);
    }
}

void DeviceStateManager::EnableDevice(int32_t deviceId, EnableCallback callback)
{
    auto it = deviceStates_.find(deviceId);
    if (it == deviceStates_.end()) {
        MMI_HILOGI("No pending operations for device[%{public}d]", deviceId);
        if (callback) {
            callback(deviceId);
        }
        return;
    }

    if (!it->second.HaveActiveOperations()) {
        MMI_HILOGI("No active operations for device[%{public}d]", deviceId);
        deviceStates_.erase(it);
        if (callback) {
            callback(deviceId);
        }
        return;
    }

    it->second.Enable(callback);
    MMI_HILOGI("Device[%{public}d] has active operations, pending enable", deviceId);
}

void DeviceStateManager::DisableDevice(int32_t deviceId)
{
    MMI_HILOGI("Disable device[%{public}d]", deviceId);
    auto it = deviceStates_.find(deviceId);
    if (it == deviceStates_.end()) {
        MMI_HILOGI("No pending operations for device[%{public}d]", deviceId);
        return;
    }
    it->second.Disable();
}

void DeviceStateManager::HandleEvent(struct libinput_event *event)
{
    CHKPV(event);

    auto device = libinput_event_get_device(event);
    CHKPV(device);

    int32_t deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
    if (deviceId < 0) {
        MMI_HILOGW("Device not found");
        return;
    }

    auto it = deviceStates_.find(deviceId);
    if (it == deviceStates_.end()) {
        auto [tIter, _] = deviceStates_.emplace(deviceId, DeviceState(deviceId));
        it = tIter;
    }

    auto &state = it->second;
    state.HandleEvent(event);

    if (state.IsEnabled() && !state.HaveActiveOperations()) {
        MMI_HILOGI("Device[%{public}d] all operations ended, executing pending enable", deviceId);
        state.NotifyEnabled();
        deviceStates_.erase(it);
    }
}

void DeviceStateManager::OnDeviceRemoved(int32_t deviceId)
{
    auto it = deviceStates_.find(deviceId);
    if (it != deviceStates_.end()) {
        deviceStates_.erase(it);
        MMI_HILOGI("Device[%{public}d] removed from state manager", deviceId);
    }
}
} // namespace MMI
} // namespace OHOS
