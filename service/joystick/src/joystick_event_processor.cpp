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

#include "joystick_event_processor.h"

#include <iomanip>

#include "key_map_manager.h"
#include "key_event_normalize.h"
#include "key_unicode_transformation.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickEventProcessor"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEFAULT_POINTER_ID { 0 };
constexpr double THRESHOLD { 0.01 };
} // namespace

JoystickEventProcessor::JoystickEventProcessor(int32_t deviceId)
    : deviceId_(deviceId) {}

std::shared_ptr<KeyEvent> JoystickEventProcessor::OnButtonEvent(struct libinput_event *event)
{
    auto inputDev = libinput_event_get_device(event);
    CHKPP(inputDev);
    auto rawBtnEvent = libinput_event_get_joystick_button_event(event);
    CHKPP(rawBtnEvent);
    auto keyCode = KeyMapMgr->TransferDeviceKeyValue(inputDev,
        libinput_event_joystick_button_get_key(rawBtnEvent));
    auto rawBtnState = libinput_event_joystick_button_get_key_state(rawBtnEvent);

    KeyEvent::KeyItem button {};
    button.SetKeyCode(keyCode);
    button.SetPressed(rawBtnState == LIBINPUT_BUTTON_STATE_PRESSED);

    auto btnEvent = FormatButtonEvent(button);
    if (btnEvent != nullptr) {
        MMI_HILOGI("Joystick_button_event, No:%{public}d,KC:%{public}d,KA:%{public}d,Intention:%{public}d",
            btnEvent->GetId(), btnEvent->GetKeyCode(), btnEvent->GetKeyAction(), btnEvent->GetKeyIntention());
    }
    return btnEvent;
}

std::shared_ptr<PointerEvent> JoystickEventProcessor::OnAxisEvent(struct libinput_event *event)
{
    CHKPP(event);
    auto rawAxisEvent = libinput_event_get_joystick_axis_event(event);
    CHKPP(rawAxisEvent);
    if (pointerEvent_ == nullptr) {
        pointerEvent_ = PointerEvent::Create();
        CHKPP(pointerEvent_);
        pointerEvent_->SetPointerId(DEFAULT_POINTER_ID);
        pointerEvent_->SetDeviceId(deviceId_);
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
        pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);

        PointerEvent::PointerItem pointerItem {};
        pointerItem.SetPointerId(DEFAULT_POINTER_ID);
        pointerItem.SetDeviceId(deviceId_);
        pointerEvent_->AddPointerItem(pointerItem);
    }
    int64_t time = GetSysClockTime();
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetTargetDisplayId(-1);

    for (const auto &item : axesMap_) {
        if (libinput_event_get_joystick_axis_value_is_changed(rawAxisEvent, item.first)) {
            auto rawAxisInfo = libinput_event_get_joystick_axis_abs_info(rawAxisEvent, item.first);
            CHKPC(rawAxisInfo);
            pointerEvent_->SetAxisValue(item.second.axisType, item.second.normalize(*rawAxisInfo));
        } else {
            pointerEvent_->ClearAxisStatus(item.second.axisType);
        }
    }
    pointerEvent_->UpdateId();
    WIN_MGR->UpdateTargetPointer(pointerEvent_);
    MMI_HILOGI("Joystick_axis_event, %{public}s", DumpJoystickAxisEvent(pointerEvent_).c_str());
    return pointerEvent_;
}

void JoystickEventProcessor::CheckIntention(std::shared_ptr<PointerEvent> pointerEvent,
    std::function<void(std::shared_ptr<KeyEvent>)> handler)
{
    CHKPV(pointerEvent);
    CHKPV(handler);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_JOYSTICK) {
        return;
    }
    std::vector<KeyEvent::KeyItem> buttonEvents;

    CheckHAT0X(pointerEvent, buttonEvents);
    CheckHAT0Y(pointerEvent, buttonEvents);

    for (const auto &button : buttonEvents) {
        UpdateButtonState(button);
        auto btnEvent = FormatButtonEvent(button);
        if (btnEvent != nullptr) {
            MMI_HILOGI("Joystick_intention, No:%{public}d,KC:%{public}d,KA:%{public}d,Intention:%{public}d",
                btnEvent->GetId(), btnEvent->GetKeyCode(), btnEvent->GetKeyAction(), btnEvent->GetKeyIntention());
            handler(btnEvent);
        }
    }
}

void JoystickEventProcessor::CheckHAT0X(std::shared_ptr<PointerEvent> pointerEvent,
    std::vector<KeyEvent::KeyItem> &buttonEvents) const
{
    if (!pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_ABS_HAT0X)) {
        return;
    }
    KeyEvent::KeyItem keyItem {};
    auto axisValue = pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_HAT0X);
    if (axisValue > THRESHOLD) {
        keyItem.SetKeyCode(KeyEvent::KEYCODE_DPAD_RIGHT);
        keyItem.SetPressed(true);
        buttonEvents.emplace_back(keyItem);
    } else if (axisValue < -THRESHOLD) {
        keyItem.SetKeyCode(KeyEvent::KEYCODE_DPAD_LEFT);
        keyItem.SetPressed(true);
        buttonEvents.emplace_back(keyItem);
    } else if (IsButtonPressed(KeyEvent::KEYCODE_DPAD_LEFT)) {
        keyItem.SetKeyCode(KeyEvent::KEYCODE_DPAD_LEFT);
        keyItem.SetPressed(false);
        buttonEvents.emplace_back(keyItem);
    } else if (IsButtonPressed(KeyEvent::KEYCODE_DPAD_RIGHT)) {
        keyItem.SetKeyCode(KeyEvent::KEYCODE_DPAD_RIGHT);
        keyItem.SetPressed(false);
        buttonEvents.emplace_back(keyItem);
    }
}

void JoystickEventProcessor::CheckHAT0Y(std::shared_ptr<PointerEvent> pointerEvent,
    std::vector<KeyEvent::KeyItem> &buttonEvents) const
{
    if (!pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_ABS_HAT0Y)) {
        return;
    }
    KeyEvent::KeyItem keyItem {};
    auto axisValue = pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_HAT0Y);
    if (axisValue > THRESHOLD) {
        keyItem.SetKeyCode(KeyEvent::KEYCODE_DPAD_DOWN);
        keyItem.SetPressed(true);
        buttonEvents.emplace_back(keyItem);
    } else if (axisValue < -THRESHOLD) {
        keyItem.SetKeyCode(KeyEvent::KEYCODE_DPAD_UP);
        keyItem.SetPressed(true);
        buttonEvents.emplace_back(keyItem);
    } else if (IsButtonPressed(KeyEvent::KEYCODE_DPAD_DOWN)) {
        keyItem.SetKeyCode(KeyEvent::KEYCODE_DPAD_DOWN);
        keyItem.SetPressed(false);
        buttonEvents.emplace_back(keyItem);
    } else if (IsButtonPressed(KeyEvent::KEYCODE_DPAD_UP)) {
        keyItem.SetKeyCode(KeyEvent::KEYCODE_DPAD_UP);
        keyItem.SetPressed(false);
        buttonEvents.emplace_back(keyItem);
    }
}

void JoystickEventProcessor::UpdateButtonState(const KeyEvent::KeyItem &keyItem)
{
    if (keyItem.IsPressed()) {
        PressButton(keyItem.GetKeyCode());
    } else {
        LiftButton(keyItem.GetKeyCode());
    }
}

std::shared_ptr<KeyEvent> JoystickEventProcessor::FormatButtonEvent(const KeyEvent::KeyItem &button) const
{
    auto keyEvent = CleanUpKeyEvent();
    CHKPP(keyEvent);
    int64_t time = GetSysClockTime();
    keyEvent->SetActionTime(time);
    keyEvent->SetAction(button.IsPressed() ? KeyEvent::KEY_ACTION_DOWN : KeyEvent::KEY_ACTION_UP);
    keyEvent->SetDeviceId(deviceId_);
    keyEvent->SetSourceType(InputEvent::SOURCE_TYPE_JOYSTICK);
    keyEvent->SetKeyCode(button.GetKeyCode());
    keyEvent->SetKeyAction(button.IsPressed() ? KeyEvent::KEY_ACTION_DOWN : KeyEvent::KEY_ACTION_UP);
    if (keyEvent->GetPressedKeys().empty()) {
        keyEvent->SetActionStartTime(time);
    }
    keyEvent->SetRepeat(false);

    KeyEvent::KeyItem keyItem {};
    keyItem.SetDownTime(time);
    keyItem.SetKeyCode(button.GetKeyCode());
    keyItem.SetDeviceId(deviceId_);
    keyItem.SetPressed(button.IsPressed());
    keyItem.SetUnicode(KeyCodeToUnicode(button.GetKeyCode(), keyEvent));

    if (!keyItem.IsPressed()) {
        auto tItem = keyEvent->GetKeyItem(keyItem.GetKeyCode());
        if (tItem) {
            keyItem.SetDownTime(tItem->GetDownTime());
        }
        keyEvent->RemoveReleasedKeyItems(keyItem);
    }
    keyEvent->AddPressedKeyItems(keyItem);
    keyEvent->SetKeyIntention(
        KeyItemsTransKeyIntention({ keyItem }));
    keyEvent->UpdateId();
    return keyEvent;
}

std::shared_ptr<KeyEvent> JoystickEventProcessor::CleanUpKeyEvent() const
{
    auto keyEvent = KeyEventHdr->GetKeyEvent();
    CHKPP(keyEvent);
    if (keyEvent->GetAction() == KeyEvent::KEY_ACTION_UP) {
        std::optional<KeyEvent::KeyItem> preUpKeyItem = keyEvent->GetKeyItem();
        if (preUpKeyItem) {
            keyEvent->RemoveReleasedKeyItems(*preUpKeyItem);
        }
    }
    return keyEvent;
}

std::string JoystickEventProcessor::DumpJoystickAxisEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    constexpr int32_t precision { 2 };
    std::ostringstream sAxes;

    sAxes << "No:" << pointerEvent->GetId();

    for (const auto &[_, axisInfo] : axesMap_) {
        sAxes << "," << axisInfo.name << ":" << std::fixed << std::setprecision(precision)
            << pointerEvent->GetAxisValue(axisInfo.axisType);
        if (pointerEvent->HasAxis(axisInfo.axisType)) {
            sAxes << "[C]";
        }
    }
    return std::move(sAxes).str();
}

double JoystickEventProcessor::Normalize(
    const struct libinput_event_joystick_axis_abs_info &axis, double low, double high)
{
    constexpr double epsilon { 0.001 };
    if (high - epsilon < low) {
        return {};
    }
    if (axis.maximum <= axis.minimum) {
        return {};
    }
    double value = std::clamp(axis.value, axis.minimum, axis.maximum);
    double norm = (value - axis.minimum) / (axis.maximum - axis.minimum);
    return (low + (high - low) * norm);
}
} // namespace MMI
} // namespace OHOS
