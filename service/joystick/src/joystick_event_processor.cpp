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

#include "i_input_windows_manager.h"
#include "input_device_manager.h"
#include "key_map_manager.h"
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
constexpr double STATIONARY_VALUE { 0.0 };
constexpr double MIN_FLAT_VALUE { 0.01 };
constexpr double MAX_FLAT_VALUE { 0.1 };
constexpr double MIN_FUZZ_VALUE { 0.001 };
constexpr double MAX_FUZZ_VALUE { 0.01 };
constexpr int32_t LIBINPUT_BUTTON_STATE_REPEAT { 2 };
constexpr char EMPTY_NAME[] { "" };
} // namespace

#define DEFINE_AXIS_NAME(axis)   { PointerEvent::AXIS_TYPE_ABS_##axis, #axis }

struct JoystickAxisState {
    bool changed { false };
    double value {};
};

const std::unordered_map<PointerEvent::AxisType, std::string> JoystickEventProcessor::axisNames_ {
    { PointerEvent::AXIS_TYPE_UNKNOWN, "UNKNOWN" },
    { PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, "SCROLL_VERTICAL" },
    { PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, "SCROLL_HORIZONTAL" },
    { PointerEvent::AXIS_TYPE_PINCH, "PINCH" },
    { PointerEvent::AXIS_TYPE_ROTATE, "ROTATE" },
    DEFINE_AXIS_NAME(X),
    DEFINE_AXIS_NAME(Y),
    DEFINE_AXIS_NAME(Z),
    DEFINE_AXIS_NAME(RX),
    DEFINE_AXIS_NAME(RY),
    DEFINE_AXIS_NAME(RZ),
    DEFINE_AXIS_NAME(THROTTLE),
    DEFINE_AXIS_NAME(RUDDER),
    DEFINE_AXIS_NAME(WHEEL),
    DEFINE_AXIS_NAME(GAS),
    DEFINE_AXIS_NAME(BRAKE),
    DEFINE_AXIS_NAME(HAT0X),
    DEFINE_AXIS_NAME(HAT0Y),
    DEFINE_AXIS_NAME(HAT1X),
    DEFINE_AXIS_NAME(HAT1Y),
    DEFINE_AXIS_NAME(HAT2X),
    DEFINE_AXIS_NAME(HAT2Y),
    DEFINE_AXIS_NAME(HAT3X),
    DEFINE_AXIS_NAME(HAT3Y),
};

const std::set<PointerEvent::AxisType> JoystickEventProcessor::centrosymmetricAxes_ {
    PointerEvent::AXIS_TYPE_ABS_X,
    PointerEvent::AXIS_TYPE_ABS_Y,
    PointerEvent::AXIS_TYPE_ABS_Z,
    PointerEvent::AXIS_TYPE_ABS_RX,
    PointerEvent::AXIS_TYPE_ABS_RY,
    PointerEvent::AXIS_TYPE_ABS_RZ,
    PointerEvent::AXIS_TYPE_ABS_RUDDER,
    PointerEvent::AXIS_TYPE_ABS_WHEEL,
    PointerEvent::AXIS_TYPE_ABS_HAT0X,
    PointerEvent::AXIS_TYPE_ABS_HAT0Y,
    PointerEvent::AXIS_TYPE_ABS_HAT1X,
    PointerEvent::AXIS_TYPE_ABS_HAT1Y,
    PointerEvent::AXIS_TYPE_ABS_HAT2X,
    PointerEvent::AXIS_TYPE_ABS_HAT2Y,
    PointerEvent::AXIS_TYPE_ABS_HAT3X,
    PointerEvent::AXIS_TYPE_ABS_HAT3Y
};

std::string JoystickEventProcessor::MapAxisName(PointerEvent::AxisType axis)
{
    if (auto iter = axisNames_.find(axis); iter != axisNames_.cend()) {
        return iter->second;
    }
    return std::string();
}

bool JoystickEventProcessor::IsCentrosymmetric(PointerEvent::AxisType axis)
{
    return (centrosymmetricAxes_.find(axis) != centrosymmetricAxes_.cend());
}

JoystickEventProcessor::JoystickEventProcessor(int32_t deviceId)
    : deviceId_(deviceId)
{
    Initialize();
}

std::shared_ptr<KeyEvent> JoystickEventProcessor::OnButtonEvent(struct libinput_event *event)
{
    auto inputDev = libinput_event_get_device(event);
    CHKPP(inputDev);
    auto rawBtnEvent = libinput_event_get_joystick_button_event(event);
    CHKPP(rawBtnEvent);
    auto keyCode = MapKey(inputDev, libinput_event_joystick_button_get_key(rawBtnEvent));
    auto rawBtnState = libinput_event_joystick_button_get_key_state(rawBtnEvent);

    KeyEvent::KeyItem button {};
    button.SetKeyCode(keyCode);
    button.SetPressed(rawBtnState != LIBINPUT_BUTTON_STATE_RELEASED);

    auto btnEvent = FormatButtonEvent(button);
    if (btnEvent != nullptr) {
        btnEvent->SetRepeatKey(rawBtnState == LIBINPUT_BUTTON_STATE_REPEAT);
        MMI_HILOGI("Joystick_button_event, No:%{public}d,KC:%{private}d,KA:%{public}d,Intention:%{public}d",
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

    for (const auto &[source, axisInfo] : axesMap_) {
        pointerEvent_->ClearAxisStatus(axisInfo.axis_);
        if (axisInfo.mode_ == JoystickLayoutMap::AxisMode::AXIS_MODE_SPLIT) {
            pointerEvent_->ClearAxisStatus(axisInfo.highAxis_);
        }
    }
    for (const auto &[source, axisInfo] : axesMap_) {
        if (libinput_event_get_joystick_axis_value_is_changed(rawAxisEvent, source)) {
            auto rawAxisInfo = libinput_event_get_joystick_axis_abs_info(rawAxisEvent, source);
            CHKPC(rawAxisInfo);
            NormalizeAxisValue(*rawAxisInfo, axisInfo);
        }
    }
    if (!HasAxisValueChanged()) {
        return nullptr;
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
            MMI_HILOGI("Joystick_intention, No:%{public}d,KC:%{private}d,KA:%{public}d,Intention:%{public}d",
                btnEvent->GetId(), btnEvent->GetKeyCode(), btnEvent->GetKeyAction(), btnEvent->GetKeyIntention());
            handler(btnEvent);
        }
    }
}

void JoystickEventProcessor::Initialize()
{
    auto inputDev = INPUT_DEV_MGR->GetLibinputDevice(deviceId_);
    if (inputDev == nullptr) {
        MMI_HILOGW("No libinput-device attached to device(%{public}d)", deviceId_);
        return;
    }
    const char *name = libinput_device_get_name(inputDev);
    const char *devName = (name != nullptr ? name : EMPTY_NAME);

    if (!libinput_device_has_capability(inputDev, LIBINPUT_DEVICE_CAP_JOYSTICK)) {
        MMI_HILOGI("[%{public}s:%{private}d] Not joystick", devName, deviceId_);
        return;
    }
    layout_ = JoystickLayoutMap::Load(inputDev);
    if (layout_ == nullptr) {
        MMI_HILOGI("[%{public}s:%{private}d] No layout config", devName, deviceId_);
    }
    for (auto &[_, axisInfo] : axesMap_) {
        InitializeAxisInfo(inputDev, devName, axisInfo);

        MMI_HILOGI("[%{public}s:%{private}d] Mode:%{public}s, Axis:%{public}s, Min:%{public}d, Max:%{public}d"
            ", Scale:%{public}f, fuzz:%{public}f, flat:%{public}f",
            devName, deviceId_, JoystickLayoutMap::MapAxisModeName(axisInfo.mode_).c_str(),
            MapAxisName(axisInfo.axis_).c_str(), axisInfo.minimum_, axisInfo.maximum_,
            axisInfo.scale_, axisInfo.fuzz_, axisInfo.flat_);

        if (axisInfo.mode_ == JoystickLayoutMap::AxisMode::AXIS_MODE_SPLIT) {
            MMI_HILOGI("[%{public}s:%{private}d] Mode:%{public}s, HighAxis:%{public}s"
                ", SplitValue:%{public}d, HighScale:%{public}f",
                devName, deviceId_, JoystickLayoutMap::MapAxisModeName(axisInfo.mode_).c_str(),
                MapAxisName(axisInfo.highAxis_).c_str(), axisInfo.splitValue_, axisInfo.highScale_);
        }
    }
}

void JoystickEventProcessor::InitializeAxisInfo(
    struct libinput_device *device, const char *name, AxisInfo &axisInfo) const
{
    std::optional<JoystickLayoutMap::AxisInfo> layout {};

    if (layout_ != nullptr) {
        layout = layout_->MapAxis(axisInfo.rawCode_);
    }
    if (layout) {
        axisInfo.mode_ = layout->mode_;
        axisInfo.axis_ = layout->axis_;
        axisInfo.highAxis_ = layout->highAxis_;
        axisInfo.splitValue_ = layout->splitValue_;
        MMI_HILOGI("[%{public}s:%{private}d] Layout {%{public}d,%{public}d,%{public}d,%{public}d,%{public}d}",
            name, deviceId_, axisInfo.mode_, axisInfo.axis_, axisInfo.highAxis_,
            axisInfo.splitValue_, layout->flatOverride_);
    }

    axisInfo.minimum_ = libinput_device_get_axis_min(device, axisInfo.rawCode_);
    axisInfo.maximum_ = libinput_device_get_axis_max(device, axisInfo.rawCode_);

    if (axisInfo.mode_ == JoystickLayoutMap::AxisMode::AXIS_MODE_SPLIT) {
        if ((axisInfo.splitValue_ > axisInfo.minimum_) && (axisInfo.splitValue_ < axisInfo.maximum_)) {
            axisInfo.scale_ = 1.0 / (axisInfo.splitValue_ - axisInfo.minimum_);
            axisInfo.highScale_ = 1.0 / (axisInfo.maximum_ - axisInfo.splitValue_);
        }
    } else if (axisInfo.maximum_ > axisInfo.minimum_) {
        if (JoystickEventProcessor::IsCentrosymmetric(axisInfo.axis_)) {
            axisInfo.low_ = -1.0;
            axisInfo.offset_ = -1.0;
        }
        axisInfo.scale_ = (axisInfo.high_ - axisInfo.low_) / (axisInfo.maximum_ - axisInfo.minimum_);
    }

    int32_t flat {};

    if (layout && (layout->flatOverride_ > 0)) {
        flat = layout->flatOverride_;
    } else {
        flat = libinput_device_get_axis_flat(device, axisInfo.rawCode_);
    }
    axisInfo.flat_ = std::clamp(flat * axisInfo.scale_, MIN_FLAT_VALUE, MAX_FLAT_VALUE);

    constexpr int32_t flatScale { 4 };
    int32_t fuzz = libinput_device_get_axis_fuzz(device, axisInfo.rawCode_);
    if (fuzz <= 0) {
        fuzz = flat / flatScale;
    }
    if (fuzz > 0) {
        axisInfo.fuzz_ = fuzz * axisInfo.scale_;
    }
    axisInfo.fuzz_ = std::clamp(axisInfo.fuzz_, MIN_FUZZ_VALUE, MAX_FUZZ_VALUE);
    axisInfo.fuzz_ = std::max<double>(axisInfo.fuzz_, axisInfo.flat_ / flatScale);
}

int32_t JoystickEventProcessor::MapKey(struct libinput_device *device, int32_t rawCode) const
{
    if (layout_ != nullptr) {
        auto key = layout_->MapKey(rawCode);
        if (key) {
            return key->keyCode_;
        }
    }
    return KeyMapMgr->TransferDefaultKeyValue(rawCode);
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

std::shared_ptr<KeyEvent> JoystickEventProcessor::FormatButtonEvent(const KeyEvent::KeyItem &button)
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
    keyEvent->SetRepeatKey(false);
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

std::shared_ptr<KeyEvent> JoystickEventProcessor::CleanUpKeyEvent()
{
    if (keyEvent_ == nullptr) {
        keyEvent_ = KeyEvent::Create();
        CHKPP(keyEvent_);
    }
    for (const auto &keyItem : keyEvent_->GetKeyItems()) {
        if (!keyItem.IsPressed()) {
            keyEvent_->RemoveReleasedKeyItems(keyItem);
        }
    }
    return keyEvent_;
}

std::string JoystickEventProcessor::DumpJoystickAxisEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    constexpr int32_t precision { 2 };
    std::map<PointerEvent::AxisType, JoystickAxisState> axisStates;
    std::ostringstream sAxes;

    sAxes << "No:" << pointerEvent->GetId();

    for (const auto &[_, axisInfo] : axesMap_) {
        axisStates.emplace(axisInfo.axis_,
            JoystickAxisState {
                .changed = pointerEvent->HasAxis(axisInfo.axis_),
                .value = pointerEvent->GetAxisValue(axisInfo.axis_),
            });

        if (axisInfo.mode_ == JoystickLayoutMap::AxisMode::AXIS_MODE_SPLIT) {
            axisStates.emplace(axisInfo.highAxis_,
                JoystickAxisState {
                    .changed = pointerEvent->HasAxis(axisInfo.highAxis_),
                    .value = pointerEvent->GetAxisValue(axisInfo.highAxis_),
                });
        }
    }

    for (const auto &[axis, axisStat] : axisStates) {
        sAxes << "," << JoystickEventProcessor::MapAxisName(axis) << ":" << std::fixed
            << std::setprecision(precision) << axisStat.value;
        if (axisStat.changed) {
            sAxes << "[C]";
        }
    }
    return std::move(sAxes).str();
}

void JoystickEventProcessor::NormalizeAxisValue(
    const struct libinput_event_joystick_axis_abs_info &abs, const AxisInfo &axisInfo)
{
    if (axisInfo.mode_ == JoystickLayoutMap::AxisMode::AXIS_MODE_SPLIT) {
        if ((axisInfo.splitValue_ <= axisInfo.minimum_) || (axisInfo.splitValue_ >= axisInfo.maximum_)) {
            return;
        }
        double value = 0.0;
        double highValue = 0.0;

        if (abs.value < axisInfo.splitValue_) {
            value = std::clamp(abs.value, axisInfo.minimum_, axisInfo.splitValue_);
            value = (axisInfo.splitValue_ - value) * axisInfo.scale_;
        } else if (abs.value > axisInfo.splitValue_) {
            highValue = std::clamp(abs.value, axisInfo.splitValue_, axisInfo.maximum_);
            highValue = (highValue - axisInfo.splitValue_) * axisInfo.highScale_;
        }

        UpdateAxisValue(axisInfo, axisInfo.axis_, value);
        UpdateAxisValue(axisInfo, axisInfo.highAxis_, highValue);
        return;
    }

    if (axisInfo.maximum_ <= axisInfo.minimum_) {
        return;
    }
    double value = std::clamp(abs.value, axisInfo.minimum_, axisInfo.maximum_);

    if (axisInfo.mode_ == JoystickLayoutMap::AxisMode::AXIS_MODE_INVERT) {
        value = axisInfo.maximum_ - value;
    } else {
        value = value - axisInfo.minimum_;
    }
    value = value * axisInfo.scale_ + axisInfo.offset_;
    UpdateAxisValue(axisInfo, axisInfo.axis_, value);
}

void JoystickEventProcessor::UpdateAxisValue(
    const AxisInfo &axisInfo, PointerEvent::AxisType axis, double newValue)
{
    if (std::abs(newValue - STATIONARY_VALUE) < axisInfo.flat_) {
        newValue = STATIONARY_VALUE;
    }
    const auto currentValue = pointerEvent_->GetAxisValue(axis);
    auto changed = (
        (std::abs(newValue - currentValue) > axisInfo.fuzz_) ||
        ((std::abs(axisInfo.high_ - newValue) < axisInfo.fuzz_) &&
         (std::abs(axisInfo.high_ - newValue) < std::abs(axisInfo.high_ - currentValue))) ||
        ((std::abs(newValue - axisInfo.low_) < axisInfo.fuzz_) &&
         (std::abs(newValue - axisInfo.low_) < std::abs(currentValue - axisInfo.low_))) ||
        ((std::abs(newValue) < axisInfo.fuzz_) &&
         (std::abs(newValue) < std::abs(currentValue)))
    );
    if (changed) {
        pointerEvent_->SetAxisValue(axis, newValue);
    }
}

bool JoystickEventProcessor::HasAxisValueChanged() const
{
    if (pointerEvent_ == nullptr) {
        return false;
    }
    for (const auto &[_, axisInfo] : axesMap_) {
        if (pointerEvent_->HasAxis(axisInfo.axis_)) {
            return true;
        }
        if ((axisInfo.mode_ == JoystickLayoutMap::AxisMode::AXIS_MODE_SPLIT) &&
            pointerEvent_->HasAxis(axisInfo.highAxis_)) {
            return true;
        }
    }
    return false;
}
} // namespace MMI
} // namespace OHOS
