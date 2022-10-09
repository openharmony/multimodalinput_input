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

#include "pointer_event.h"

#include <iomanip>

#include "mmi_log.h"

using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "PointerEvent" };
constexpr double MAX_PRESSURE { 1.0 };
constexpr size_t MAX_N_PRESSED_BUTTONS { 10 };
constexpr size_t MAX_N_POINTER_ITEMS { 5 };
} // namespace

std::shared_ptr<PointerEvent> PointerEvent::from(std::shared_ptr<InputEvent> inputEvent)
{
    return nullptr;
}

PointerEvent::PointerItem::PointerItem() {}

PointerEvent::PointerItem::~PointerItem() {}

int32_t PointerEvent::PointerItem::GetPointerId() const
{
    return pointerId_;
}

void PointerEvent::PointerItem::SetPointerId(int32_t pointerId)
{
    pointerId_ = pointerId;
}

int64_t PointerEvent::PointerItem::GetDownTime() const
{
    return downTime_;
}

void PointerEvent::PointerItem::SetDownTime(int64_t downTime)
{
    downTime_ = downTime;
}

bool PointerEvent::PointerItem::IsPressed() const
{
    return pressed_;
}

void PointerEvent::PointerItem::SetPressed(bool pressed)
{
    pressed_ = pressed;
}

int32_t PointerEvent::PointerItem::GetDisplayX() const
{
    return displayX_;
}

void PointerEvent::PointerItem::SetDisplayX(int32_t x)
{
    displayX_ = x;
}

int32_t PointerEvent::PointerItem::GetDisplayY() const
{
    return displayY_;
}

void PointerEvent::PointerItem::SetDisplayY(int32_t y)
{
    displayY_ = y;
}

int32_t PointerEvent::PointerItem::GetWindowX() const
{
    return windowX_;
}

void PointerEvent::PointerItem::SetWindowX(int32_t x)
{
    windowX_ = x;
}

int32_t PointerEvent::PointerItem::GetWindowY() const
{
    return windowY_;
}

void PointerEvent::PointerItem::SetWindowY(int32_t y)
{
    windowY_ = y;
}

int32_t PointerEvent::PointerItem::GetWidth() const
{
    return width_;
}

void PointerEvent::PointerItem::SetWidth(int32_t width)
{
    width_ = width;
}

int32_t PointerEvent::PointerItem::GetHeight() const
{
    return height_;
}

void PointerEvent::PointerItem::SetHeight(int32_t height)
{
    height_ = height;
}

double PointerEvent::PointerItem::GetTiltX() const
{
    return tiltX_;
}

void PointerEvent::PointerItem::SetTiltX(double tiltX)
{
    tiltX_ = tiltX;
}

double PointerEvent::PointerItem::GetTiltY() const
{
    return tiltY_;
}

void PointerEvent::PointerItem::SetTiltY(double tiltY)
{
    tiltY_ = tiltY;
}

int32_t PointerEvent::PointerItem::GetToolDisplayX() const
{
    return toolDisplayX_;
}

void PointerEvent::PointerItem::SetToolDisplayX(int32_t x)
{
    toolDisplayX_ = x;
}

int32_t PointerEvent::PointerItem::GetToolDisplayY() const
{
    return toolDisplayY_;
}

void PointerEvent::PointerItem::SetToolDisplayY(int32_t y)
{
    toolDisplayY_ = y;
}

int32_t PointerEvent::PointerItem::GetToolWindowX() const
{
    return toolWindowX_;
}

void PointerEvent::PointerItem::SetToolWindowX(int32_t x)
{
    toolWindowX_ = x;
}

int32_t PointerEvent::PointerItem::GetToolWindowY() const
{
    return toolWindowY_;
}

void PointerEvent::PointerItem::SetToolWindowY(int32_t y)
{
    toolWindowY_ = y;
}

int32_t PointerEvent::PointerItem::GetToolWidth() const
{
    return toolWidth_;
}

void PointerEvent::PointerItem::SetToolWidth(int32_t width)
{
    toolWidth_ = width;
}

int32_t PointerEvent::PointerItem::GetToolHeight() const
{
    return toolHeight_;
}

void PointerEvent::PointerItem::SetToolHeight(int32_t height)
{
    toolHeight_ = height;
}

double PointerEvent::PointerItem::GetPressure() const
{
    return pressure_;
}

void PointerEvent::PointerItem::SetPressure(double pressure)
{
    pressure_ = pressure >= MAX_PRESSURE ? MAX_PRESSURE : pressure;
}

int32_t PointerEvent::PointerItem::GetLongAxis() const
{
    return longAxis_;
}

void PointerEvent::PointerItem::SetLongAxis(int32_t longAxis)
{
    longAxis_ = longAxis;
}

int32_t PointerEvent::PointerItem::GetShortAxis() const
{
    return shortAxis_;
}

void PointerEvent::PointerItem::SetShortAxis(int32_t shortAxis)
{
    shortAxis_ = shortAxis;
}

int32_t PointerEvent::PointerItem::GetDeviceId() const
{
    return deviceId_;
}

void PointerEvent::PointerItem::SetDeviceId(int32_t deviceId)
{
    deviceId_ = deviceId;
}

int32_t PointerEvent::PointerItem::GetToolType() const
{
    return toolType_;
}

void PointerEvent::PointerItem::SetToolType(int32_t toolType)
{
    toolType_ = toolType;
}

int32_t PointerEvent::PointerItem::GetTargetWindowId() const
{
    return targetWindowId_;
}

void PointerEvent::PointerItem::SetTargetWindowId(int32_t windowId)
{
    targetWindowId_ = windowId;
}

int32_t PointerEvent::PointerItem::GetRawDx() const
{
    return rawDx_;
}

void PointerEvent::PointerItem::SetRawDx(int32_t rawDx)
{
    rawDx_ = rawDx;
}

int32_t PointerEvent::PointerItem::GetRawDy() const
{
    return rawDy_;
}

void PointerEvent::PointerItem::SetRawDy(int32_t rawDy)
{
    rawDy_ = rawDy;
}

bool PointerEvent::PointerItem::WriteToParcel(Parcel &out) const
{
    return (
        out.WriteInt32(pointerId_) &&
        out.WriteInt64(downTime_) &&
        out.WriteBool(pressed_) &&
        out.WriteInt32(displayX_) &&
        out.WriteInt32(displayY_) &&
        out.WriteInt32(windowX_) &&
        out.WriteInt32(windowY_) &&
        out.WriteInt32(width_) &&
        out.WriteInt32(height_) &&
        out.WriteInt32(toolDisplayX_) &&
        out.WriteInt32(toolDisplayY_) &&
        out.WriteInt32(toolWindowX_) &&
        out.WriteInt32(toolWindowY_) &&
        out.WriteInt32(toolWidth_) &&
        out.WriteInt32(toolHeight_) &&
        out.WriteDouble(tiltX_) &&
        out.WriteDouble(tiltY_) &&
        out.WriteDouble(pressure_) &&
        out.WriteInt32(longAxis_) &&
        out.WriteInt32(shortAxis_) &&
        out.WriteInt32(toolType_) &&
        out.WriteInt32(deviceId_) &&
        out.WriteInt32(rawDx_) &&
        out.WriteInt32(rawDy_)
    );
}

bool PointerEvent::PointerItem::ReadFromParcel(Parcel &in)
{
    return (
        in.ReadInt32(pointerId_) &&
        in.ReadInt64(downTime_) &&
        in.ReadBool(pressed_) &&
        in.ReadInt32(displayX_) &&
        in.ReadInt32(displayY_) &&
        in.ReadInt32(windowX_) &&
        in.ReadInt32(windowY_) &&
        in.ReadInt32(width_) &&
        in.ReadInt32(height_) &&
        in.ReadInt32(toolDisplayX_) &&
        in.ReadInt32(toolDisplayY_) &&
        in.ReadInt32(toolWindowX_) &&
        in.ReadInt32(toolWindowY_) &&
        in.ReadInt32(toolWidth_) &&
        in.ReadInt32(toolHeight_) &&
        in.ReadDouble(tiltX_) &&
        in.ReadDouble(tiltY_) &&
        in.ReadDouble(pressure_) &&
        in.ReadInt32(longAxis_) &&
        in.ReadInt32(shortAxis_) &&
        in.ReadInt32(toolType_) &&
        in.ReadInt32(deviceId_) &&
        in.ReadInt32(rawDx_) &&
        in.ReadInt32(rawDy_)
    );
}

PointerEvent::PointerEvent(int32_t eventType) : InputEvent(eventType) {}

PointerEvent::PointerEvent(const PointerEvent& other)
    : InputEvent(other), pointerId_(other.pointerId_), pointers_(other.pointers_),
      pressedButtons_(other.pressedButtons_), sourceType_(other.sourceType_),
      pointerAction_(other.pointerAction_), buttonId_(other.buttonId_),
      axes_(other.axes_), axisValues_(other.axisValues_),
      pressedKeys_(other.pressedKeys_) {}

PointerEvent::~PointerEvent() {}

std::shared_ptr<PointerEvent> PointerEvent::Create()
{
    auto event = std::shared_ptr<PointerEvent>(new (std::nothrow) PointerEvent(InputEvent::EVENT_TYPE_POINTER));
    CHKPP(event);
    return event;
}

void PointerEvent::Reset()
{
    InputEvent::Reset();
    pointerId_ = -1;
    pointers_.clear();
    pressedButtons_.clear();
    sourceType_ = SOURCE_TYPE_UNKNOWN;
    pointerAction_ = POINTER_ACTION_UNKNOWN;
    buttonId_ = -1;
    axes_ = 0U;
    axisValues_.fill(0.0);
    pressedKeys_.clear();
}

int32_t PointerEvent::GetPointerAction() const
{
    return pointerAction_;
}

void PointerEvent::SetPointerAction(int32_t pointerAction)
{
    pointerAction_ = pointerAction;
}

const char* PointerEvent::DumpPointerAction() const
{
    switch (pointerAction_) {
        case PointerEvent::POINTER_ACTION_CANCEL: {
            return "cancel";
        }
        case PointerEvent::POINTER_ACTION_DOWN: {
            return "down";
        }
        case PointerEvent::POINTER_ACTION_MOVE: {
            return "move";
        }
        case PointerEvent::POINTER_ACTION_UP: {
            return "up";
        }
        case PointerEvent::POINTER_ACTION_AXIS_BEGIN: {
            return "axis-begin";
        }
        case PointerEvent::POINTER_ACTION_AXIS_UPDATE: {
            return "axis-update";
        }
        case PointerEvent::POINTER_ACTION_AXIS_END: {
            return "axis-end";
        }
        case PointerEvent::POINTER_ACTION_BUTTON_DOWN: {
            return "button-down";
        }
        case PointerEvent::POINTER_ACTION_BUTTON_UP: {
            return "button-up";
        }
        case PointerEvent::POINTER_ACTION_ENTER_WINDOW: {
            return "enter-window";
        }
        case PointerEvent::POINTER_ACTION_LEAVE_WINDOW: {
            return "leave-window";
        }
        default: {
            break;
        }
    }
    return "unknown";
}

int32_t PointerEvent::GetPointerId() const
{
    return pointerId_;
}

void PointerEvent::SetPointerId(int32_t pointerId)
{
    pointerId_ = pointerId;
}

bool PointerEvent::GetPointerItem(int32_t pointerId, PointerItem &pointerItem)
{
    for (const auto &item : pointers_) {
        if (item.GetPointerId() == pointerId) {
            pointerItem = item;
            return true;
        }
    }
    return false;
}

void PointerEvent::RemovePointerItem(int32_t pointerId)
{
    for (auto it = pointers_.begin(); it != pointers_.end(); ++it) {
        if (it->GetPointerId() == pointerId) {
            pointers_.erase(it);
            break;
        }
    }
}

void PointerEvent::AddPointerItem(PointerItem &pointerItem)
{
    if (pointers_.size() >= MAX_N_POINTER_ITEMS) {
        MMI_HILOGE("Exceed maximum allowed number of pointer items");
        return;
    }
    pointers_.push_back(pointerItem);
}

void PointerEvent::UpdatePointerItem(int32_t pointerId, PointerItem &pointerItem)
{
    for (auto &item : pointers_) {
        if (item.GetPointerId() == pointerId) {
            item = pointerItem;
            return;
        }
    }
    AddPointerItem(pointerItem);
}

std::set<int32_t> PointerEvent::GetPressedButtons() const
{
    return pressedButtons_;
}

bool PointerEvent::IsButtonPressed(int32_t buttonId) const
{
    return (pressedButtons_.find(buttonId) != pressedButtons_.end());
}

void PointerEvent::SetButtonPressed(int32_t buttonId)
{
    if (pressedButtons_.size() >= MAX_N_PRESSED_BUTTONS) {
        MMI_HILOGE("Exceed maximum allowed number of pressed buttons");
        return;
    }
    auto iter = pressedButtons_.insert(buttonId);
    if (!iter.second) {
        MMI_HILOGE("Insert value failed, button:%{public}d", buttonId);
    }
}

void PointerEvent::DeleteReleaseButton(int32_t buttonId)
{
    if (pressedButtons_.find(buttonId) != pressedButtons_.end()) {
        pressedButtons_.erase(buttonId);
    }
}

void PointerEvent::ClearButtonPressed()
{
    pressedButtons_.clear();
}

std::vector<int32_t> PointerEvent::GetPointerIds() const
{
    std::vector<int32_t> pointerIdList;
    for (const auto &item : pointers_) {
        pointerIdList.push_back(item.GetPointerId());
    }
    return pointerIdList;
}

int32_t PointerEvent::GetSourceType() const
{
    return sourceType_;
}

void PointerEvent::SetSourceType(int32_t sourceType)
{
    sourceType_ = sourceType;
}

const char* PointerEvent::DumpSourceType() const
{
    switch (sourceType_) {
        case PointerEvent::SOURCE_TYPE_MOUSE: {
            return "mouse";
        }
        case PointerEvent::SOURCE_TYPE_TOUCHSCREEN: {
            return "touch-screen";
        }
        case PointerEvent::SOURCE_TYPE_TOUCHPAD: {
            return "touch-pad";
        }
        case PointerEvent::SOURCE_TYPE_JOYSTICK: {
            return "joystick";
        }
        default: {
            break;
        }
    }
    return "unknown";
}

int32_t PointerEvent::GetButtonId() const
{
    return buttonId_;
}

void PointerEvent::SetButtonId(int32_t buttonId)
{
    buttonId_ = buttonId;
}

double PointerEvent::GetAxisValue(AxisType axis) const
{
    double axisValue {};
    if ((axis >= AXIS_TYPE_UNKNOWN) && (axis < AXIS_TYPE_MAX)) {
        axisValue = axisValues_[axis];
    }
    return axisValue;
}

void PointerEvent::SetAxisValue(AxisType axis, double axisValue)
{
    if ((axis >= AXIS_TYPE_UNKNOWN) && (axis < AXIS_TYPE_MAX)) {
        axisValues_[axis] = axisValue;
        axes_ = static_cast<uint32_t>(axes_ | static_cast<uint32_t>(1 << axis));
    }
}

void PointerEvent::ClearAxisValue()
{
    axisValues_ = {};
    axes_ = 0;
}

bool PointerEvent::HasAxis(uint32_t axes, AxisType axis)
{
    bool ret { false };
    if ((axis >= AXIS_TYPE_UNKNOWN) && (axis < AXIS_TYPE_MAX)) {
        ret = static_cast<bool>(static_cast<uint32_t>(axes) & (1 << static_cast<uint32_t>(axis)));
    }
    return ret;
}

void PointerEvent::SetPressedKeys(const std::vector<int32_t> pressedKeys)
{
    pressedKeys_ = pressedKeys;
}

std::vector<int32_t> PointerEvent::GetPressedKeys() const
{
    return pressedKeys_;
}

bool PointerEvent::WriteToParcel(Parcel &out) const
{
    if (!InputEvent::WriteToParcel(out)) {
        return false;
    }

    WRITEINT32(out, pointerId_);

    WRITEINT32(out, static_cast<int32_t>(pointers_.size()));

    for (const auto &item : pointers_) {
        if (!item.WriteToParcel(out)) {
            return false;
        }
    }

    WRITEINT32(out, static_cast<int32_t>(pressedButtons_.size()));

    for (const auto &item : pressedButtons_) {
        WRITEINT32(out, item);
    }

    WRITEINT32(out, sourceType_);

    WRITEINT32(out, pointerAction_);

    WRITEINT32(out, buttonId_);

    const uint32_t axes { GetAxes() };
    WRITEUINT32(out, axes);

    for (int32_t i = AXIS_TYPE_UNKNOWN; i < AXIS_TYPE_MAX; ++i) {
        const AxisType axis { static_cast<AxisType>(i) };
        if (HasAxis(axes, axis)) {
            WRITEDOUBLE(out, GetAxisValue(axis));
        }
    }

    return true;
}

bool PointerEvent::ReadFromParcel(Parcel &in)
{
    if (!InputEvent::ReadFromParcel(in)) {
        return false;
    }

    READINT32(in, pointerId_);

    int32_t nPointers;
    READINT32(in, nPointers);
    if (nPointers > static_cast<int32_t>(MAX_N_POINTER_ITEMS)) {
        return false;
    }

    for (int32_t i = 0; i < nPointers; ++i) {
        PointerItem item;
        if (!item.ReadFromParcel(in)) {
            return false;
        }
        AddPointerItem(item);
    }

    int32_t nPressedButtons;
    READINT32(in, nPressedButtons);
    if (nPressedButtons > static_cast<int32_t>(MAX_N_PRESSED_BUTTONS)) {
        return false;
    }

    for (int32_t i = 0; i < nPressedButtons; ++i) {
        int32_t buttonId;
        READINT32(in, buttonId);
        SetButtonPressed(buttonId);
    }

    READINT32(in, sourceType_);

    READINT32(in, pointerAction_);

    READINT32(in, buttonId_);

    uint32_t axes;
    READUINT32(in, axes);

    for (int32_t i = AXIS_TYPE_UNKNOWN; i < AXIS_TYPE_MAX; ++i) {
        const AxisType axis { static_cast<AxisType>(i) };
        if (HasAxis(axes, axis)) {
            double val;
            READDOUBLE(in, val);
            SetAxisValue(axis, val);
        }
    }

    return true;
}

bool PointerEvent::IsValidCheckMouseFunc() const
{
    CALL_DEBUG_ENTER;
    if (pointers_.size() != 1) {
        MMI_HILOGE("Pointers_ is invalid");
        return false;
    }

    size_t maxPressedButtons = 3;
    if (pressedButtons_.size() > maxPressedButtons) {
        MMI_HILOGE("PressedButtons_.size is greater than three and is invalid");
        return false;
    }

    for (const auto &item : pressedButtons_) {
        if (item != MOUSE_BUTTON_LEFT && item != MOUSE_BUTTON_RIGHT && item != MOUSE_BUTTON_MIDDLE) {
            MMI_HILOGE("PressedButtons_ is invalid");
            return false;
        }
    }

    int32_t pointAction = GetPointerAction();
    if (pointAction != POINTER_ACTION_CANCEL && pointAction != POINTER_ACTION_MOVE &&
        pointAction != POINTER_ACTION_AXIS_BEGIN && pointAction != POINTER_ACTION_AXIS_UPDATE &&
        pointAction != POINTER_ACTION_AXIS_END && pointAction != POINTER_ACTION_BUTTON_DOWN &&
        pointAction != POINTER_ACTION_BUTTON_UP) {
        MMI_HILOGE("PointAction is invalid");
        return false;
    }

    int32_t buttonId = GetButtonId();
    if (pointAction == POINTER_ACTION_BUTTON_DOWN || pointAction == POINTER_ACTION_BUTTON_UP) {
        if (buttonId != MOUSE_BUTTON_LEFT && buttonId != MOUSE_BUTTON_RIGHT && buttonId != MOUSE_BUTTON_MIDDLE) {
            MMI_HILOGE("ButtonId is invalid");
            return false;
        }
    } else {
        if (buttonId != BUTTON_NONE) {
            MMI_HILOGE("ButtonId is not BUTTON_NONE and is invalid");
            return false;
        }
    }
    return true;
}

bool PointerEvent::IsValidCheckMouse() const
{
    CALL_DEBUG_ENTER;
    int32_t mousePointID = GetPointerId();
    if (mousePointID < 0) {
        MMI_HILOGE("MousePointID is invalid");
        return false;
    }

    if (!IsValidCheckMouseFunc()) {
        MMI_HILOGE("IsValidCheckMouseFunc is invalid");
        return false;
    }

    for (const auto &item : pointers_) {
        if (item.GetPointerId() < 0) {
            MMI_HILOGE("Item.pointerid is invalid");
            return false;
        }

        if (item.GetPointerId() != mousePointID) {
            MMI_HILOGE("Item.pointerid is not same to mousePointID and is invalid");
            return false;
        }

        if (item.GetDownTime() > 0) {
            MMI_HILOGE("Item.downtime is invalid");
            return false;
        }

        if (item.IsPressed() != false) {
            MMI_HILOGE("Item.ispressed is not false and is invalid");
            return false;
        }
    }
    return true;
}

bool PointerEvent::IsValidCheckTouchFunc() const
{
    CALL_DEBUG_ENTER;
    int32_t touchPointID = GetPointerId();
    if (touchPointID < 0) {
        MMI_HILOGE("TouchPointID is invalid");
        return false;
    }

    if (!pressedButtons_.empty()) {
        MMI_HILOGE("PressedButtons_.size is invalid");
        return false;
    }

    int32_t pointAction = GetPointerAction();
    if (pointAction != POINTER_ACTION_CANCEL && pointAction != POINTER_ACTION_MOVE &&
        pointAction != POINTER_ACTION_DOWN && pointAction != POINTER_ACTION_UP) {
        MMI_HILOGE("PointAction is invalid");
        return false;
    }

    if (GetButtonId() != BUTTON_NONE) {
        MMI_HILOGE("ButtonId is invalid");
        return false;
    }
    return true;
}

bool PointerEvent::IsValidCheckTouch() const
{
    CALL_DEBUG_ENTER;
    if (!IsValidCheckTouchFunc()) {
        MMI_HILOGE("IsValidCheckTouchFunc is invalid");
        return false;
    }
    bool isSameItem = false;
    int32_t touchPointID = GetPointerId();
    for (auto item = pointers_.begin(); item != pointers_.end(); item++) {
        if (item->GetPointerId() < 0) {
            MMI_HILOGE("Item.pointerid is invalid");
            return false;
        }

        if (item->GetPointerId() == touchPointID) {
            isSameItem = true;
        }

        if (item->GetDownTime() <= 0) {
            MMI_HILOGE("Item.downtime is invalid");
            return false;
        }

        if (item->IsPressed() != false) {
            MMI_HILOGE("Item.ispressed is not false and is invalid");
            return false;
        }

        auto itemtmp = item;
        for (++itemtmp; itemtmp != pointers_.end(); itemtmp++) {
            if (item->GetPointerId() == itemtmp->GetPointerId()) {
                MMI_HILOGE("Pointitems pointerid exist same items and is invalid");
                return false;
            }
        }
    }

    if (!isSameItem) {
        MMI_HILOGE("Item.pointerid is not same to touchPointID and is invalid");
        return false;
    }
    return true;
}

bool PointerEvent::IsValid() const
{
    CALL_DEBUG_ENTER;
    int32_t sourceType = GetSourceType();
    if (sourceType != SOURCE_TYPE_MOUSE && sourceType != SOURCE_TYPE_TOUCHSCREEN &&
        sourceType != SOURCE_TYPE_TOUCHPAD) {
        MMI_HILOGE("SourceType is invalid");
        return false;
    }
    switch (sourceType) {
        case SOURCE_TYPE_MOUSE: {
            if (!IsValidCheckMouse()) {
                MMI_HILOGE("IsValidCheckMouse is invalid");
                return false;
            }
            break;
        }
        case SOURCE_TYPE_TOUCHSCREEN:
        case SOURCE_TYPE_TOUCHPAD: {
            if (!IsValidCheckTouch()) {
                MMI_HILOGE("IsValidCheckTouch is invalid");
                return false;
            }
            break;
        }
        default: {
            MMI_HILOGE("SourceType is invalid");
            return false;
        }
    }
    return true;
}
} // namespace MMI
} // namespace OHOS
