/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "pointer_event.h"
#include <iomanip>
#include "mmi_log.h"

using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "PointerEvent" };
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

int32_t PointerEvent::PointerItem::GetGlobalX() const
{
    return globalX_;
}

void PointerEvent::PointerItem::SetGlobalX(int32_t x)
{
    globalX_ = x;
}

int32_t PointerEvent::PointerItem::GetGlobalY() const
{
    return globalY_;
}

void PointerEvent::PointerItem::SetGlobalY(int32_t y)
{
    globalY_ = y;
}

int32_t PointerEvent::PointerItem::GetLocalX() const
{
    return localX_;
}

void PointerEvent::PointerItem::SetLocalX(int32_t x)
{
    localX_ = x;
}

int32_t PointerEvent::PointerItem::GetLocalY() const
{
    return localY_;
}

void PointerEvent::PointerItem::SetLocalY(int32_t y)
{
    localY_ = y;
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

int32_t PointerEvent::PointerItem::GetPressure() const
{
    return pressure_;
}

void PointerEvent::PointerItem::SetPressure(int32_t pressure)
{
    pressure_ = pressure;
}

int32_t PointerEvent::PointerItem::GetDeviceId() const
{
    return deviceId_;
}

void PointerEvent::PointerItem::SetDeviceId(int32_t deviceId)
{
    deviceId_ = deviceId;
}

bool PointerEvent::PointerItem::WriteToParcel(Parcel &out) const
{
    if (!out.WriteInt32(pointerId_)) {
        return false;
    }

    if (!out.WriteInt64(downTime_)) {
        return false;
    }

    if (!out.WriteBool(pressed_)) {
        return false;
    }

    if (!out.WriteInt32(globalX_)) {
        return false;
    }

    if (!out.WriteInt32(globalY_)) {
        return false;
    }

    if (!out.WriteInt32(localX_)) {
        return false;
    }

    if (!out.WriteInt32(localY_)) {
        return false;
    }

    if (!out.WriteInt32(width_)) {
        return false;
    }

    if (!out.WriteInt32(height_)) {
        return false;
    }

    if (!out.WriteInt32(pressure_)) {
        return false;
    }

    if (!out.WriteInt32(deviceId_)) {
        return false;
    }

    return true;
}

bool PointerEvent::PointerItem::ReadFromParcel(Parcel &in)
{
    if (!in.ReadInt32(pointerId_)) {
        return false;
    }

    if (!in.ReadInt64(downTime_)) {
        return false;
    }

    if (!in.ReadBool(pressed_)) {
        return false;
    }

    if (!in.ReadInt32(globalX_)) {
        return false;
    }

    if (!in.ReadInt32(globalY_)) {
        return false;
    }

    if (!in.ReadInt32(localX_)) {
        return false;
    }

    if (!in.ReadInt32(localY_)) {
        return false;
    }

    if (!in.ReadInt32(width_)) {
        return false;
    }

    if (!in.ReadInt32(height_)) {
        return false;
    }

    if (!in.ReadInt32(pressure_)) {
        return false;
    }

    if (!in.ReadInt32(deviceId_)) {
        return false;
    }

    return true;
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
    return std::shared_ptr<PointerEvent>(new (std::nothrow) PointerEvent(InputEvent::EVENT_TYPE_POINTER));
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
        case PointerEvent::POINTER_ACTION_CANCEL:
            return "cancel";
        case PointerEvent::POINTER_ACTION_DOWN:
            return "down";
        case PointerEvent::POINTER_ACTION_MOVE:
            return "move";
        case PointerEvent::POINTER_ACTION_UP:
            return "up";
        case PointerEvent::POINTER_ACTION_AXIS_BEGIN:
            return "axis-begin";
        case PointerEvent::POINTER_ACTION_AXIS_UPDATE:
            return "axis-update";
        case PointerEvent::POINTER_ACTION_AXIS_END:
            return "axis-end";
        case PointerEvent::POINTER_ACTION_BUTTON_DOWN:
            return "button-down";
        case PointerEvent::POINTER_ACTION_BUTTON_UP:
            return "button-up";
        default:
            break;
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
    pointers_.push_back(pointerItem);
}

void PointerEvent::UpdatePointerItem(int32_t pointerId, PointerItem &pointerItem)
{
    for (auto &item : pointers_) {
        if (item.GetPointerId() == pointerId) {
            item = pointerItem; // update
            return;
        }
    }
    pointers_.push_back(pointerItem); // insert
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
    auto iter = pressedButtons_.insert(buttonId);
    if (!iter.second) {
        MMI_LOGE("Insert value failed, button:%{public}d", buttonId);
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

std::vector<int32_t> PointerEvent::GetPointersIdList() const
{
    std::vector<int32_t> pointerIdList;
    for (auto &item : pointers_) {
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
        case PointerEvent::SOURCE_TYPE_MOUSE:
            return "mouse";
        case PointerEvent::SOURCE_TYPE_TOUCHSCREEN:
            return "touch-screen";
        case PointerEvent::SOURCE_TYPE_TOUCHPAD:
            return "touch-pad";
        default:
            break;
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
    double axisValue {  };
    if ((axis >= AXIS_TYPE_UNKNOWN) && (axis < AXIS_TYPE_MAX)) {
        axisValue = axisValues_[axis];
    }
    return axisValue;
}

void PointerEvent::SetAxisValue(AxisType axis, double axisValue)
{
    if ((axis >= AXIS_TYPE_UNKNOWN) && (axis < AXIS_TYPE_MAX)) {
        axisValues_[axis] = axisValue;
        axes_ = static_cast<int32_t>(static_cast<uint32_t>(axes_) | (1 << static_cast<uint32_t>(axis)));
    }
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

    if (!out.WriteInt32(pointerId_)) {
        return false;
    }

    // vector
    if (pointers_.size() > INT_MAX) {
        return false;
    }

    if (!out.WriteInt32(static_cast<int32_t>(pointers_.size()))) {
        return false;
    }

    for (const auto &item : pointers_) {
        if (!item.WriteToParcel(out)) {
            return false;
        }
    }

    // set
    if (pressedButtons_.size() > INT_MAX) {
        return false;
    }

    if (!out.WriteInt32(static_cast<int32_t>(pressedButtons_.size()))) {
        return false;
    }

    for (const auto &item : pressedButtons_) {
        if (!out.WriteInt32(item)) {
            return false;
        }
    }

    if (!out.WriteInt32(sourceType_)) {
        return false;
    }

    if (!out.WriteInt32(pointerAction_)) {
        return false;
    }

    if (!out.WriteInt32(buttonId_)) {
        return false;
    }

    if (!out.WriteUint32(axes_)) {
        return false;
    }

    // axisValues_
    const size_t axisValuesSize = axisValues_.size();
    if (axisValuesSize > INT_MAX) {
        return false;
    }

    if (axisValuesSize > AXIS_TYPE_MAX) {
        return false;
    }

    if (!out.WriteInt32(static_cast<int32_t>(axisValuesSize))) {
        return false;
    }

    for (const auto &item : axisValues_) {
        if (!out.WriteDouble(item)) {
            return false;
        }
    }

    return true;
}

bool PointerEvent::ReadFromParcel(Parcel &in)
{
    if (!InputEvent::ReadFromParcel(in)) {
        return false;
    }

    if (!in.ReadInt32(pointerId_)) {
        return false;
    }

    // vector
    const int32_t pointersSize = in.ReadInt32();
    if (pointersSize < 0) {
        return false;
    }

    for (int32_t i = 0; i < pointersSize; i++) {
        PointerItem val = {};
        if (!val.ReadFromParcel(in)) {
            return false;
        }
        pointers_.push_back(val);
    }

    // set
    const int32_t pressedButtonsSize = in.ReadInt32();
    if (pressedButtonsSize < 0) {
        return false;
    }

    for (int32_t i = 0; i < pressedButtonsSize; i++) {
        int32_t val = 0;
        if (!in.ReadInt32(val)) {
            return false;
        }
        auto iter = pressedButtons_.insert(val);
        if (!iter.second) {
            MMI_LOGE("Insert value failed, button:%{public}d", val);
        }
    }

    if (!in.ReadInt32(sourceType_)) {
        return false;
    }

    if (!in.ReadInt32(pointerAction_)) {
        return false;
    }

    if (!in.ReadInt32(buttonId_)) {
        return false;
    }

    if (!in.ReadUint32(axes_)) {
        return false;
    }

    // axisValue_ array
    const int32_t axisValueSize = in.ReadInt32();
    if (axisValueSize < 0) {
        return false;
    }

    if (axisValueSize > AXIS_TYPE_MAX) {
        return false;
    }

    for (int32_t i = 0; i < axisValueSize; i++) {
        double val = {};
        if (!in.ReadDouble(val)) {
            return false;
        }
        axisValues_[i] = val;
    }

    return true;
}

bool PointerEvent::IsValidCheckMouseFunc() const
{
    MMI_LOGD("begin");
    if (pointers_.size() != 1) {
        MMI_LOGE("Pointers_ is invalid");
        return false;
    }

    size_t maxPressedButtons = 3;
    if (pressedButtons_.size() > maxPressedButtons) {
        MMI_LOGE("PressedButtons_.size is greater than three and is invalid");
        return false;
    }

    for (const auto &item : pressedButtons_) {
        if (item != MOUSE_BUTTON_LEFT && item != MOUSE_BUTTON_RIGHT && item != MOUSE_BUTTON_MIDDLE) {
            MMI_LOGE("PressedButtons_ is invalid");
            return false;
        }
    }

    int32_t pointAction = GetPointerAction();
    if (pointAction != POINTER_ACTION_CANCEL && pointAction != POINTER_ACTION_MOVE &&
        pointAction != POINTER_ACTION_AXIS_BEGIN && pointAction != POINTER_ACTION_AXIS_UPDATE &&
        pointAction != POINTER_ACTION_AXIS_END && pointAction != POINTER_ACTION_BUTTON_DOWN &&
        pointAction != POINTER_ACTION_BUTTON_UP) {
        MMI_LOGE("PointAction is invalid");
        return false;
    }

    int32_t buttonId = GetButtonId();
    if (pointAction == POINTER_ACTION_BUTTON_DOWN || pointAction == POINTER_ACTION_BUTTON_UP) {
        if (buttonId != MOUSE_BUTTON_LEFT && buttonId != MOUSE_BUTTON_RIGHT && buttonId != MOUSE_BUTTON_MIDDLE) {
            MMI_LOGE("ButtonId is invalid");
            return false;
        }
    } else {
        if (buttonId != BUTTON_NONE) {
            MMI_LOGE("ButtonId is not BUTTON_NONE and is invalid");
            return false;
        }
    }
    MMI_LOGD("end");
    return true;
}

bool PointerEvent::IsValidCheckMouse() const
{
    MMI_LOGD("begin");
    int32_t mousePointID = GetPointerId();
    if (mousePointID < 0) {
        MMI_LOGE("MousePointID is invalid");
        return false;
    }

    if (!IsValidCheckMouseFunc()) {
        MMI_LOGE("IsValidCheckMouseFunc is invalid");
        return false;
    }

    for (const auto &item : pointers_) {
        if (item.GetPointerId() < 0) {
            MMI_LOGE("Item.pointerid is invalid");
            return false;
        }

        if (item.GetPointerId() != mousePointID) {
            MMI_LOGE("Item.pointerid is not same to mousePointID and is invalid");
            return false;
        }

        if (item.GetDownTime() > 0) {
            MMI_LOGE("Item.downtime is invalid");
            return false;
        }

        if (item.IsPressed() != false) {
            MMI_LOGE("Item.ispressed is not false and is invalid");
            return false;
        }
    }
    MMI_LOGD("end");
    return true;
}

bool PointerEvent::IsValidCheckTouchFunc() const
{
    MMI_LOGD("begin");
    int32_t touchPointID = GetPointerId();
    if (touchPointID < 0) {
        MMI_LOGE("TouchPointID is invalid");
        return false;
    }

    if (!pressedButtons_.empty()) {
        MMI_LOGE("PressedButtons_.size is invalid");
        return false;
    }

    int32_t pointAction = GetPointerAction();
    if (pointAction != POINTER_ACTION_CANCEL && pointAction != POINTER_ACTION_MOVE &&
        pointAction != POINTER_ACTION_DOWN && pointAction != POINTER_ACTION_UP) {
        MMI_LOGE("PointAction is invalid");
        return false;
    }

    if (GetButtonId() != BUTTON_NONE) {
        MMI_LOGE("ButtonId is invalid");
        return false;
    }
    MMI_LOGD("PointerEvent::IsValidCheckTouchFunc end");
    return true;
}

bool PointerEvent::IsValidCheckTouch() const
{
    MMI_LOGD("begin");
    if (!IsValidCheckTouchFunc()) {
        MMI_LOGE("IsValidCheckTouchFunc is invalid");
        return false;
    }
    bool isSameItem = false;
    int32_t touchPointID = GetPointerId();
    for (auto item = pointers_.begin(); item != pointers_.end(); item++) {
        if (item->GetPointerId() < 0) {
            MMI_LOGE("Item.pointerid is invalid");
            return false;
        }

        if (item->GetPointerId() == touchPointID) {
            isSameItem = true;
        }

        if (item->GetDownTime() <= 0) {
            MMI_LOGE("Item.downtime is invalid");
            return false;
        }

        if (item->IsPressed() != false) {
            MMI_LOGE("Item.ispressed is not false and is invalid");
            return false;
        }

        auto itemtmp = item;
        for (++itemtmp; itemtmp != pointers_.end(); itemtmp++) {
            if (item->GetPointerId() == itemtmp->GetPointerId()) {
                MMI_LOGE("Pointitems pointerid exist same items and is invalid");
                return false;
            }
        }
    }

    if (!isSameItem) {
        MMI_LOGE("Item.pointerid is not same to touchPointID and is invalid");
        return false;
    }
    MMI_LOGD("end");
    return true;
}

bool PointerEvent::IsValid() const
{
    MMI_LOGD("begin");
    int32_t sourceType = GetSourceType();
    if (sourceType != SOURCE_TYPE_MOUSE && sourceType != SOURCE_TYPE_TOUCHSCREEN &&
        sourceType != SOURCE_TYPE_TOUCHPAD) {
        MMI_LOGE("SourceType is invalid");
        return false;
    }
    switch (sourceType) {
        case SOURCE_TYPE_MOUSE: {
            if (!IsValidCheckMouse()) {
                MMI_LOGE("IsValidCheckMouse is invalid");
                return false;
            }
            break;
        }
        case SOURCE_TYPE_TOUCHSCREEN:
        case SOURCE_TYPE_TOUCHPAD: {
            if (!IsValidCheckTouch()) {
                MMI_LOGE("IsValidCheckTouch is invalid");
                return false;
            }
            break;
        }
        default: {
            MMI_LOGE("SourceType is invalid");
            return false;
            break;
        }
    }
    MMI_LOGD("end");
    return true;
}

std::ostream& operator<<(std::ostream& ostream, PointerEvent& pointerEvent)
{
    const int precision = 2;
    std::vector<int32_t> pointerIds { pointerEvent.GetPointersIdList() };
    ostream << "EventType:" << pointerEvent.DumpEventType()
         << ",ActionTime:" << pointerEvent.GetActionTime()
         << ",Action:" << pointerEvent.GetAction()
         << ",ActionStartTime:" << pointerEvent.GetActionStartTime()
         << ",Flag:" << pointerEvent.GetFlag()
         << ",PointerAction:" << pointerEvent.DumpPointerAction()
         << ",SourceType:" << pointerEvent.DumpSourceType()
         << ",VerticalAxisValue:" << std::fixed << std::setprecision(precision)
         << pointerEvent.GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)
         << ",HorizontalAxisValue:" << std::fixed << std::setprecision(precision)
         << pointerEvent.GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)
         << ",PinchAxisValue:" << std::fixed << std::setprecision(precision)
         << pointerEvent.GetAxisValue(PointerEvent::AXIS_TYPE_PINCH)
         << ",PointerCount:" << pointerIds.size()
         << ",EventNumber:" << pointerEvent.GetId() << std::endl;

    for (const auto& pointerId : pointerIds) {
        PointerEvent::PointerItem item;
        if (!pointerEvent.GetPointerItem(pointerId, item)) {
            MMI_LOGE("Invalid pointer: %{public}d.", pointerId);
            return ostream;
        }
        ostream << "DownTime:" << item.GetDownTime()
            << ",IsPressed:" << std::boolalpha << item.IsPressed()
            << ",GlobalX:" << item.GetGlobalX() << ",GlobalY:" << item.GetGlobalY()
            << ",LocalX:" << item.GetLocalX() << ",LocalY:" << item.GetLocalY()
            << ",Width:" << item.GetWidth() << ",Height:" << item.GetHeight()
            << ",Pressure:" << item.GetPressure() << std::endl;
    }
    std::vector<int32_t> pressedKeys = pointerEvent.GetPressedKeys();
    if (!pressedKeys.empty()) {
        ostream << "Pressed keyCode: [";
        for (const auto& keyCode : pressedKeys) {
            ostream << keyCode << ",";
        }
        ostream << "]" << std::endl;
    }
    return ostream;
}
} // namespace MMI
} // namespace OHOS
