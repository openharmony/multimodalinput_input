/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

namespace OHOS {
namespace MMI {
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

int32_t PointerEvent::PointerItem::GetDownTime() const
{
    return donwTime_;
}

void PointerEvent::PointerItem::SetDownTime(int32_t downTime)
{
    donwTime_ = downTime;
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

    if (!out.WriteInt32(donwTime_)) {
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

    if (!in.ReadInt32(donwTime_)) {
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

PointerEvent::~PointerEvent() {}

std::shared_ptr<PointerEvent> PointerEvent::Create()
{
    return std::shared_ptr<PointerEvent>(new PointerEvent(InputEvent::EVENT_TYPE_POINTER));
}

int32_t PointerEvent::GetPointerAction() const
{
    return pointerAction_;
}

void PointerEvent::SetPointerAction(int32_t pointerAction)
{
    pointerAction_ = pointerAction;
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
    for (auto &item : pointers_) {
        if (item.GetPointerId() == pointerId) {
            pointerItem = item;
            return true;
        }
    }
    return false;
}

void PointerEvent::RemovePointerItem(int32_t pointerId)
{
    for (auto it = pointers_.begin(); it != pointers_.end(); it++) {
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

std::set<int32_t> PointerEvent::GetPressedButtons() const
{
    return pressedButtons_;
}

bool PointerEvent::IsButtonPressed(int buttonId) const
{
    return (pressedButtons_.find(buttonId) != pressedButtons_.end());
}

void PointerEvent::SetButtonPressed(int buttonId)
{
    pressedButtons_.insert(buttonId);
}

std::vector<int32_t> PointerEvent::GetPointersIdList() const
{
    std::vector<int32_t> pointerIdList;

    for (auto &item : pointers_) {
        pointerIdList.push_back(item.GetPointerId());
    }

    return pointerIdList;
}

int32_t PointerEvent::GetSourceType()
{
    return sourceType_;
}

void PointerEvent::SetSourceType(int32_t sourceType)
{
    sourceType_ = sourceType;
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
        axes_ |= (1 << axis);
    }
}

bool PointerEvent::HasAxis(int32_t axes, AxisType axis)
{
    bool ret { false };
    if ((axis >= AXIS_TYPE_UNKNOWN) && (axis < AXIS_TYPE_MAX)) {
        ret = static_cast<bool>(axes & (1 << axis));
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

    for (const auto &v : pointers_) {
        if (!v.WriteToParcel(out)) {
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

    for (const auto &v : pressedButtons_) {
        if (!out.WriteInt32(v)) {
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

    if (!out.WriteInt32(axes_)) {
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

    for (const auto &v : axisValues_) {
        if (!out.WriteDouble(v)) {
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
    
    for (int32_t i = 0; i < pointersSize; ++i) {
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
    
    for (int32_t i = 0; i < pressedButtonsSize; ++i) {
        int32_t val = 0;
        if (!in.ReadInt32(val)) {
            return false;
        }
        pressedButtons_.insert(val);
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

    if (!in.ReadInt32(axes_)) {
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
    
    for (int32_t i = 0; i < axisValueSize; ++i) {
        double val = {};
        if (!in.ReadDouble(val)) {
            return false;
        }
        axisValues_[i] = val;
    }

    return true;
}
}
} // namespace OHOS::MMI
