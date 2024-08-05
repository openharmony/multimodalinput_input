/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerEvent"

using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace MMI {
namespace {
constexpr double MAX_PRESSURE { 1.0 };
constexpr size_t MAX_N_PRESSED_BUTTONS { 10 };
constexpr size_t MAX_N_POINTER_ITEMS { 10 };
constexpr int32_t SIMULATE_EVENT_START_ID { 10000 };
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
constexpr size_t MAX_N_ENHANCE_DATA_SIZE { 64 };
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
constexpr size_t MAX_N_BUFFER_SIZE { 512 };
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

double PointerEvent::PointerItem::GetDisplayXPos() const
{
    return displayXPos_;
}

void PointerEvent::PointerItem::SetDisplayXPos(double x)
{
    displayXPos_ = x;
}

double PointerEvent::PointerItem::GetDisplayYPos() const
{
    return displayYPos_;
}

void PointerEvent::PointerItem::SetDisplayYPos(double y)
{
    displayYPos_ = y;
}

double PointerEvent::PointerItem::GetWindowXPos() const
{
    return windowXPos_;
}

void PointerEvent::PointerItem::SetWindowXPos(double x)
{
    windowXPos_ = x;
}

double PointerEvent::PointerItem::GetWindowYPos() const
{
    return windowYPos_;
}

void PointerEvent::PointerItem::SetWindowYPos(double y)
{
    windowYPos_ = y;
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
    if (pressure < 0.0) {
        pressure_ = 0.0;
    } else if (TOOL_TYPE_PEN == GetToolType()) {
        pressure_ = pressure >= MAX_PRESSURE ? MAX_PRESSURE : pressure;
    } else {
        pressure_ = pressure;
    }
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

int32_t PointerEvent::PointerItem::GetOriginPointerId() const
{
    return originPointerId_;
}

void PointerEvent::PointerItem::SetOriginPointerId(int32_t originPointerId)
{
    originPointerId_ = originPointerId;
}

int32_t PointerEvent::PointerItem::GetRawDy() const
{
    return rawDy_;
}

void PointerEvent::PointerItem::SetRawDy(int32_t rawDy)
{
    rawDy_ = rawDy;
}

int32_t PointerEvent::PointerItem::GetRawDisplayX() const
{
    return rawDisplayX_;
}
 
void PointerEvent::PointerItem::SetRawDisplayX(int32_t rawDisplayX)
{
    rawDisplayX_ = rawDisplayX;
}
 
int32_t PointerEvent::PointerItem::GetRawDisplayY() const
{
    return rawDisplayY_;
}
 
void PointerEvent::PointerItem::SetRawDisplayY(int32_t rawDisplayY)
{
    rawDisplayY_ = rawDisplayY;
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
        out.WriteInt32(rawDy_) &&
        out.WriteInt32(targetWindowId_) &&
        out.WriteDouble(displayXPos_) &&
        out.WriteDouble(displayYPos_) &&
        out.WriteDouble(windowXPos_) &&
        out.WriteDouble(windowYPos_) &&
        out.WriteInt32(originPointerId_)
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
        in.ReadInt32(rawDy_) &&
        in.ReadInt32(targetWindowId_) &&
        in.ReadDouble(displayXPos_) &&
        in.ReadDouble(displayYPos_) &&
        in.ReadDouble(windowXPos_) &&
        in.ReadDouble(windowYPos_) &&
        in.ReadInt32(originPointerId_)
    );
}

PointerEvent::PointerEvent(int32_t eventType) : InputEvent(eventType) {}

PointerEvent::PointerEvent(const PointerEvent& other)
    : InputEvent(other), pointerId_(other.pointerId_), pointers_(other.pointers_),
      pressedButtons_(other.pressedButtons_), sourceType_(other.sourceType_),
      pointerAction_(other.pointerAction_), originPointerAction_(other.originPointerAction_),
      buttonId_(other.buttonId_), fingerCount_(other.fingerCount_), zOrder_(other.zOrder_),
      axes_(other.axes_), axisValues_(other.axisValues_), velocity_(other.velocity_),
      pressedKeys_(other.pressedKeys_), buffer_(other.buffer_), axisEventType_(other.axisEventType_),
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
      fingerprintDistanceX_(other.fingerprintDistanceX_), fingerprintDistanceY_(other.fingerprintDistanceY_),
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
      dispatchTimes_(other.dispatchTimes_)
      {}

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
    originPointerAction_ = POINTER_ACTION_UNKNOWN;
    buttonId_ = -1;
    fingerCount_ = 0;
    zOrder_ = -1.0f;
    dispatchTimes_ = 0;
    axes_ = 0U;
    axisValues_.fill(0.0);
    velocity_ = 0.0;
    axisEventType_ = AXIS_EVENT_TYPE_UNKNOWN;
    pressedKeys_.clear();
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    fingerprintDistanceX_ = 0.0;
    fingerprintDistanceY_ = 0.0;
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
}

int32_t PointerEvent::GetPointerAction() const
{
    return pointerAction_;
}

void PointerEvent::SetPointerAction(int32_t pointerAction)
{
    pointerAction_ = pointerAction;
    originPointerAction_ = pointerAction;
}

int32_t PointerEvent::GetOriginPointerAction() const
{
    return originPointerAction_;
}

void PointerEvent::SetOriginPointerAction(int32_t pointerAction)
{
    originPointerAction_ = pointerAction;
}

static const std::unordered_map<int32_t, std::string> pointerActionMap = {
    { PointerEvent::POINTER_ACTION_CANCEL, "cancel" },
    { PointerEvent::POINTER_ACTION_DOWN, "down" },
    { PointerEvent::POINTER_ACTION_MOVE, "move" },
    { PointerEvent::POINTER_ACTION_UP, "up" },
    { PointerEvent::POINTER_ACTION_AXIS_BEGIN, "axis-begin" },
    { PointerEvent::POINTER_ACTION_AXIS_UPDATE, "axis-update" },
    { PointerEvent::POINTER_ACTION_AXIS_END, "axis-end" },
    { PointerEvent::POINTER_ACTION_BUTTON_DOWN, "button-down" },
    { PointerEvent::POINTER_ACTION_BUTTON_UP, "button-up" },
    { PointerEvent::POINTER_ACTION_ENTER_WINDOW, "enter-window" },
    { PointerEvent::POINTER_ACTION_LEAVE_WINDOW, "leave-window" },
    { PointerEvent::POINTER_ACTION_PULL_DOWN, "pull-down" },
    { PointerEvent::POINTER_ACTION_PULL_MOVE, "pull-move" },
    { PointerEvent::POINTER_ACTION_PULL_UP, "pull-up" },
    { PointerEvent::POINTER_ACTION_PULL_IN_WINDOW, "pull-in-window" },
    { PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW, "pull-out-window" },
    { PointerEvent::POINTER_ACTION_SWIPE_BEGIN, "swipe-begin" },
    { PointerEvent::POINTER_ACTION_SWIPE_UPDATE, "swipe-update" },
    { PointerEvent::POINTER_ACTION_SWIPE_END, "swipe-end" },
    { PointerEvent::POINTER_ACTION_ROTATE_BEGIN, "rotate-begin" },
    { PointerEvent::POINTER_ACTION_ROTATE_UPDATE, "rotate-update" },
    { PointerEvent::POINTER_ACTION_ROTATE_END, "rotate-end" },
    { PointerEvent::POINTER_ACTION_TRIPTAP, "touchpad-triptap" },
    { PointerEvent::POINTER_ACTION_QUADTAP, "quadtap" },
    { PointerEvent::POINTER_ACTION_HOVER_MOVE, "hover-move" },
    { PointerEvent::POINTER_ACTION_HOVER_ENTER, "hover-enter" },
    { PointerEvent::POINTER_ACTION_HOVER_EXIT, "hover-exit" },
    { PointerEvent::POINTER_ACTION_FINGERPRINT_DOWN, "fingerprint-down" },
    { PointerEvent::POINTER_ACTION_FINGERPRINT_UP, "fingerprint-up" },
    { PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE, "fingerprint-slide" },
    { PointerEvent::POINTER_ACTION_FINGERPRINT_RETOUCH, "fingerprint-retouch" },
    { PointerEvent::POINTER_ACTION_FINGERPRINT_CLICK, "fingerprint-click" },
};

const char* PointerEvent::DumpPointerAction() const
{
    auto it = pointerActionMap.find(pointerAction_);
    if (it != pointerActionMap.end()) {
        return it->second.c_str();
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

void PointerEvent::RemoveAllPointerItems()
{
    pointers_.clear();
}

void PointerEvent::AddPointerItem(PointerItem &pointerItem)
{
    if (pointers_.size() >= MAX_N_POINTER_ITEMS) {
        MMI_HILOGE("Exceed maximum allowed number of pointer items");
        return;
    }
    int32_t pointerId = pointerItem.GetPointerId();
    for (auto &item : pointers_) {
        if (item.GetPointerId() == pointerId) {
            item = pointerItem;
            return;
        }
    }
    pointers_.push_back(pointerItem);
}

void PointerEvent::UpdatePointerItem(int32_t pointerId, PointerItem &pointerItem)
{
    for (auto &item : pointers_) {
        if ((item.GetPointerId() % SIMULATE_EVENT_START_ID) == pointerId) {
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

int32_t PointerEvent::GetPointerCount() const
{
    return static_cast<int32_t>(pointers_.size());
}

std::vector<int32_t> PointerEvent::GetPointerIds() const
{
    std::vector<int32_t> pointerIdList;
    for (const auto &item : pointers_) {
        pointerIdList.push_back(item.GetPointerId());
    }
    return pointerIdList;
}

std::list<PointerEvent::PointerItem> PointerEvent::GetAllPointerItems() const
{
    return pointers_;
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
        case PointerEvent::SOURCE_TYPE_FINGERPRINT: {
            return "fingerprint";
        }
        case PointerEvent::SOURCE_TYPE_CROWN: {
            return "crown";
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

int32_t PointerEvent::GetFingerCount() const
{
    return fingerCount_;
}

void PointerEvent::SetFingerCount(int32_t fingerCount)
{
    fingerCount_ = fingerCount;
}

float PointerEvent::GetZOrder() const
{
    return zOrder_;
}

void PointerEvent::SetZOrder(float zOrder)
{
    zOrder_ = zOrder;
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

double PointerEvent::GetVelocity() const
{
    return velocity_;
}

void PointerEvent::SetVelocity(double velocity)
{
    velocity_ = velocity;
}

void PointerEvent::SetPressedKeys(const std::vector<int32_t> pressedKeys)
{
    pressedKeys_ = pressedKeys;
}

std::vector<int32_t> PointerEvent::GetPressedKeys() const
{
    return pressedKeys_;
}

int32_t PointerEvent::GetAxisEventType() const
{
    return axisEventType_;
}

void PointerEvent::SetAxisEventType(int32_t axisEventType)
{
    axisEventType_ = axisEventType;
}

#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
void PointerEvent::SetEnhanceData(const std::vector<uint8_t> enhanceData)
{
    enhanceData_ = enhanceData;
}

std::vector<uint8_t> PointerEvent::GetEnhanceData() const
{
    return enhanceData_;
}
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT

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

    WRITEINT32(out, static_cast<int32_t>(buffer_.size()));

    for (const auto& buff : buffer_) {
        WRITEUINT8(out, buff);
    }

    WRITEINT32(out, static_cast<int32_t>(pressedButtons_.size()));

    for (const auto &item : pressedButtons_) {
        WRITEINT32(out, item);
    }

    WRITEINT32(out, sourceType_);

    WRITEINT32(out, pointerAction_);

    WRITEINT32(out, originPointerAction_);

    WRITEINT32(out, buttonId_);

    WRITEINT32(out, fingerCount_);

    WRITEFLOAT(out, zOrder_);

    const uint32_t axes { GetAxes() };
    WRITEUINT32(out, axes);

    for (int32_t i = AXIS_TYPE_UNKNOWN; i < AXIS_TYPE_MAX; ++i) {
        const AxisType axis { static_cast<AxisType>(i) };
        if (HasAxis(axes, axis)) {
            WRITEDOUBLE(out, GetAxisValue(axis));
        }
    }
    WRITEDOUBLE(out, velocity_);

    WRITEINT32(out, axisEventType_);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    WRITEINT32(out, static_cast<int32_t>(enhanceData_.size()));
    for (uint32_t i = 0; i < enhanceData_.size(); i++) {
        WRITEUINT32(out, enhanceData_[i]);
    }
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    WRITEDOUBLE(out, fingerprintDistanceX_);
    WRITEDOUBLE(out, fingerprintDistanceY_);
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
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

    if (!ReadBufferFromParcel(in)) {
        return false;
    }

    int32_t nPressedButtons;
    READINT32(in, nPressedButtons);
    if (nPressedButtons > static_cast<int32_t>(MAX_N_PRESSED_BUTTONS)) {
        return false;
    }

    for (int32_t i = 0; i < nPressedButtons; ++i) {
        int32_t buttonId = 0;
        READINT32(in, buttonId);
        SetButtonPressed(buttonId);
    }

    READINT32(in, sourceType_);
    READINT32(in, pointerAction_);
    READINT32(in, originPointerAction_);
    READINT32(in, buttonId_);
    READINT32(in, fingerCount_);
    READFLOAT(in, zOrder_);

    if (!ReadAxisFromParcel(in)) {
        return false;
    }

    READDOUBLE(in, velocity_);

    READINT32(in, axisEventType_);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    if (!ReadEnhanceDataFromParcel(in)) {
        return false;
    }
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    READDOUBLE(in, fingerprintDistanceX_);
    READDOUBLE(in, fingerprintDistanceY_);
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
    return true;
}

bool PointerEvent::ReadAxisFromParcel(Parcel &in)
{
    uint32_t axes = 0;
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

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
void PointerEvent::SetFingerprintDistanceX(double x)
{
    fingerprintDistanceX_ = x;
}

void PointerEvent::SetFingerprintDistanceY(double y)
{
    fingerprintDistanceY_ = y;
}

double PointerEvent::GetFingerprintDistanceX() const
{
    return fingerprintDistanceX_;
}

double PointerEvent::GetFingerprintDistanceY() const
{
    return fingerprintDistanceY_;
}
#endif // OHOS_BUILD_ENABLE_FINGERPRINT

#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
bool PointerEvent::ReadEnhanceDataFromParcel(Parcel &in)
{
    int32_t size = 0;
    READINT32(in, size);
    if (size > static_cast<int32_t>(MAX_N_ENHANCE_DATA_SIZE) || size < 0) {
        MMI_HILOGE("enhanceData_ size is invalid");
        return false;
    }

    for (int32_t i = 0; i < size; i++) {
        uint32_t val = 0;
        READUINT32(in, val);
        enhanceData_.emplace_back(val);
    }
    return true;
}
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT

bool PointerEvent::ReadBufferFromParcel(Parcel &in)
{
    int32_t bufflen = 0;
    READINT32(in, bufflen);
    if (bufflen > static_cast<int32_t>(MAX_N_BUFFER_SIZE)) {
        return false;
    }

    for (int32_t i = 0; i < bufflen; ++i) {
        uint8_t data;
        READUINT8(in, data);
        buffer_.push_back(data);
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

    const size_t maxPressedButtons = 3;
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
    bool checkFlag = pointAction != POINTER_ACTION_CANCEL && pointAction != POINTER_ACTION_MOVE &&
        pointAction != POINTER_ACTION_AXIS_BEGIN && pointAction != POINTER_ACTION_AXIS_UPDATE &&
        pointAction != POINTER_ACTION_AXIS_END && pointAction != POINTER_ACTION_BUTTON_DOWN &&
        pointAction != POINTER_ACTION_BUTTON_UP;
    if (checkFlag) {
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
    if (GetPointerId() < 0) {
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
    switch (GetSourceType()) {
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
        case SOURCE_TYPE_JOYSTICK:
            break;
        default: {
            MMI_HILOGE("SourceType is invalid");
            return false;
        }
    }
    return true;
}

void PointerEvent::SetBuffer(std::vector<uint8_t> buffer)
{
    buffer_ = buffer;
}

void PointerEvent::ClearBuffer()
{
    buffer_.clear();
}

std::vector<uint8_t> PointerEvent::GetBuffer() const
{
    return buffer_;
}

int32_t PointerEvent::GetDispatchTimes() const
{
    return dispatchTimes_;
}

void PointerEvent::SetDispatchTimes(int32_t dispatchTimes)
{
    dispatchTimes_ = dispatchTimes;
}

void PointerEvent::SetHandlerEventType(HandleEventType eventType)
{
    handleEventType_ = eventType;
}

HandleEventType PointerEvent::GetHandlerEventType() const
{
    return handleEventType_;
}

std::string_view PointerEvent::ActionToShortStr(int32_t action)
{
    // 该函数逻辑简单，功能单一，考虑性能影响，使用switch-case而不是表驱动实现。
    switch (action) {
        case PointerEvent::POINTER_ACTION_CANCEL:
            return "P:C:";
        case PointerEvent::POINTER_ACTION_DOWN:
            return "P:D:";
        case PointerEvent::POINTER_ACTION_MOVE:
            return "P:M:";
        case PointerEvent::POINTER_ACTION_UP:
            return "P:U:";
        case PointerEvent::POINTER_ACTION_AXIS_BEGIN:
            return "P:AB:";
        case PointerEvent::POINTER_ACTION_AXIS_UPDATE:
            return "P:AU:";
        case PointerEvent::POINTER_ACTION_AXIS_END:
            return "P:AE:";
        case PointerEvent::POINTER_ACTION_BUTTON_DOWN:
            return "P:BD:";
        case PointerEvent::POINTER_ACTION_BUTTON_UP:
            return "P:BU:";
        case PointerEvent::POINTER_ACTION_ENTER_WINDOW:
            return "P:EW:";
        case PointerEvent::POINTER_ACTION_LEAVE_WINDOW:
            return "P:LW:";
        case PointerEvent::POINTER_ACTION_PULL_DOWN:
            return "P:PD:";
        case PointerEvent::POINTER_ACTION_PULL_MOVE:
            return "P:PM:";
        case PointerEvent::POINTER_ACTION_PULL_UP:
            return "P:PU:";
        case PointerEvent::POINTER_ACTION_PULL_IN_WINDOW:
            return "P:PI:";
        case PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW:
            return "P:PO:";
        case PointerEvent::POINTER_ACTION_SWIPE_BEGIN:
            return "P:SB:";
        case PointerEvent::POINTER_ACTION_SWIPE_UPDATE:
            return "P:SU:";
        case PointerEvent::POINTER_ACTION_SWIPE_END:
            return "P:SE:";
        case PointerEvent::POINTER_ACTION_ROTATE_BEGIN:
            return "P:RB:";
        case PointerEvent::POINTER_ACTION_ROTATE_UPDATE:
            return "P:RU:";
        case PointerEvent::POINTER_ACTION_ROTATE_END:
            return "P:RE:";
        case PointerEvent::POINTER_ACTION_TRIPTAP:
            return "P:TT:";
        case PointerEvent::POINTER_ACTION_QUADTAP:
            return "P:Q:";
        case PointerEvent::POINTER_ACTION_HOVER_MOVE:
            return "P:HM:";
        case PointerEvent::POINTER_ACTION_HOVER_ENTER:
            return "P:HE:";
        case PointerEvent::POINTER_ACTION_HOVER_EXIT:
            return "P:HEX:";
        case PointerEvent::POINTER_ACTION_FINGERPRINT_DOWN:
            return "P:FD:";
        case PointerEvent::POINTER_ACTION_FINGERPRINT_UP:
            return "P:FU:";
        case PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE:
            return "P:FS:";
        case PointerEvent::POINTER_ACTION_FINGERPRINT_RETOUCH:
            return "P:FR:";
        case PointerEvent::POINTER_ACTION_FINGERPRINT_CLICK:
            return "P:FC:";
        case PointerEvent::POINTER_ACTION_UNKNOWN:
            return "P:UK:";
        default:
            return "P:?:";
    }
}
} // namespace MMI
} // namespace OHOS
