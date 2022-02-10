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

#ifndef POINTER_EVENT_H
#define POINTER_EVENT_H

#include <array>
#include <list>
#include <vector>
#include <memory>
#include <map>
#include <set>
#include "parcel.h"
#include "input_event.h"
namespace OHOS {
namespace MMI {
class PointerEvent : public InputEvent {
public:
    // Unknown pointer action. Usually used to indicate the initial invalid value
    static const int32_t POINTER_ACTION_UNKNOWN = 0;
    // Indicates cancel action.
    static const int32_t POINTER_ACTION_CANCEL = 1;

    // Pointer pressing action.
    // Indicates that the finger is pressed on the screen,
    // the left mouse button is pressed, etc.
    static const int32_t POINTER_ACTION_DOWN = 2;
    // Pointer movement action.
    // Indicates finger movement on the screen, mouse movement, etc.
    static const int32_t POINTER_ACTION_MOVE = 3;
    // Pointer release action.
    // Indicates that the finger leaves the screen, the left mouse button is released, etc.
    static const int32_t POINTER_ACTION_UP = 4;

    // The start action of the axis event related to the pointer
    static const int32_t POINTER_ACTION_AXIS_BEGIN = 5;
    // Update action of axis event related to pointer
    static const int32_t POINTER_ACTION_AXIS_UPDATE = 6;
    // End action of axis event related to pointer
    static const int32_t POINTER_ACTION_AXIS_END = 7;

    // Button press action on pointer input device
    static const int32_t POINTER_ACTION_BUTTON_DOWN = 8;
    // Button release action on pointer input device
    static const int32_t POINTER_ACTION_BUTTON_UP = 9;

    enum AxisType {
        // Unknown axis type, generally used to indicate the initial value
        AXIS_TYPE_UNKNOWN,
        // Scroll axis, generally used to represent the UI element where the mouse is scrolled
        AXIS_TYPE_SCROLL_VERTICAL,
        AXIS_TYPE_SCROLL_HORIZONTAL,
        // Pinch axis, generally used to represent the UI element where the mouse is zoomed
        AXIS_TYPE_PINCH,
        // This is for programing usage only, indicating the number of axis types defined.
        AXIS_TYPE_MAX
    };

    // Unknown source type.
    // Indicates the default value of the source of pointer type events
    static const int32_t SOURCE_TYPE_UNKNOWN = 0;
    // Mouse source type. Indicates that the source of the pointer type event is a mouse-like device
    static const int32_t SOURCE_TYPE_MOUSE = 1;
    // Touch screen source type. Indicates that the source of pointer type events is a touch screen device
    static const int32_t SOURCE_TYPE_TOUCHSCREEN = 2;
    // Touchpad source type. Indicates that the source of pointer type events is a touchpad device
    static const int32_t SOURCE_TYPE_TOUCHPAD = 3;

    static const int32_t BUTTON_NONE = -1;
    static const int32_t MOUSE_BUTTON_LEFT = 0;
    static const int32_t MOUSE_BUTTON_RIGHT = 1;
    static const int32_t MOUSE_BUTTON_MIDDLE = 2;

public:
    static std::shared_ptr<PointerEvent> from(std::shared_ptr<InputEvent> inputEvent);

public:
    class PointerItem {
    public:
        PointerItem();
        ~PointerItem();

    public:
        // Get or set the id of PointerItem
        int32_t GetPointerId() const;
        void SetPointerId(int32_t pointerId);

        // Get or set the time when the Pointer is pressed
        int32_t GetDownTime() const;
        void SetDownTime(int32_t downTime);

        // Get or set whether the Pointer is pressed
        bool IsPressed() const;
        void SetPressed(bool pressed);

        // Get or set the global X coordinate of Pointer.
        // For touchpad input events, it is the absolute X coordinate on the touchpad;
        // for other pointer type input events, it is the coordinate X in the target logic screen
        int32_t GetGlobalX() const;
        void SetGlobalX(int32_t globalX);

        // Get or set the global Y coordinate of Pointer.
        // For touchpad input events, it is the absolute Y coordinate on the touchpad;
        // for other pointer type input events, it is the coordinate Y in the target logic screen
        int32_t GetGlobalY() const;
        void SetGlobalY(int32_t globalY);

        // Get or set the X coordinate in the current window
        int32_t GetLocalX() const;
        void SetLocalX(int32_t x);

        // Get or set the X coordinate in the current window
        int32_t GetLocalY() const;
        void SetLocalY(int32_t y);

        // Gets or sets the width of the pressed area. For precisely pointed input events such as a mouse, it is 0
        int32_t GetWidth() const;
        void SetWidth(int32_t width);

        // Gets or sets the height of the pressed area. For precisely pointed input events such as a mouse, it is 0
        int32_t GetHeight() const;
        void SetHeight(int32_t height);

        // Get or set the pressed pressure value.
        // For unsupported devices, use the default value 0
        int32_t GetPressure() const;
        void SetPressure(int32_t pressure);

        // Get or set the device id, the default value is 0, which means non-real device
        int32_t GetDeviceId() const;
        void SetDeviceId(int32_t deviceId);
    public:
        bool WriteToParcel(Parcel &out) const;
        bool ReadFromParcel(Parcel &in);

    private:
        int32_t pointerId_ { 0 };
        int32_t downTime_ { 0 };
        bool pressed_ { false };
        int32_t globalX_ { 0 };
        int32_t globalY_ { 0 };
        int32_t localX_ { 0 };
        int32_t localY_ { 0 };
        int32_t width_ { 0 };
        int32_t height_ { 0 };
        int32_t pressure_ { 0 };
        int32_t deviceId_ { 0 };
    };

public:
    virtual ~PointerEvent();
    static std::shared_ptr<PointerEvent> Create();
    // Get or set the action of pointer type input event
    int32_t GetPointerAction() const;
    void SetPointerAction(int32_t pointerAction);

    // Get or set the current Pointer of the pointer type input event
    int32_t GetPointerId() const;
    void SetPointerId(int32_t pointerId);

    // Get the PionterItem of the specified pointer id
    bool GetPointerItem(int32_t pointerId, PointerItem &pointerItem);

    // Add a PointerItem
    void AddPointerItem(PointerItem &pointerItem);
    void RemovePointerItem(int32_t pointerId);
    void UpdatePointerItem(int32_t pointerId, PointerItem &pointerItem);

    // Gets or sets whether the specified button on the pointing device is pressed
    std::set<int32_t> GetPressedButtons() const;
    bool IsButtonPressed(int buttonId) const;
    void SetButtonPressed(int buttonId);
    void DeleteReleaseButton(int buttonId);
    void ClearButtonPressed();

    // Get all Pointers in the current pointer event
    std::vector<int32_t> GetPointersIdList() const;

    // Get or set the source type of the current pointer event
    int32_t GetSourceType() const;
    void SetSourceType(int32_t sourceType);

    // Get or set the button id of the current pointer event
    int32_t GetButtonId() const;
    void SetButtonId(int32_t buttonId);

    double GetAxisValue(AxisType axis) const;
    void SetAxisValue(AxisType axis, double axisValue);
    bool HasAxis(AxisType axis) const;
    int32_t GetAxes() const;
    
    void SetPressedKeys(const std::vector<int32_t> pressedKeys);
    std::vector<int32_t> GetPressedKeys() const;
    
    bool IsValidCheckMouseFunc() const;
    bool IsValidCheckMouse() const;
    bool IsValidCheckTouchFunc() const;
    bool IsValidCheckTouch() const;
    bool IsValid() const;
public:
    static bool HasAxis(int32_t axes, AxisType axis);

public:
    bool WriteToParcel(Parcel &out) const;
    bool ReadFromParcel(Parcel &in);

protected:
    explicit PointerEvent(int32_t eventType);

private:
    int32_t pointerId_ { 0 };
    std::list<PointerItem> pointers_;
    std::set<int32_t> pressedButtons_;
    int32_t sourceType_ { 0 };
    int32_t pointerAction_ { 0 };
    int32_t buttonId_ { -1 };
    int32_t axes_ { 0 };
    std::array<double, AXIS_TYPE_MAX>   axisValues_ { };
    std::vector<int32_t> pressedKeys_;
};

inline bool PointerEvent::HasAxis(AxisType axis) const
{
    return HasAxis(axes_, axis);
}

inline int32_t PointerEvent::GetAxes() const
{
    return axes_;
}
}
} // namespace OHOS::MMI
#endif // POINTER_EVENT_H