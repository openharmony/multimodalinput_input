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
    /**
     * Indicates an unknown pointer action. It is usually used as initial value.
     * 
     * @since 8
     */
    static const int32_t POINTER_ACTION_UNKNOWN = 0;

    /**
     * Indicates a pointer action that has been canceled.
     * 
     * @since 8
     */
    static const int32_t POINTER_ACTION_CANCEL = 1;

    /**
     * Indicates a pointer action representing that a funger is pressed on a touchscreen or touchpad.
     * 
     * @since 8
     */
    static const int32_t POINTER_ACTION_DOWN = 2;

    /**
     * Indicates a pointer action representing that a funger moves on a touchscreen or touchpad or a mouse pointer moves.
     * 
     * @since 8
     */
    static const int32_t POINTER_ACTION_MOVE = 3;

    /**
     * Indicates a pointer action representing that a funger leaves  the touchscreen or touchpad.
     * 
     * @since 8
     */
    static const int32_t POINTER_ACTION_UP = 4;

    /**
     * Indicates the start action of the axis event related to the pointer.
     * 
     * @since 8
     */
    static const int32_t POINTER_ACTION_AXIS_BEGIN = 5;

    /**
     * Indicates the update action of the axis event related to the pointer.
     * 
     * @since 8
     */
    static const int32_t POINTER_ACTION_AXIS_UPDATE = 6;

    /**
     * Indicates the end action of the axis event related to the pointer.
     * 
     * @since 8
     */
    static const int32_t POINTER_ACTION_AXIS_END = 7;

    /**
     * Indicates a pointer action representing that a button is pressed.
     * 
     * @since 8
     */
    static const int32_t POINTER_ACTION_BUTTON_DOWN = 8;

    /**
     * Indicates a pointer action representing that a button is released.
     * 
     * @since 8
     */
    static const int32_t POINTER_ACTION_BUTTON_UP = 9;

    enum AxisType {
        /**
         * Indicates an unknown axis type. It is generally used as the initial value.
         * 
         * @since 8
         */
        AXIS_TYPE_UNKNOWN,

        /**
         * Indicates the vertical scroll axis. When you scrall the mouse wheel or make certain gestures on the touchpad, the status of the vertical scroll axis changes.
         * 
         * @since 8
         */
        AXIS_TYPE_SCROLL_VERTICAL,

        /**
         * Indicates the horizontal scroll axis. When you scrall the mouse wheel or make certain gestures on the touchpad, the status of the horizontal scroll axis changes.
         * 
         * @since 8
         */
        AXIS_TYPE_SCROLL_HORIZONTAL,

        /**
         * Indicates the pinch axis, which is used to describe a pinch gesture on the touchscreen or touchpad.
         * 
         * @since 8
         */
        AXIS_TYPE_PINCH,

        /**
         * Indicates the maximum number of defined axis types.
         * 
         * @since 8
         */
        AXIS_TYPE_MAX
    };

    /**
     * Indicates an unknown input source type. It is usually used as the initial value.
     * 
     * @since 8
     */
    static const int32_t SOURCE_TYPE_UNKNOWN = 0;

    /**
     * Indicates that the input source generates events similar to mouse cursor movement, button press and release, and wheel scrolling.
     * 
     * @since 8
     */
    static const int32_t SOURCE_TYPE_MOUSE = 1;

    /**
     * Indicates that the input source generates a touchscreen multi-touch event.
     * 
     * @since 8
     */
    static const int32_t SOURCE_TYPE_TOUCHSCREEN = 2;

    /**
     * Indicates that the input source generates a touchpad multi-touch event.
     * 
     * @since 8
     */
    static const int32_t SOURCE_TYPE_TOUCHPAD = 3;

    /**
     * Indicates an invalid button ID.
     * 
     * @since 8
     */
    static const int32_t BUTTON_NONE = -1;

    /**
     * Indicates the left button on a mouse.
     * 
     * @since 8
     */
    static const int32_t MOUSE_BUTTON_LEFT = 0;

    /**
     * Indicates the right button on a mouse.
     * 
     * @since 8
     */
    static const int32_t MOUSE_BUTTON_RIGHT = 1;

    /**
     * Indicates the middle button on a mouse.
     * 
     * @since 8
     */
    static const int32_t MOUSE_BUTTON_MIDDLE = 2;

public:
    static std::shared_ptr<PointerEvent> from(std::shared_ptr<InputEvent> inputEvent);

public:
    class PointerItem {
    public:
        PointerItem();
        ~PointerItem();

    public:
        /**
         * @brief Obtains the ID of the pointer in this event.
         * @return Returns the pointer ID.
         * @since 8
         */
        int32_t GetPointerId() const;

        /**
         * @brief Sets the ID of the pointer in this event.
         * @param pointerId Indicates the pointer ID to set.
         * @return void
         * @since 8
         */
        void SetPointerId(int32_t pointerId);

        /**
         * @brief Obtains the time when the pointer is pressed.
         * @return Returns the time.
         * @since 8
         */
        int32_t GetDownTime() const;

        /**
         * @brief Sets the time when the pointer is pressed.
         * @param downTime Indicates the time to set.
         * @return void
         * @since 8
         */
        void SetDownTime(int32_t downTime);

        /**
         * @brief Checks whether the pointer is pressed.
         * @return Returns <b>true</b> if the pointer is pressed; returns <b>false</b> otherwise.
         * @since 8
         */
        bool IsPressed() const;

        /**
         * @brief Sets whether to enable the pressed state for the pointer.
         * @param pressed Specifies whether to set the pressed state for the pointer. The value <b>true</b> means to set the pressed state for the pointer, and the <b>false</b> means the opposite.
         * @return void
         * @since 8
         */
        void SetPressed(bool pressed);

        /**
         * @brief Obtains the x coordinate relative to the upper left corner of the screen.
         * For a touchpad input event, the value is the absolute x coordinate on the touchpad. For other pointer input events, the value is the x coordinate on the target screen.
         * @return Returns the x coordinate.
         * @since 8
         */
        int32_t GetGlobalX() const;

        /**
         * @brief Sets the x coordinate relative to the upper left corner of the screen.
         * @param globalX Indicates the x coordinate to set.
         * @return void
         * @since 8
         */
        void SetGlobalX(int32_t globalX);

        /**
         * @brief Obtains the y coordinate relative to the upper left corner of the screen.
         * For a touchpad input event, the value is the absolute y coordinate on the touchpad. For other pointer input events, the value is the y coordinate on the target screen.
         * @return Returns the y coordinate.
         * @since 8
         */
        int32_t GetGlobalY() const;

        /**
         * @brief Sets the y coordinate relative to the upper left corner of the screen.
         * @param globalY Indicates the y coordinate to set.
         * @return void
         * @since 8
         */
        void SetGlobalY(int32_t globalY);

        /**
         * @brief Obtains the x coordinate of the active window.
         * @return Returns the x coordinate.
         * @since 8
         */
        int32_t GetLocalX() const;

        /**
         * @brief Sets the x coordinate of the active window.
         * @param x Indicates the x coordinate to set.
         * @return void
         * @since 8
         */
        void SetLocalX(int32_t x);

        /**
         * @brief Obtains the y coordinate of the active window.
         * @return Returns the y coordinate.
         * @since 8
         */
        int32_t GetLocalY() const;

        /**
         * @brief Sets the y coordinate of the active window.
         * @param y Indicates the y coordinate to set.
         * @return void
         * @since 8
         */
        void SetLocalY(int32_t y);

        /**
         * @brief Obtains the width of the pressed area.
         * @return Returns the width.
         * @since 8
         */
        int32_t GetWidth() const;

        /**
         * @brief Sets the width of the pressed area.
         * @param width Indicates the width to set.
         * @return void
         * @since 8
         */
        void SetWidth(int32_t width);

        /**
         * @brief Obtains the height of the pressed area.
         * @return Returns the height.
         * @since 8
         */
        int32_t GetHeight() const;

        /**
         * @brief Sets the height of the pressed area.
         * @param height Indicates the height to set.
         * @return void
         * @since 8
         */
        void SetHeight(int32_t height);

        /**
         * @brief Obtains the pressure in this event.
         * @return Returns the pressure.
         * @since 8
         */
        int32_t GetPressure() const;

        /**
         * @brief Sets the pressure for this event.
         * @param pressure Indicates the pressure to set.
         * @return void
         * @since 8
         */
        void SetPressure(int32_t pressure);

        /**
         * @brief Obtains the ID of the current device.
         * @return Returns the device ID.
         * @since 8
         */
        int32_t GetDeviceId() const;

        /**
         * @brief Sets the ID for the current device.
         * @param deviceId Indicates the device ID to set.
         * @return void
         * @since 8
         */
        void SetDeviceId(int32_t deviceId);
    public:
        /**
         * @brief Writes data to a <b>Parcel</b> obejct.
         * @param out Indicates the object into which data will be written.
         * @return Returns <b>true</b> if the data is successfully written; returns <b>false</b> otherwise.
         * @since 8
         */
        bool WriteToParcel(Parcel &out) const;

        /**
         * @brief Reads data from a <b>Parcel</b> obejct.
         * @param in Indicates the object from which data will be read.
         * @return Returns <b>true</b> if the data is successfully read; returns <b>false</b> otherwise.
         * @since 8
         */
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
    PointerEvent(const PointerEvent& other);
    PointerEvent(PointerEvent&& other) = delete;
    virtual ~PointerEvent();
    virtual PointerEvent& operator=(const PointerEvent& other) = delete;
    virtual PointerEvent& operator=(PointerEvent&& other) = delete;

    static std::shared_ptr<PointerEvent> Create();

    /**
     * @brief Obtains the pointer action in this event.
     * @return Returns the pointer action.
     * @since 8
     */
    int32_t GetPointerAction() const;

    /**
     * @brief Sets a pointer action for this event.
     * @param pointerAction Indicates the pointer action to set.
     * @return void
     * @since 8
     */
    void SetPointerAction(int32_t pointerAction);
    const char* DumpPointerAction() const;

    void SetSkipInspection(bool skipInspection);
    bool NeedSkipInspection();
    /**
     * @brief Obtains the pointer ID in this event.
     * @return Returns the pointer ID.
     * @since 8
     */
    int32_t GetPointerId() const;

    /**
     * @brief Sets an ID for the pointer in this event.
     * @param pointerId Indicates the pointer ID to set.
     * @return void
     * @since 8
     */
    void SetPointerId(int32_t pointerId);

    /**
     * @brief Obtains the pointer item of a specified pointer ID.
     * @param pointerId Indicates the pointer ID.
     * @param pointerItem Indicates the item used to receive the data of the pointer.
     * @return Returns <b>true</b> if the data of the pointer with the specified ID exists; returns <b>false</b> otherwise.
     * @since 8
     */
    bool GetPointerItem(int32_t pointerId, PointerItem &pointerItem);

    /**
     * @brief Adds a pointer item.
     * @param pointerItem Indicates the pointer item to add.
     * @return void
     * @since 8
     */
    void AddPointerItem(PointerItem &pointerItem);

    /**
     * @brief Removes a pointer item based on the pointer ID.
     * @param pointerId Indicates the ID of the pointer from which the pointer item is to be removed.
     * @return void
     * @since 8
     */
    void RemovePointerItem(int32_t pointerId);

    /**
     * @brief Updates a pointer item based on the pointer ID.
     * @param pointerId Indicates the ID of the pointer from which the pointer item is to be updated.
     * @param pointerItem Indicates the pointer item to update.
     * @return void
     * @since 8
     */
    void UpdatePointerItem(int32_t pointerId, PointerItem &pointerItem);

    /**
     * @brief Obtains the set of pressed buttons.
     * @return Returns the pressed buttons.
     * @since 8
     */
    std::set<int32_t> GetPressedButtons() const;

    /**
     * @brief Checks whether a specified button is being pressed.
     * @param buttonId Indicates the button ID.
     * @return Returns <b>true</b> if the button is being pressed; returns <b>false</b> otherwise.
     * @since 8
     */
    bool IsButtonPressed(int buttonId) const;

    /**
     * @brief Sets the pressed state for a button.
     * @param buttonId Indicates the button ID of the button to be set in the pressed state.
     * @return void
     * @since 8
     */
    void SetButtonPressed(int buttonId);

    /**
     * @brief Deletes a released button.
     * @param buttonId Indicates the button ID of the button.
     * @return void
     * @since 8
     */
    void DeleteReleaseButton(int buttonId);

    /**
     * @brief Clears the button in the pressed state.
     * @return void
     * @since 8
     */
    void ClearButtonPressed();

    /**
     * @brief Obtains all pointers in this event.
     * @return Returns all the pointer IDs.
     * @since 8
     */
    std::vector<int32_t> GetPointersIdList() const;

    /**
     * @brief Obtains the source type of this event.
     * @return Returns the source type.
     * @since 8
     */
    int32_t GetSourceType() const;

    /**
     * @brief Sets the source type for this event.
     * @param sourceType Indicates the source type to set.
     * @return void
     * @since 8
     */
    void SetSourceType(int32_t sourceType);
    const char* DumpSourceType() const;

    /**
     * @brief Obtains the button ID in this event.
     * @return Returns the button ID.
     * @since 8
     */
    int32_t GetButtonId() const;

    /**
     * @brief Sets the button ID for this event.
     * @param buttonId Indicates the button ID to set.
     * @return void
     * @since 8
     */
    void SetButtonId(int32_t buttonId);

    /**
     * @brief Obtains the axis value.
     * @param axis Indicates the axis type.
     * @return Returns the axis value.
     * @since 8
     */
    double GetAxisValue(AxisType axis) const;

    /**
     * @brief Sets the axis value.
     * @param axis Indicates the axis type.
     * @param axisValue Indicates the axis value to set.
     * @return void
     * @since 8
     */
    void SetAxisValue(AxisType axis, double axisValue);

    /**
     * @brief Checks whether this event contains a specified axis type.
     * @param axis Indicates the axis type.
     * @return Returns <b>true</b> if the event contains the specified axis type; returns <b>false</b> otherwise.
     * @since 8
     */
    bool HasAxis(AxisType axis) const;

    /**
     * @brief Obtains all axis of this event.
     * @return Returns all the axis, Each bit indicates an axis.
     * @since 8
     */
    int32_t GetAxes() const;

    /**
     * @brief Set the front keys in the key combination.
     * @param pressedKeys Indicates the front keys to set.
     * @return void.
     * @since 8
     */
    void SetPressedKeys(const std::vector<int32_t> pressedKeys);

    /**
     * @brief Obtains the set of pressed keys.
     * @return Returns the pressed keys.
     * @since 8
     */
    std::vector<int32_t> GetPressedKeys() const;

    /**
     * @brief Checks whether this input event is valid.
     * @return Returns <b>true</b> if the input event is valid; returns <b>false</b> otherwise.
     * @since 8
     */
    bool IsValid() const;
public:
    /**
     * @brief Checks whether the axes set represented by <b>axes</b> contains a specified type of axis.
     * @param axes Indicates the set of axes. Each bit indicates an axis.
     * @param axis Indicates the type of the axis to check.
     * @return Returns <b>true</b> if the axes set contains the specified axis type; returns <b>false</b> otherwise.
     * @since 8
     */
    static bool HasAxis(int32_t axes, AxisType axis);

public:
    /**
     * @brief Writes data to a <b>Parcel</b> obejct.
     * @param out Indicates the object into which data will be written.
     * @return Returns <b>true</b> if the data is successfully written; returns <b>false</b> otherwise.
     * @since 8
     */
    bool WriteToParcel(Parcel &out) const;

    /**
     * @brief Reads data from a <b>Parcel</b> obejct.
     * @param in Indicates the object from which data will be read.
     * @return Returns <b>true</b> if the data is successfully read; returns <b>false</b> otherwise.
     * @since 8
     */
    bool ReadFromParcel(Parcel &in);

protected:
    explicit PointerEvent(int32_t eventType);

private:
    bool IsValidCheckMouseFunc() const;
    bool IsValidCheckMouse() const;
    bool IsValidCheckTouchFunc() const;
    bool IsValidCheckTouch() const;

private:
    bool skipInspection_ { false };
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
} // namespace MMI
} // namespace OHOS
#endif // POINTER_EVENT_H