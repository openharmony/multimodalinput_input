/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef MOUSE_EVENT_H
#define MOUSE_EVENT_H

#include <map>
#include "struct_multimodal.h"
#include "mmi_point.h"
#include "nocopyable.h"
#include "composite_event.h"

enum class MouseActionEnum: int32_t {
    /**
    * Indicates no mouse action.
    *
    * @since 1
    */
    MMNONE = 0,

    /**
    * Indicates that a mouse button is pressed.
    *
    * @since 1
    */
    PRESS = 1,

    /**
    * Indicates that a mouse button is released.
    *
    * @since 1
    */
    RELEASE = 2,

    /**
    * Indicates the movement of the cursor in a window or view when the
    * left mouse button is pressed.
    *
    * @since 1
    */
    MOVE = 3,

    /**
    * Indicates that a mouse button is not pressed while the cursor moves
    * into the window or view.
    *
    * @since 1
    */
    HOVER_ENTER = 4,

    /**
    * Indicates the movement of the cursor in a window or view when the
    * left mouse button is not pressed.
    *
    * @since 1
    */
    HOVER_MOVE = 5,

    /**
    * Indicates the exit of the cursor from a window or view when the
    * left mouse button is not pressed.
    *
    * @since 1
    */
    HOVER_EXIT = 6,

    /**
    * Indicates that no mouse button is pressed.
    *
    * @since 1
    */
    MMNONE_BUTTON = 7,
};

enum MouseButtonEnum {
    /**
    * Indicates that the left button on the mouse is pressed.
    *
    * @since 1
    */
    LEFT_BUTTON = 0x110,

    /**
    * Indicates that the right button on the mouse is pressed.
    *
    * @since 1
    */
    RIGHT_BUTTON = 0x111,

    /**
    * Indicates that the middle button on the mouse is pressed.
    *
    * @since 1
    */
    MIDDLE_BUTTON = 0x112,
    SIDE_BUTTON = 0x113,
    EXTRA_BUTTON = 0x114,

    /**
    * Indicates that the forward button on the mouse is pressed.
    *
    * @since 1
    */
    FORWARD_BUTTON = 0x115,

    /**
    * Indicates that the back button on the mouse is pressed.
    *
    * @since 1
    */
    BACK_BUTTON = 0x116,
    TASK_BUTTON = 0x117,
};

enum AxisEnum {
    /**
    * Indicates the movement of the mouse pointer or scroll wheel in the X axis.
    *
    * @since 1
    */
    AXIS_X = 0,
    /**
    * Indicates the movement of the mouse pointer or scroll wheel in the Y axis.
    *
    * @since 1
    */
    AXIS_Y = 1,
    /**
    * Indicates the movement of the mouse pointer or scroll wheel in the Z axis.
    *
    * @since 1
    */
    AXIS_Z = 2,
    AXIS_ORIENTATION = 3,
    AXIS_RX = 4,
    AXIS_RY = 5,
    AXIS_RZ = 6,
    AXIS_HAT_X = 7,
    AXIS_HAT_Y = 8,
    AXIS_LTRIGGER = 9,
    AXIS_THROTTLE = 10,
    AXIS_RUDDER = 11,
    AXIS_WHEEL = 12,
    AXIS_GAS = 13,
    AXIS_BRAKE = 14,
    AXIS_DISTANCE = 15,
    AXIS_TILT = 16,
    AXIS_TILT_X = 17,
    AXIS_TILT_Y = 18,
};

namespace OHOS {
/**
 * Reports mouse events.
 *
 * <p>A reported event can contain both mouse button state change and cursor
 * state change.
 *
 * @see CompositeEvent
 * @since 1
 */
class MouseEvent : public CompositeEvent {
public:
    MouseEvent() = default;
    DISALLOW_COPY_AND_MOVE(MouseEvent);
    virtual ~MouseEvent();
    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void Initialize(int32_t windowId, int32_t action, int32_t actionButton, int32_t pressedButtons,
                    const MmiPoint& mmiPoint, float xOffset, float yOffset, float cursorDelta, float scrollingDelta,
                    int32_t highLevelEvent, const std::string& uuid, int32_t sourceType, int32_t occurredTime,
                    const std::string& deviceId, int32_t inputDeviceId,  bool isHighLevelEvent,
                    uint16_t deviceUdevTags, const MMI::EventJoyStickAxis& eventJoyStickInfo);
    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void Initialize(MouseEvent& mouseEvent);

    /**
    * Obtains the mouse action.
    *
    * @return Returns the mouse action. The return value can be
    * {@link #PRESS},{@link #RELEASE}, {@link #MOVE},{@link #HOVER_ENTER},
    *  {@link #HOVER_MOVE},or {@link #HOVER_EXIT}.
    * @since 1
    */
    virtual int32_t GetAction() const;

    /**
     * Obtains the mouse button whose status has changed.
     *
     * @return Returns the mouse button whose status has changed. The return
     * value can be {@link #MMNONE_BUTTON},{@link #LEFT_BUTTON},
     * {@link #RIGHT_BUTTON}, {@link #MIDDLE_BUTTON}, {@link #BACK_BUTTON},or
     * {@link #FORWARD_BUTTON}.Note that {@link #MMNONE_BUTTON} indicates that
     * there is no mouse button whose status has changed.
     * @since 1
     */
    virtual int32_t GetActionButton() const;

    /**
     * Obtains all mouse buttons in the pressed state.
     *
     * @return Returns all mouse buttons in the pressed state. The return
     * value can be {@link #MMNONE_BUTTON},or the result of logical OR
     * operations among{@link #LEFT_BUTTON}, {@link #RIGHT_BUTTON},
     * {@link #MIDDLE_BUTTON},{@link #BACK_BUTTON}, and
     * {@link #FORWARD_BUTTON}. Note that{@link #MMNONE_BUTTON} indicates
     * that there isno mouse button in the pressed state.
     * @see #MMNONE_BUTTON
     * @see #LEFT_BUTTON
     * @see #RIGHT_BUTTON
     * @see #MIDDLE_BUTTON
     * @see #FORWARD_BUTTON
     * @since 1
     */
    virtual int32_t GetPressedButtons() const;

    /**
     * Obtains the current position of the mouse pointer.
     *
     * @return Returns the current position of the mouse pointer.
     * @since 1
     */
    virtual MmiPoint GetCursor() const;

    /**
    * Sets the offset position relative to the screen.
    *
    * @param offsetX Indicates the offset relative to the x on the upper left
    * corner of the screen.
    * @param offsetY Indicates the offset relative to the y on the upper left
    * corner of the screen.
    * @since 1
    */
    virtual void SetCursorOffset(float offsetX, float offsetY);

    virtual float GetXOffset() const;

    virtual float GetYOffset() const;

    /**
     * Obtains the movement of the mouse pointer in the given direction since
     * last call.
     * @param axis Indicates the movement direction of the mouse pointer.
     * The value can be {@link #AXIS_X},{@link #AXIS_Y}, or {@link #AXIS_Z}.
     * @return Returns the movement of the mouse pointer in the given
     * direction since last call.
     * @since 1
     */
    virtual float GetCursorDelta(int32_t axis) const;

    /**
     * Obtains the movement of the scroll wheel in the given direction since
     * last call.
     * @param axis Indicates the movement direction of the scroll wheel. The
     * value can be {@link #AXIS_X},{@link #AXIS_Y}, or {@link #AXIS_Z}.
     * @return Returns the movement of the scroll wheel in the given
     * direction since last call.
     * @since 1
     */
    virtual float GetScrollingDelta(int32_t axis) const;

    virtual float GetAxisValue(int32_t axis) const;

private:
    int32_t mAction_ = 0;
    int32_t mActionButton_ = 0;
    int32_t mPressedButtons_ = 0;
    MmiPoint mMmiPoint_;
    float mXOffset_ = 0.f;
    float mYOffset_ = 0.f;
    float mCursorDelta_ = 0.f;
    float mScrollingDelta_ = 0.f;
    std::map<int32_t, float> mapDeviceAxis_ = {};
};
}
#endif // MOUSE_EVENT_H