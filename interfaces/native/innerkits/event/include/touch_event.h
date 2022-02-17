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

#ifndef TOUCH_EVENT_H
#define TOUCH_EVENT_H
#include "manipulation_event.h"
#include "mouse_event.h"
#include "nocopyable.h"

namespace OHOS {
enum TouchEnum {
    /**
    * Indicates no touch activity.
    *
    * @since 1
    */
    MTNONE = 0,

    /**
    * Indicates that the first finger touches the screen. This indicates the
    * beginning of an interaction.
    *
    * @since 1
    */
    PRIMARY_POINT_DOWN = 1,

    /**
    * Indicates that the last finger lifts up from the screen. This indicates
    * the end of an interaction.
    *
    * @since 1
    */
    PRIMARY_POINT_UP = 2,

    /**
    * Indicates that the finger moves on the screen.
    *
    * @since 1
    */
    POINT_MOVE = 3,

    /**
    * Indicates that another finger touches on the screen when one finger or
    * more already touch on the screen.
    *
    * @since 1
    */
    OTHER_POINT_DOWN = 4,

    /**
    * Indicates some fingers lift up from the screen while some remain on
    * the screen.
    * @since 1
    */
    OTHER_POINT_UP = 5,

    /**
    * Indicates that the event is interrupted or canceled.
    *
    * @since 1
    */
    CANCEL = 6,

    /**
    * Indicates that the hover pointer enters a window or component.
    *
    * @since 1
    */
    HOVER_POINTER_ENTER = 7,

    /**
    * Indicates that the hover pointer moves in a window or component.
    *
    * @since 1
    */
    HOVER_POINTER_MOVE = 8,

    /**
    * Indicates that the hover pointer leaves a window or component.
    *
    * @since 1
    */
    HOVER_POINTER_EXIT = 9,

    /**
    * Key code of touch:
    *
    * @since 1
    */
    BUTTON_TOUCH = 2500,

    BUTTON_TOOL_PEN = 2501,
    BUTTON_TOOL_RUBBER = 2502,
    BUTTON_TOOL_BRUSH = 2503,
    BUTTON_TOOL_PENCIL = 2504,
    BUTTON_TOOL_AIRBRUSH = 2505,
    BUTTON_TOOL_FINGER = 2506,
    BUTTON_TOOL_MOUSE = 2507,
    BUTTON_TOOL_LENS = 2508,
    BUTTON_TOOL_DOUBLETAP = 2512,
    BUTTON_TOOL_TRIPLETAP = 2513,
    BUTTON_TOOL_QUADTAP = 2514,
    BUTTON_TOOL_QUINTTAP = 2515,
};

/**
 * Defines touch events and mapped standard events.
 *
 * <p>Information about a touch event includes the finger positions in
 * multi-finger touch, touch pressure, and touch radius. A standard event
 * is used to indicate the user intent. Its definition is irrelevant of the
 * input device type.The system maps a basic interaction event of another type
 * of input to a standard interaction event of a touch input.The mapping is as
 * follows:
 * <b>For basic mouse interaction events:</b>
 * <ul><li>Clicking and holding the left button on the mouse maps to touching
 * the screen with a finger at the pointer
 * position, as described in {@link #PRIMARY_POINT_DOWN}.</li>
 * <li>Clicking and holding the left button on the mouse and then moving the
 * pointer maps to touching the screen and
 * moving the finger on the screen, as described in {@link #POINT_MOVE}.</li>
 * <li>Releasing the left button on the mouse maps to lifting up a finger from
 * the screen, as described in
 * {@link #PRIMARY_POINT_UP}.</li></ul>
 * Note: The touchscreen does not have a hover pointer state. Therefore, if the
 * mouse is moved without any button
 * pressed, no interaction event is mapped to the touchscreen. To map to this
 * mouse input event, this class defines the
 * hover states for the pointer, such as {@link #HOVER_POINTER_ENTER},
 * {@link #HOVER_POINTER_MOVE}, and {@link #HOVER_POINTER_EXIT}.
 * <b>For basic stylus interaction events:</b>
 * <ul><li>Touching the screen with the stylus pen tip maps to touching the
 * screen with a finger, as described in {@link #PRIMARY_POINT_DOWN}.</li>
 * <li>Touching the screen with the stylus pen tip and then moving on the screen
 * maps to touching the screen and moving
 * the finger on the screen, as described in {@link #POINT_MOVE}.</li>
 * <li>Lifting up the stylus from the screen maps to lifting up a finger from
 * the screen, as described in{@link #PRIMARY_POINT_UP}.</li></ul>
 *
 * @see ManipulationEvent
 * @see MouseEvent
 * @see StylusEvent
 * @since 1
 */
class TouchEvent : public ManipulationEvent {
public:
    TouchEvent() = default;
    DISALLOW_COPY_AND_MOVE(TouchEvent);
    virtual ~TouchEvent();
    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void Initialize(int32_t windowId, int32_t action, int32_t index, float forcePrecision, float maxForce,
                    float tapCount, int32_t startTime, int32_t operationState, int32_t pointerCount,
                    fingerInfos fingersInfos[], int32_t highLevelEvent, const std::string& uuid, int32_t sourceType,
                    int32_t occurredTime, const std::string& deviceId, int32_t inputDeviceId,
                    bool isHighLevelEvent = false, bool isStandard = false, uint16_t deviceUdevTags = 0,
                    int32_t deviceEventType = 0);

    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void Initialize(TouchEvent& touchEvent);

    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void Initialize(int32_t windowId, MMI::MultimodalEventPtr deviceEvent, int32_t deviceEventType,
            int32_t action, int32_t index, float forcePrecision, float maxForce, float tapCount,
            int32_t startTime, int32_t operationState, int32_t pointerCount, fingerInfos fingersInfos[],
            bool isStandard);

    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void setMultimodalEvent(MMI::MultimodalEventPtr deviceEvent);

    /**
     * Obtains the current pointer action status.
     *
     * @return Returns the current pointer action status. The return value can be
     * {@link #PRIMARY_POINT_DOWN}, {@link #PRIMARY_POINT_UP}, {@link #POINT_MOVE},
     * {@link #OTHER_POINT_DOWN}, or {@link #OTHER_POINT_UP}.
     * @since 1
     */
    virtual int32_t GetAction() const;

    /**
     * Obtains the index of the pointer action.
     *
     * <p>This method obtains the pointer index of the pointer action, for example,
     * {@link #OTHER_POINT_DOWN} or {@link #OTHER_POINT_UP}. Based on the index,
     * you can obtain information such as the touch pressure and touch radius.
     *
     * @return Returns the index of the pointer action, which is in the range
     * from 0 to {@link ManipulationEvent#getPointerCount()}-1.
     * @since 1
     */
    virtual int32_t GetIndex() const;

    /**
     * Obtains the pressure precision of the device.
     *
     * @return Returns the pressure precision of the device.
     * @hide
     * @since 1
     */
    virtual float GetForcePrecision() const;

    /**
     * Obtains the maximum pressure supported by the device.
     *
     * @return Returns the maximum pressure supported by the device.
     * @hide
     * @since 1
     */
    virtual float GetMaxForce() const;

    /**
     * Obtains the number of touches within a certain period of time. It applies
     * only in the single-finger touch scenario.
     *
     * @return Returns the number of touches within a certain period of time.
     * @hide
     * @since 1
     */
    virtual float GetTapCount() const;

    /**
     *
     *
     * @return Returns the bool.
     * @hide
     * @since 1
     */
    virtual bool GetIsStandard() const;

    virtual const MMI::MultimodalEvent *GetMultimodalEvent() const;

    virtual int32_t GetPointToolType(int32_t index) const;

    virtual int32_t GetOriginEventType () const;

private:
    int32_t action_ = 0;
    int32_t index_ = 0;
    float forcePrecision_ = 0.f;
    float maxForce_ = 0.f;
    float tapCount_ = 0.f;
    bool isStandard_ = false;
    int32_t deviceEventType_ = 0;
    MMI::MultimodalEventPtr deviceEvent_ = nullptr;
};
} // namespace OHOS
#endif // TOUCH_EVENT_H