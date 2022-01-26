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
#ifndef OHOS_MANIPULATION_EVENTS_H
#define OHOS_MANIPULATION_EVENTS_H

#include "mmi_point.h"
#include "multimodal_event.h"

namespace OHOS {
enum ManipulationEnum {
    /**
    * Indicates an invalid action.
    *
    * @since 1
    */
    PHASE_NONE = 0,

    /**
    * Indicates that the action has started.
    *
    * @since 1
    */
    PHASE_START = 1,

    /**
    * Indicates that the action is in process.
    *
    * @since 1
    */
    PHASE_MOVE = 2,

    /**
    * Indicates that the action has ended.
    *
    * @since 1
    */
    PHASE_COMPLETED = 3,

    /**
    * Indicates that the action has been canceled. An action is considered
    *  ended after being canceled.
    *
    * @since 1
    */
    PHASE_CANCEL = 4
};

const int32_t FINGER_NUM = 10;

struct fingerInfos {
    int32_t mPointerId;
    float mTouchArea;
    float mTouchPressure;
    MmiPoint mMp;
};

class ManipulationEvent : public MMI::MultimodalEvent {
public:
    virtual ~ManipulationEvent();
    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void Initialize(int32_t windowId, int32_t startTime, int32_t operationState, int32_t pointerCount,
                    fingerInfos fingersInfos[], int32_t highLevelEvent, const std::string& uuid, int32_t sourceType,
                    uint64_t occurredTime, const std::string& deviceId, int32_t inputDeviceId,  bool isHighLevelEvent,
                    uint16_t deviceUdevTags = 0);
    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void Initialize(ManipulationEvent& manipulationEvent);

    /**
    * Obtains the time (in ms) of the operation start phase.
    *
    * @return Returns the time (in ms) of the operation start phase.
    * @since 1
    */
    virtual int32_t GetStartTime() const;

    /**
     * Obtains the operation phase of the event.
     *
     * <p>The operation phase can be {@link #PHASE_NONE}, {@link #PHASE_START},
     *  {@link #PHASE_MOVE},{@link #PHASE_COMPLETED}, or {@link #PHASE_CANCEL}.
     * <p>
     *
     * @return Returns the operation phase of the event. The return value can be
     * {@link #PHASE_NONE},{@link #PHASE_START}, {@link #PHASE_MOVE},
     * {@link #PHASE_COMPLETED}, or {@link #PHASE_CANCEL}.
     * @since 1
     */
    virtual int32_t GetPhase() const;

    /**
    * Obtains the x and y coordinates of a pointer index relative to the offset
    * position during touch control or trajectory tracking in an event.
    *
    * @param index Indicates the pointer index mapping to the pointer action in
    * the event. The value ranges from 0 to {@link #getPointerCount()}-1. For the
    * mouse and stylus, only a single pointer action is supported. When the
    * location information is obtained, the pointer index is set to {@code 0}.
    * @return Returns the x and y coordinates of the pointer index. If a control's
    * position has been specified, the x and y coordinates relative to the control
    * are returned. If a control's position has not been specified, the x and y
    * coordinates relative to the screen are returned.
    *
    * @since 1
    */
    virtual MmiPoint GetPointerPosition(int32_t index) const;

    /**
     * Sets the offset position relative to the screen.
     *
     * @param offsetX Indicates the offset relative to the x on the upper left
     * corner of the screen.
     * @param offsetY Indicates the offset relative to the y on the upper left
     * corner of the screen.
     * @since 1
     */
    virtual void SetScreenOffset(float offsetX, float offsetY);

    /**
     * Obtains the x and y coordinates of a pointer index relative to the screen
     * coordinate origin during touch control or trajectory tracking in an event.
     *
     * @param index Indicates the pointer index mapping to the pointer ID in
     * the event. The value ranges from 0 to {@link #getPointerCount()}-1. For
     * the mouse and stylus, only a single pointer action is supported. When the
     * pointer ID is obtained, the pointer index is set to{@code 0}.
     * @return Returns the x and y coordinates of the pointer index relative
     * to the screen.
     * @since 1
     */
    virtual MmiPoint GetPointerScreenPosition(int32_t index) const;

    /**
     * Obtains the number of pointers for touch control or trajectory tracking
     * in an event.
     * @return Returns the number of pointers for touch control or trajectory
     * tracking in an event.
     * @since 1
     */
    virtual int32_t GetPointerCount() const;

    /**
     * Obtains the unique ID of a pointer in an event.
     *
     * @param index Indicates the pointer index mapping to the pointer ID in
     * the event. The value ranges from 0 to {@link #getPointerCount()}-1. For the
     * mouse and stylus, only a single pointer action is supported. When the pointer
     * ID is obtained, the pointer index is set to{@code 0}.
     *
     * @return Returns the unique ID of the pointer in the event.
     * @since 1
     */
    virtual int32_t GetPointerId(int32_t index) const;

    /**
     * Obtains the touch pressure of the finger with a specified index.
     *
     * <p>The touch pressure of a finger generally ranges from 0 to 1.0.
     * Depending on the calibration of the input device, a value greater
     * than 1 may be generated sometimes.
     *
     * @param index Indicates the index of the touch finger. The value
     * ranges from 0 to{@link #getPointerCount()}-1. The position of the touch
     * finger in the current event can be obtained based on its unique ID. For
     * the mouse and stylus action events, only a single pointer action is
     * supported.When the pressure information is obtained, the index is set to
     * {@code 0}.For the mouse action event, the touch pressure is {@code 1.0}
     * when the left button is pressed and is {@code 0} in other cases.
     * @return Returns the touch pressure.
     * @since 1
     */
    virtual float GetForce(int32_t index) const;

    /**
     * Obtains the touch radius of the finger with a specified index.
     *
     * <p>The touch radius indicates the area the finger touches on the screen.
     *
     * @param index Indicates the index of the touch finger. The value ranges
     * from 0 to{@link #getPointerCount()}-1. The position of the touch finger
     * in the current event can be obtained based on its unique ID. For the mouse
     * and stylus action events, only a single pointer action is supported. When
     * the screen size is obtained, the index is set to {@code0}. For the mouse
     * action event, the touch radius has a fixed value of {@code 0}.
     *
     * @return Returns the touch radius of the finger with a specified index.
     * @since 1
     */
    virtual float GetRadius(int32_t index) const;

    /**
    * get the member of fingerInfos.
    *
    * @return the point
    * @since 1
    */
    virtual const fingerInfos* GetFingersInfos() const;
private:
    int32_t mStartTime_ = 0;
    int32_t mOperationState_ = 0;
    int32_t mPointerCount_ = 0;
    fingerInfos mfingersInfos_[FINGER_NUM] = {};
};
}
#endif
