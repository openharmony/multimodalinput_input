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

#ifndef STYLUS_EVENT_H
#define STYLUS_EVENT_H

#include "manipulation_event.h"

namespace OHOS {
enum StylusEnum {
    /**
    * Indicates that the stylus does not perform any operation on the screen.
    *
    * @since 1
    */
    NONE = 0,

    /**
    * Indicates that the stylus presses on a button.
    *
    * @since 1
    */
    BUTTON_PRESS = 1,

    /**
    * Indicates that the stylus lifts up a button.
    *
    * @since 1
    */
    BUTTON_RELEASE = 2,

    /**
    * Indicates that the stylus presses on the screen.
    *
    * @since 1
    */
    STYLUS_DOWN = 3,

    /**
    * Indicates that the stylus slides on the screen.
    *
    * @since 1
    */
    STYLUS_MOVE = 4,

    /**
    * Indicates that the stylus lifts up from the screen.
    *
    * @since 1
    */
    STYLUS_UP = 5,

    /**
    * Indicates no button state change in the stylus event.
    *
    * @since 1
    */
    NONE_BUTTON = 6,
    /**
    * Indicates button state change in the stylus event.
    *
    * @since 1
    */
    FIRST_BUTTON = 1
};

enum StylusButton {
    BUTTON_STYLUS = 0,
    BUTTON_STYLUS2 = 1
};

/**
 * Reports stylus events.
 *
 * <p>The reported event contains information such as button state change
 * and stylus action(press, slide, or lift). Currently, one event supports
 * only one stylus action.
 * @hide
 * @see ManipulationEvent
 * @since 1
 */
class StylusEvent : public ManipulationEvent {
public:
    virtual ~StylusEvent();
    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void Initialize(int32_t windowId, int32_t action, int32_t buttons, int32_t startTime, int32_t operationState,
                    int32_t pointerCount, fingerInfos fingersInfos[], int32_t highLevelEvent, const std::string& uuid,
                    int32_t sourceType, int32_t occurredTime, const std::string& deviceId, int32_t inputDeviceId,
                    bool isHighLevelEvent, uint16_t deviceUdevTags = 0);

    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void Initialize(StylusEvent& stylusEvent);

    /**
     * Obtains the stylus action.
     *
     * @return Returns the stylus action. The return value can be
     * {@link #BUTTON_PRESS},{@link #BUTTON_RELEASE}, {@link #STYLUS_DOWN},
     * {@link #STYLUS_MOVE}, or {@link #STYLUS_MOVE}.
     * @since 1
     */
    virtual int32_t GetAction() const;

    /**
     * Obtains the button state change of the stylus.
     *
     * @return Returns the button state change of the stylus. The return
     * value can be{@link #FIRST_BUTTON} or {@link #NONE_BUTTON}.
     * @since 1
     */
    virtual int32_t GetButtons() const;

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

private:
    int32_t stylusButtonMapping(int32_t stylusButton) const;
private:
    int32_t action_ = 0;
    int32_t buttons_ = 0;
    int32_t actionButtons_ = 0;
};
} // namespace OHOS
#endif // STYLUS_EVENT_H