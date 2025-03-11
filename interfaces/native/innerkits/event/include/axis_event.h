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

#ifndef AXIS_EVENT_H
#define AXIS_EVENT_H

#include "input_event.h"

namespace OHOS {
namespace MMI {
class AxisEvent : public InputEvent {
public:
    /**
     * Unknown action for the axis input event. It is usually used as initial value.
     *
     * @since 9
     */
    static constexpr int32_t AXIS_ACTION_UNKNOWN = 0;

    /**
     * Cancel action for the axis input event.
     *
     * @since 9
     */
    static constexpr int32_t AXIS_ACTION_CANCEL = 1;

    /**
     * Start action for the axis input event.
     *
     * @since 9
     */
    static constexpr int32_t AXIS_ACTION_START = 2;

    /**
     * Update action for the axis input event.
     *
     * @since 9
     */
    static constexpr int32_t AXIS_ACTION_UPDATE = 3;

    /**
     * End action for the axis input event.
     *
     * @since 9
     */
    static constexpr int32_t AXIS_ACTION_END = 4;

    /**
     * Unknown axis type. It is the initial value of axis type.
     *
     * @since 9
     */
    static constexpr int32_t AXIS_TYPE_UNKNOWN = 0;

public:
    static std::shared_ptr<AxisEvent> from(std::shared_ptr<InputEvent> inputEvent);
    static std::shared_ptr<AxisEvent> Create();

public:
    DISALLOW_COPY_AND_MOVE(AxisEvent);
    virtual ~AxisEvent();

    /**
     * @brief Obtains the action for the axis input event.
     * @return Returns the action for the axis input event.
     * @since 9
     */
    int32_t GetAxisAction();

    /**
     * @brief Sets the action for the axis input event.
     * @param axisAction Indicates the action for the axis input event.
     * @return void
     * @since 9
     */
    void SetAxisAction(int32_t axisAction);

    /**
     * @brief Obtains the type of the axis input event.
     * @return Returns the type of the axis input event.
     * @since 9
     */
    int32_t GetAxisType() const;

    /**
     * @brief Sets the type of the axis input event.
     * @param axisType Indicates the type of the axis input event.
     * @return void
     * @since 9
     */
    void SetAxisType(int32_t axisType);

    /**
     * @brief Obtains the value of the axis input event.
     * @return Returns the value of the axis input event.
     * @since 9
     */
    int32_t GetAxisValue() const;

    /**
     * @brief Sets the value of the axis input event.
     * @param axisValue Value of the axis input event.
     * @return void
     * @since 9
     */
    void SetAxisValue(int32_t axisValue);

    /**
     * @brief Converts a Axis event action into a short string.
     * @param Indicates the Axis event action.
     * @return Returns the string converted from the Axis action.
     * @since 12
    */
    static std::string_view ActionToShortStr(int32_t action);
protected:
    /**
     * @brief Constructs an input event object by using the specified input event type. Generally, this method
     * is used to construct a base class object when constructing a derived class object.
     * @since 9
     */
    explicit AxisEvent(int32_t eventType);

private:
    int32_t axisAction_ { 0 };
    int32_t axisType_ { 0 };
    int32_t axisValue_ { 0 };
};
} // namespace MMI
} // namespace OHOS
#endif // AXIS_EVENT_H