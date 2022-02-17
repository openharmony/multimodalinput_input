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

#ifndef AXIS_EVENT_H
#define AXIS_EVENT_H

#include "input_event.h"

namespace OHOS {
namespace MMI {
class AxisEvent : public InputEvent {
public:
    static const int32_t AXIS_ACTION_UNKNOWN = 0;
    static const int32_t AXIS_ACTION_CANCEL = 1;

    static const int32_t AXIS_ACTION_START = 2;
    static const int32_t AXIS_ACTION_UPDATE = 3;
    static const int32_t AXIS_ACTION_END = 4;

    static const int32_t AXIS_TYPE_UNKNOWN = 0;

public:
    static std::shared_ptr<AxisEvent> from(std::shared_ptr<InputEvent> inputEvent);
    static std::shared_ptr<AxisEvent> Create();

public:
    virtual ~AxisEvent();

    int32_t GetAxisAction();
    void SetAxisAction(int32_t axisAction);

    int32_t GetAxisType() const;
    void SetAxisType(int32_t axisType);

    int32_t GetAxisValue() const;
    void SetAxisValue(int32_t axisValue);

protected:
    explicit AxisEvent(int32_t eventType);
};
} // namespace MMI
} // namespace OHOS
#endif // AXIS_EVENT_H