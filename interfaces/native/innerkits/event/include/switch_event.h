/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SWITCH_EVENT_H
#define SWITCH_EVENT_H

#include "nocopyable.h"

#include "input_event.h"

namespace OHOS {
namespace MMI {
class SwitchEvent : public InputEvent {
public:
    static constexpr int32_t SWITCH_ON = 0;
    static constexpr int32_t SWITCH_OFF = 1;

    enum SwitchType {
        DEFAULT = 0,
        LID,
        TABLET,
        PRIVACY
    };

public:
    int32_t GetSwitchType() const
    {
        return switchType_;
    }
    
    int32_t GetSwitchValue() const
    {
        return switchValue_;
    }

    int32_t GetSwitchMask() const
    {
        return updateSwitchMask_;
    }

    void SetSwitchType(int32_t type)
    {
        switchType_ = type;
    }

    void SetSwitchValue(int32_t value)
    {
        switchValue_ = value;
    }

    void SetSwitchMask(int32_t switchMask)
    {
        updateSwitchMask_ = switchMask;
    }

    explicit SwitchEvent(int32_t value)
        : InputEvent(value),
        switchValue_(value),
        updateSwitchMask_(0),
        switchType_(SwitchType::DEFAULT) {}
private:
        int32_t switchValue_ { 0 };
        int32_t updateSwitchMask_ { 0 };
        int32_t switchType_ { SwitchType::DEFAULT };
};
} // namespace MMI
} // namespace OHOS
#endif // SWITCH_EVENT_H