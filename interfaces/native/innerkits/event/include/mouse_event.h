/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "mmi_point.h"
#include "composite_event.h"

namespace OHOS {
struct MouseProperty {
    int action;
    int actionButton;
    int pressedButtons;
    MmiPoint mmiPoint;
    float xOffset;
    float yOffset;
    float cursorDelta;
    float scrollingDelta;
    uint32_t scrollType;
};

class MouseEvent : public CompositeEvent {
public:
    void Initialize(MultimodalProperty &multiProperty, MouseProperty &mouseProperty);

    virtual int GetAction();

    virtual int GetActionButton();

    virtual int GetPressedButtons();

    virtual MmiPoint GetCursor();

    virtual void SetCursorOffset(float offsetX, float offsetY);

    virtual float GetCursorDelta(int axis);

    virtual float GetScrollingDelta(int axis);

    bool Marshalling(Parcel &parcel) const override;
    static MouseEvent *Unmarshalling(Parcel &parcel);

    static constexpr int NONE = 0;

    static constexpr int PRESS = 1;

    static constexpr int RELEASE = 2;

    static constexpr int MOVE = 3;

    static constexpr int HOVER_ENTER = 4;

    static constexpr int HOVER_MOVE = 5;

    static constexpr int HOVER_EXIT = 6;

    static constexpr int SCROLL = 7;

    static constexpr int NONE_BUTTON = 0;

    static constexpr int LEFT_BUTTON = 1 << 0;

    static constexpr int RIGHT_BUTTON = 1 << 1;

    static constexpr int MIDDLE_BUTTON = 1 << 2;

    static constexpr int BACK_BUTTON = 1 << 3;

    static constexpr int FORWARD_BUTTON = 1 << 4;

    static constexpr int AXIS_X = 0;

    static constexpr int AXIS_Y = 1;

    static constexpr int AXIS_Z = 2;

    static constexpr int VERTICAL_SCROLL = 0;

    static constexpr int HORIZONTAL_SCROLL = 1;
protected:
    MouseProperty mouseProperty_;
};
}  // namespace OHOS
#endif  // MOUSE_EVENT_H
