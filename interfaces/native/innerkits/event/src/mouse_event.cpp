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

#include "mouse_event.h"
namespace OHOS {
void MouseEvent::Initialize(MultimodalProperty &multiProperty, MouseProperty &mouseProperty)
{
    MultimodalEvent::Initialize(multiProperty);
    mouseProperty_.action = mouseProperty.action;
    mouseProperty_.actionButton = mouseProperty.actionButton;
    mouseProperty_.pressedButtons = mouseProperty.pressedButtons;
    mouseProperty_.mmiPoint = mouseProperty.mmiPoint;
    mouseProperty_.xOffset = mouseProperty.xOffset;
    mouseProperty_.yOffset = mouseProperty.yOffset;
    mouseProperty_.cursorDelta = mouseProperty.cursorDelta;
    mouseProperty_.scrollingDelta = mouseProperty.scrollingDelta;
}

bool MouseEvent::Marshalling(Parcel &parcel) const
{
    return false;
}

MouseEvent *MouseEvent::Unmarshalling(Parcel &parcel)
{
    MouseEvent *event = new (std::nothrow) MouseEvent();
    if (event == nullptr) {
        return nullptr;
    }
    return event;
}

int MouseEvent::GetAction()
{
    return mouseProperty_.action;
}

int MouseEvent::GetActionButton()
{
    return mouseProperty_.actionButton;
}

int MouseEvent::GetPressedButtons()
{
    return mouseProperty_.pressedButtons;
}

MmiPoint MouseEvent::GetCursor()
{
    return mouseProperty_.mmiPoint;
}

void MouseEvent::SetCursorOffset(float offsetX, float offsetY)
{
    mouseProperty_.xOffset = offsetX;
    mouseProperty_.yOffset = offsetY;
}

float MouseEvent::GetCursorDelta(int axis)
{
    return mouseProperty_.cursorDelta;
}

float MouseEvent::GetScrollingDelta(int axis)
{
    return mouseProperty_.scrollingDelta;
}
}