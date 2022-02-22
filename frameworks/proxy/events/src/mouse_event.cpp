/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
MouseEvent::~MouseEvent() {}
void MouseEvent::Initialize(int32_t windowId, int32_t action, int32_t actionButton, int32_t pressedButtons,
    const MmiPoint& mmiPoint, float xOffset, float yOffset, float cursorDelta, float scrollingDelta,
    int32_t highLevelEvent, const std::string& uuid, int32_t sourceType, int32_t occurredTime,
    const std::string& deviceId, int32_t inputDeviceId, bool isHighLevelEvent,
    uint16_t deviceUdevTags, const MMI::EventJoyStickAxis& eventJoyStickInfo)
{
    MultimodalEvent::Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
                                isHighLevelEvent, deviceUdevTags);
    action_ = action;
    actionButton_ = actionButton;
    pressedButtons_ = pressedButtons;
    mmiPoint_ = mmiPoint;
    xOffset_ = xOffset;
    yOffset_ = yOffset;
    cursorDelta_ = cursorDelta;
    scrollingDelta_ = scrollingDelta;

    deviceAxis_[AXIS_X] = eventJoyStickInfo.abs_x.standardValue;
    deviceAxis_[AXIS_Y] = eventJoyStickInfo.abs_y.standardValue;
    deviceAxis_[AXIS_Z] = eventJoyStickInfo.abs_z.standardValue;
    deviceAxis_[AXIS_RX] = eventJoyStickInfo.abs_rx.standardValue;
    deviceAxis_[AXIS_RY] = eventJoyStickInfo.abs_ry.standardValue;
    deviceAxis_[AXIS_RZ] = eventJoyStickInfo.abs_rz.standardValue;
    deviceAxis_[AXIS_THROTTLE] = eventJoyStickInfo.abs_throttle.standardValue;
    deviceAxis_[AXIS_HAT_X] = eventJoyStickInfo.abs_hat0x.standardValue;
    deviceAxis_[AXIS_HAT_Y] = eventJoyStickInfo.abs_hat0y.standardValue;
    deviceAxis_[AXIS_WHEEL] = eventJoyStickInfo.abs_wheel.standardValue;
    deviceAxis_[AXIS_TILT_X] = xOffset;
    deviceAxis_[AXIS_TILT_Y] = yOffset;
}

void MouseEvent::Initialize(MouseEvent& mouseEvent)
{
    MultimodalEvent::Initialize(mouseEvent);
    action_ = mouseEvent.GetAction();
    actionButton_ = mouseEvent.GetActionButton();
    pressedButtons_ = mouseEvent.GetPressedButtons();
    mmiPoint_ = mouseEvent.GetCursor();
    xOffset_ = mouseEvent.GetXOffset();
    yOffset_ = mouseEvent.GetYOffset();
    cursorDelta_ = mouseEvent.GetCursorDelta(0);
    scrollingDelta_ = mouseEvent.GetScrollingDelta(0);
}

int32_t MouseEvent::GetAction() const
{
    return action_;
}

int32_t MouseEvent::GetActionButton() const
{
    return actionButton_;
}

int32_t MouseEvent::GetPressedButtons() const
{
    return pressedButtons_;
}

MmiPoint MouseEvent::GetCursor() const
{
    return mmiPoint_;
}

void MouseEvent::SetCursorOffset(float offsetX, float offsetY)
{
    xOffset_ = offsetX;
    yOffset_ = offsetY;
}

float MouseEvent::GetXOffset() const
{
    return xOffset_;
}

float MouseEvent::GetYOffset() const
{
    return yOffset_;
}

float MouseEvent::GetCursorDelta(int32_t axis) const
{
    return cursorDelta_;
}

float MouseEvent::GetScrollingDelta(int32_t axis) const
{
    auto it = deviceAxis_.find(axis);
    if (it != deviceAxis_.end()) {
        return it->second;
    }

    return 0.0F;
}

float MouseEvent::GetAxisValue(int32_t axis) const
{
    auto it = deviceAxis_.find(axis);
    if (it != deviceAxis_.end()) {
        return it->second;
    }

    return 0.0F;
}
} // namespace OHOS
