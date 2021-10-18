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
#include "mouse_event.h"

namespace OHOS {
MouseEvent::~MouseEvent() {}
void MouseEvent::Initialize(int32_t windowId, int32_t action, int32_t actionButton, int32_t pressedButtons,
    const MmiPoint& mmiPoint, float xOffset, float yOffset, float cursorDelta, float scrollingDelta,
    int32_t highLevelEvent, const std::string& uuid, int32_t sourceType, int32_t occurredTime,
    const std::string& deviceId, int32_t inputDeviceId, bool isHighLevelEvent,
    uint16_t deviceUdevTags, const EventJoyStickAxis& eventJoyStickInfo)
{
    MultimodalEvent::Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
                                isHighLevelEvent, deviceUdevTags);
    mAction_ = action;
    mActionButton_ = actionButton;
    mPressedButtons_ = pressedButtons;
    mMmiPoint_ = mmiPoint;
    mXOffset_ = xOffset;
    mYOffset_ = yOffset;
    mCursorDelta_ = cursorDelta;
    mScrollingDelta_ = scrollingDelta;
    
    mapDeviceAxis_[AXIS_X] = eventJoyStickInfo.abs_x.standardValue;
    mapDeviceAxis_[AXIS_Y] = eventJoyStickInfo.abs_y.standardValue;
    mapDeviceAxis_[AXIS_Z] = eventJoyStickInfo.abs_z.standardValue;
    mapDeviceAxis_[AXIS_RX] = eventJoyStickInfo.abs_rx.standardValue;
    mapDeviceAxis_[AXIS_RY] = eventJoyStickInfo.abs_ry.standardValue;
    mapDeviceAxis_[AXIS_RZ] = eventJoyStickInfo.abs_rz.standardValue;
    mapDeviceAxis_[AXIS_THROTTLE] = eventJoyStickInfo.abs_throttle.standardValue;
    mapDeviceAxis_[AXIS_HAT_X] = eventJoyStickInfo.abs_hat0x.standardValue;
    mapDeviceAxis_[AXIS_HAT_Y] = eventJoyStickInfo.abs_hat0y.standardValue;
    mapDeviceAxis_[AXIS_WHEEL] = eventJoyStickInfo.abs_wheel.standardValue;
    mapDeviceAxis_[AXIS_TILT_X] = xOffset;
    mapDeviceAxis_[AXIS_TILT_Y] = yOffset;
}

void MouseEvent::Initialize(MouseEvent& mouseEvent)
{
    MultimodalEvent::Initialize(mouseEvent);
    mAction_ = mouseEvent.GetAction();
    mActionButton_ = mouseEvent.GetActionButton();
    mPressedButtons_ = mouseEvent.GetPressedButtons();
    mMmiPoint_ = mouseEvent.GetCursor();
    mXOffset_ = mouseEvent.GetXOffset();
    mYOffset_ = mouseEvent.GetYOffset();
    mCursorDelta_ = mouseEvent.GetCursorDelta(0);
    mScrollingDelta_ = mouseEvent.GetScrollingDelta(0);
}

int32_t MouseEvent::GetAction() const
{
    return mAction_;
}

int32_t MouseEvent::GetActionButton() const
{
    return mActionButton_;
}

int32_t MouseEvent::GetPressedButtons() const
{
    return mPressedButtons_;
}

MmiPoint MouseEvent::GetCursor() const
{
    return mMmiPoint_;
}

void MouseEvent::SetCursorOffset(float offsetX, float offsetY)
{
    mXOffset_ = offsetX;
    mYOffset_ = offsetY;
}

float MouseEvent::GetXOffset() const
{
    return mXOffset_;
}

float MouseEvent::GetYOffset() const
{
    return mYOffset_;
}

float MouseEvent::GetCursorDelta(int32_t axis) const
{
    return mCursorDelta_;
}

float MouseEvent::GetScrollingDelta(int32_t axis) const
{
    auto it = mapDeviceAxis_.find(axis);
    if (it != mapDeviceAxis_.end()) {
        return it->second;
    }

    return 0.0F;
}

float MouseEvent::GetAxisValue(int32_t axis) const
{
    auto it = mapDeviceAxis_.find(axis);
    if (it != mapDeviceAxis_.end()) {
        return it->second;
    }

    return 0.0F;
}
}
