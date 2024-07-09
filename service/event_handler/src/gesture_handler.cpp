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

#include "gesture_handler.h"

#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "GestureHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t FIRST_FINGER { 0 };
constexpr int32_t SECOND_FINGER { 1 };
constexpr int32_t TWO_FINGERS { 2 };
constexpr double EFFECT_ANGLE { 5.0 };
constexpr double FLAT_ANGLE { 180.0 };
} // namespace

GestureHandler::GestureHandler() {}

GestureHandler::~GestureHandler() {}

void GestureHandler::InitRotateGesture()
{
    isReady_ = false;
    isStartRotate_ = false;
    fingerDownPosition_.clear();
    fingerCurrentPosition_.clear();
    initialAngle_ = 0.0;
    lastAngle_ = 0.0;
    rotateAngle_ = 0.0;
    numberOfTouchPadFingerDown_ = -1;
}

int32_t GestureHandler::GestureIdentify(int32_t originType, int32_t seatSlot, double logicalX, double logicalY)
{
    int32_t gestureType = PointerEvent::POINTER_ACTION_UNKNOWN;
    switch (originType) {
        case LIBINPUT_EVENT_TOUCHPAD_DOWN: {
            numberOfTouchPadFingerDown_++;
            gestureType = HandleTouchPadDownEvent(seatSlot, logicalX, logicalY);
            break;
        }
        case LIBINPUT_EVENT_TOUCHPAD_MOTION: {
            gestureType = HandleTouchPadMoveEvent(seatSlot, logicalX, logicalY);
            break;
        }
        case LIBINPUT_EVENT_TOUCHPAD_UP: {
            gestureType = HandleTouchPadUpEvent(seatSlot);
            break;
        }
        default: {
            MMI_HILOGE("originType is invalid");
            break;
        }
    }

    return gestureType;
}

int32_t GestureHandler::HandleTouchPadDownEvent(int32_t seatSlot, double logicalX, double logicalY)
{
    if (seatSlot < FIRST_FINGER || seatSlot > SECOND_FINGER) {
        if (isStartRotate_) {
            MMI_HILOGI("Exceed two fingers, rotate is end");
            return PointerEvent::POINTER_ACTION_ROTATE_END;
        }
        if (isReady_) {
            InitRotateGesture();
        }
        MMI_HILOGD("seatSlot is invalid");
        return PointerEvent::POINTER_ACTION_UNKNOWN;
    }

    struct Position position;
    position.x = logicalX;
    position.y = logicalY;
    fingerDownPosition_[seatSlot] = position;
    if (fingerDownPosition_.size() == TWO_FINGERS) {
        isReady_ = true;
        initialAngle_ = CalculateAngle(fingerDownPosition_);
        fingerCurrentPosition_ = fingerDownPosition_;
    }
    return PointerEvent::POINTER_ACTION_UNKNOWN;
}

int32_t GestureHandler::HandleTouchPadMoveEvent(int32_t seatSlot, double logicalX, double logicalY)
{
    if (!isReady_) {
        MMI_HILOGD("Gesture event is not identified");
        return PointerEvent::POINTER_ACTION_UNKNOWN;
    }
    if (numberOfTouchPadFingerDown_ < FIRST_FINGER || numberOfTouchPadFingerDown_ > SECOND_FINGER) {
        if (isStartRotate_) {
            MMI_HILOGI("Exceed two fingers, rotate is end");
            return PointerEvent::POINTER_ACTION_UNKNOWN;
        }
        if (isReady_) {
            InitRotateGesture();
        }
        MMI_HILOGD("seatSlot is invalid");
        return PointerEvent::POINTER_ACTION_UNKNOWN;
    }

    struct Position position;
    position.x = logicalX;
    position.y = logicalY;
    fingerCurrentPosition_[seatSlot] = position;
    double currentAngle = CalculateAngle(fingerCurrentPosition_);
    if (!isStartRotate_ && fabs(currentAngle - initialAngle_) >= EFFECT_ANGLE) {
        initialAngle_ = currentAngle;
        lastAngle_ = currentAngle;
        isStartRotate_ = true;
        MMI_HILOGI("Begin to rotate");
        return PointerEvent::POINTER_ACTION_ROTATE_BEGIN;
    }

    if (isStartRotate_) {
        rotateAngle_ += AdjustRotateAngle(currentAngle);
        lastAngle_ = currentAngle;
        return PointerEvent::POINTER_ACTION_ROTATE_UPDATE;
    }
    return PointerEvent::POINTER_ACTION_UNKNOWN;
}

int32_t GestureHandler::HandleTouchPadUpEvent(int32_t seatSlot)
{
    if (isStartRotate_) {
        isReady_ = false;
        isStartRotate_ = false;
        fingerDownPosition_.erase(seatSlot);
        fingerCurrentPosition_.erase(seatSlot);
        MMI_HILOGI("Rotate is end");
        return PointerEvent::POINTER_ACTION_ROTATE_END;
    }
    InitRotateGesture();
    return PointerEvent::POINTER_ACTION_UNKNOWN;
}

double GestureHandler::CalculateAngle(std::map<int32_t, struct Position> fingerPosition)
{
    double firstX = fingerPosition[FIRST_FINGER].x;
    double firstY = fingerPosition[FIRST_FINGER].y;
    double secondX = fingerPosition[SECOND_FINGER].x;
    double secondY = fingerPosition[SECOND_FINGER].y;
    double angle = atan2(firstY - secondY, firstX - secondX) * 180.0 / M_PI;
    return angle;
}

double GestureHandler::AdjustRotateAngle(double currentAngle)
{
    double angleIncrement = 0;
    if (currentAngle - lastAngle_ >= FLAT_ANGLE) {
        angleIncrement = (currentAngle - FLAT_ANGLE) - (lastAngle_ + FLAT_ANGLE);
    } else if (lastAngle_ - currentAngle >= FLAT_ANGLE) {
        angleIncrement = (currentAngle + FLAT_ANGLE) + (FLAT_ANGLE - lastAngle_);
    } else {
        angleIncrement = currentAngle - lastAngle_;
    }
    return angleIncrement;
}

double GestureHandler::GetRotateAngle()
{
    return rotateAngle_;
}

bool GestureHandler::GetRotateStatus()
{
    return isStartRotate_;
}
} // namespace MMI
} // namespace OHOS