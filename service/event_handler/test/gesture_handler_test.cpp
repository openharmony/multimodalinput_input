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

#include <gtest/gtest.h>
#include <libinput.h>

#include "gesture_handler.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "GestureHandlerTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class GestureHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: GestureHandlerTest_GestureIdentify_001
 * @tc.desc: Verify gesture handler
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(GestureHandlerTest, GestureHandlerTest_GestureIdentify_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t seatSlot = 0;
    double logicalX = 10;
    double logicalY = 10;
    auto originType = LIBINPUT_EVENT_TOUCHPAD_DOWN;
    auto actionType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    seatSlot = 1;
    logicalX = 100;
    logicalY = 100;
    originType = LIBINPUT_EVENT_TOUCHPAD_DOWN;
    actionType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    ASSERT_EQ(actionType, PointerEvent::POINTER_ACTION_UNKNOWN);
}

/**
 * @tc.name: GestureHandlerTest_GestureIdentify_002
 * @tc.desc: Verify gesture handler
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(GestureHandlerTest, GestureHandlerTest_GestureIdentify_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t seatSlot = 0;
    double logicalX = 10;
    double logicalY = 10;
    auto originType = LIBINPUT_EVENT_TOUCHPAD_DOWN;
    auto actionType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    seatSlot = 1;
    logicalX = 100;
    logicalY = 100;
    originType = LIBINPUT_EVENT_TOUCHPAD_DOWN;
    GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    seatSlot = 1;
    logicalX = 100;
    logicalY = 0;
    originType = LIBINPUT_EVENT_TOUCHPAD_MOTION;
    actionType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    ASSERT_NE(actionType, PointerEvent::POINTER_ACTION_ROTATE_BEGIN);
}

/**
 * @tc.name: GestureHandlerTest_GestureIdentify_003
 * @tc.desc: Verify gesture handler
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(GestureHandlerTest, GestureHandlerTest_GestureIdentify_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t seatSlot = 0;
    double logicalX = 9;
    double logicalY = 9;
    auto originType = LIBINPUT_EVENT_TOUCHPAD_DOWN;
    auto actionType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    seatSlot = 1;
    logicalX = 99;
    logicalY = 99;
    originType = LIBINPUT_EVENT_TOUCHPAD_DOWN;
    GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    seatSlot = 1;
    logicalX = 99;
    logicalY = 0;
    originType = LIBINPUT_EVENT_TOUCHPAD_MOTION;
    GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    seatSlot = 0;
    logicalX = 0;
    logicalY = 99;
    originType = LIBINPUT_EVENT_TOUCHPAD_MOTION;
    actionType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    ASSERT_EQ(actionType, PointerEvent::POINTER_ACTION_ROTATE_UPDATE);
}

/**
 * @tc.name: GestureHandlerTest_GestureIdentify_004
 * @tc.desc: Verify gesture handler
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(GestureHandlerTest, GestureHandlerTest_GestureIdentify_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t seatSlot = 0;
    double logicalX = 10;
    double logicalY = 10;
    auto originType = LIBINPUT_EVENT_TOUCHPAD_DOWN;
    auto actionType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    seatSlot = 1;
    logicalX = 200;
    logicalY = 200;
    originType = LIBINPUT_EVENT_TOUCHPAD_DOWN;
    GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    seatSlot = 1;
    logicalX = 200;
    logicalY = 0;
    originType = LIBINPUT_EVENT_TOUCHPAD_MOTION;
    GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    seatSlot = 0;
    logicalX = 0;
    logicalY = 200;
    originType = LIBINPUT_EVENT_TOUCHPAD_MOTION;
    GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    seatSlot = 0;
    logicalX = 0;
    logicalY = 200;
    originType = LIBINPUT_EVENT_TOUCHPAD_UP;
    actionType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    ASSERT_EQ(actionType, PointerEvent::POINTER_ACTION_ROTATE_END);
}

/**
 * @tc.name: GestureHandlerTest_GetRotateAngle_001
 * @tc.desc: Verify get rotate angle
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(GestureHandlerTest, GestureHandlerTest_GetRotateAngle_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t seatSlot = 0;
    double logicalX = 0;
    double logicalY = 0;
    auto originType = LIBINPUT_EVENT_TOUCHPAD_DOWN;
    auto actionType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    seatSlot = 1;
    logicalX = 10;
    logicalY = 10;
    originType = LIBINPUT_EVENT_TOUCHPAD_DOWN;
    actionType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    seatSlot = 2;
    logicalX = 20;
    logicalY = 20;
    originType = LIBINPUT_EVENT_TOUCHPAD_DOWN;
    actionType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    double rotateAngle = 0.0;
    ASSERT_EQ(GESTURE_HANDLER->GetRotateAngle(), rotateAngle);
}

/**
 * @tc.name: GestureHandlerTest_GestureIdentify_005
 * @tc.desc: Gesture identify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(GestureHandlerTest, GestureHandlerTest_GestureIdentify_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t originType = 999;
    int32_t seatSlot = 0;
    double logicalX = 0.0;
    double logicalY = 0.0;
    auto actionType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    ASSERT_EQ(actionType, PointerEvent::POINTER_ACTION_UNKNOWN);
}

/**
 * @tc.name: GestureHandlerTest_HandleTouchPadDownEvent_001
 * @tc.desc: Handle touch pad down event
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(GestureHandlerTest, GestureHandlerTest_HandleTouchPadDownEvent_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t seatSlot = 2;
    double logicalX = 0.0;
    double logicalY = 0.0;
    auto originType = LIBINPUT_EVENT_TOUCHPAD_DOWN;
    auto gestureType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    ASSERT_EQ(gestureType, PointerEvent::POINTER_ACTION_UNKNOWN);
}

/**
 * @tc.name: GestureHandlerTest_HandleTouchPadMoveEvent_001
 * @tc.desc: Handle touch pad move event
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(GestureHandlerTest, GestureHandlerTest_HandleTouchPadMoveEvent_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t seatSlot = 0;
    double logicalX = 0.0;
    double logicalY = 0.0;
    auto originType = LIBINPUT_EVENT_TOUCHPAD_MOTION;
    auto gestureType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    ASSERT_EQ(gestureType, PointerEvent::POINTER_ACTION_UNKNOWN);
}

/**
 * @tc.name: GestureHandlerTest_HandleTouchPadMoveEvent_002
 * @tc.desc: Handle touch pad move event
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(GestureHandlerTest, GestureHandlerTest_HandleTouchPadMoveEvent_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t seatSlot = 0;
    double logicalX = 0.0;
    double logicalY = 0.0;
    auto originType = LIBINPUT_EVENT_TOUCHPAD_MOTION;
    auto gestureType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    ASSERT_EQ(gestureType, PointerEvent::POINTER_ACTION_UNKNOWN);
}

/**
 * @tc.name: GestureHandlerTest_HandleTouchPadUpEvent_001
 * @tc.desc: Handle touch pad up event
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(GestureHandlerTest, GestureHandlerTest_HandleTouchPadUpEvent_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t seatSlot = 0;
    double logicalX = 0.0;
    double logicalY = 0.0;
    auto originType = LIBINPUT_EVENT_TOUCHPAD_UP;
    auto gestureType = GESTURE_HANDLER->GestureIdentify(originType, seatSlot, logicalX, logicalY);
    ASSERT_EQ(gestureType, PointerEvent::POINTER_ACTION_UNKNOWN);
}
} // namespace MMI
} // namespace OHOS