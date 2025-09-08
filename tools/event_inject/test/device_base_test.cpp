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

#include <gtest/gtest.h>

#include "device_base.h"
#include "msg_head.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class DeviceBaseTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class DeviceBaseDemo : public DeviceBase {
    int32_t TransformJsonDataToInputData(const DeviceItem& fingerEventArrays, InputEventArray& inputEventArray)
    {
        return RET_ERR;
    }
};

/**
 * @tc.name:Test_SetTimeToLibinputEvent
 * @tc.desc:Verify device base function SetTimeToLibinputEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetTimeToLibinputEvent, TestSize.Level1)
{
    InjectEvent injectEvent = {};
    ASSERT_TRUE(injectEvent == nullptr);
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetTimeToLibinputEvent(injectEvent);
}

/**
 * @tc.name:Test_SetSynConfigReport
 * @tc.desc:Verify device base function SetSynConfigReport
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetSynConfigReport, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetSynConfigReport(inputEventArray, blockTime);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_SYN);
    EXPECT_EQ(inputEventArray.events[0].event.code, SYN_REPORT);
    EXPECT_EQ(inputEventArray.events[0].event.value, SYN_CONFIG);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetKeyLongPressEvent
 * @tc.desc:Verify device base function SetKeyLongPressEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetKeyLongPressEvent, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t code = KEY_A;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetKeyLongPressEvent(inputEventArray, blockTime, code);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_KEY);
    EXPECT_EQ(inputEventArray.events[0].event.code, static_cast<uint16_t>(code));
    EXPECT_EQ(inputEventArray.events[0].event.value, LONG_PRESS);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetKeyPressEvent
 * @tc.desc:Verify device base function SetKeyPressEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetKeyPressEvent, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t code = KEY_A;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetKeyPressEvent(inputEventArray, blockTime, code);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_KEY);
    EXPECT_EQ(inputEventArray.events[0].event.code, static_cast<uint16_t>(code));
    EXPECT_EQ(inputEventArray.events[0].event.value, 1);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetKeyReleaseEvent
 * @tc.desc:Verify device base function SetKeyReleaseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetKeyReleaseEvent, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t code = KEY_A;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetKeyReleaseEvent(inputEventArray, blockTime, code);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_KEY);
    EXPECT_EQ(inputEventArray.events[0].event.code, static_cast<uint16_t>(code));
    EXPECT_EQ(inputEventArray.events[0].event.value, 0);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetMtSlot
 * @tc.desc:Verify device base function SetMtSlot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetMtSlot, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 0;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetMtSlot(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_MT_SLOT);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetTrackingId
 * @tc.desc:Verify device base function SetTrackingId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetTrackingId, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 0;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetTrackingId(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_MT_TRACKING_ID);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetPositionX
 * @tc.desc:Verify device base function SetPositionX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetPositionX, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 10;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetPositionX(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_MT_POSITION_X);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetPositionY
 * @tc.desc:Verify device base function SetPositionY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetPositionY, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 10;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetPositionY(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_MT_POSITION_Y);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetMtTouchMajor
 * @tc.desc:Verify device base function SetMtTouchMajor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetMtTouchMajor, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 10;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetMtTouchMajor(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_MT_TOUCH_MAJOR);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetMtTouchMinor
 * @tc.desc:Verify device base function SetMtTouchMinor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetMtTouchMinor, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 10;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetMtTouchMinor(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_MT_TOUCH_MINOR);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetMtOrientation
 * @tc.desc:Verify device base function SetMtOrientation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetMtOrientation, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 10;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetMtOrientation(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_MT_ORIENTATION);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetBtnTouch
 * @tc.desc:Verify device base function SetBtnTouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetBtnTouch, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 10;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetBtnTouch(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_KEY);
    EXPECT_EQ(inputEventArray.events[0].event.code, BTN_TOUCH);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetEvAbsX
 * @tc.desc:Verify device base function SetEvAbsX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetEvAbsX, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 10;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetEvAbsX(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_X);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetEvAbsY
 * @tc.desc:Verify device base function SetEvAbsY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetEvAbsY, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 10;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetEvAbsY(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_Y);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetMtTouchOneFingerType
 * @tc.desc:Verify device base function SetMtTouchFingerType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetMtTouchOneFingerType, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 1;
    int32_t status = 1;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetMtTouchFingerType(inputEventArray, blockTime, value, status);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
    EXPECT_EQ(inputEventArray.events[0].event.code, BTN_TOOL_FINGER);
    EXPECT_EQ(inputEventArray.events[0].event.value, status);
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_KEY);
}

/**
 * @tc.name:Test_SetMtTouchTwoFingerType
 * @tc.desc:Verify device base function SetMtTouchFingerType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetMtTouchTwoFingerType, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 2;
    int32_t status = 1;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetMtTouchFingerType(inputEventArray, blockTime, value, status);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_KEY);
    EXPECT_EQ(inputEventArray.events[0].event.code, BTN_TOOL_DOUBLETAP);
    EXPECT_EQ(inputEventArray.events[0].event.value, status);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetMtTouchThreeFingerType
 * @tc.desc:Verify device base function SetMtTouchFingerType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetMtTouchThreeFingerType, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t status = 1;
    int32_t value = 3;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetMtTouchFingerType(inputEventArray, blockTime, value, status);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.code, BTN_TOOL_TRIPLETAP);
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_KEY);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
    EXPECT_EQ(inputEventArray.events[0].event.value, status);
}

/**
 * @tc.name:Test_SetMtTouchFourFingerType
 * @tc.desc:Verify device base function SetMtTouchFingerType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetMtTouchFourFingerType, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 4;
    int32_t status = 1;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetMtTouchFingerType(inputEventArray, blockTime, value, status);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_KEY);
    EXPECT_EQ(inputEventArray.events[0].event.code, BTN_TOOL_QUADTAP);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
    EXPECT_EQ(inputEventArray.events[0].event.value, status);
}

/**
 * @tc.name:Test_SetMtTouchFiveFingerType
 * @tc.desc:Verify device base function SetMtTouchFingerType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetMtTouchFiveFingerType, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 5;
    int32_t status = 1;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetMtTouchFingerType(inputEventArray, blockTime, value, status);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.code, BTN_TOOL_QUINTTAP);
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_KEY);
    EXPECT_EQ(inputEventArray.events[0].event.value, status);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetMtTouchOtherFingerType
 * @tc.desc:Verify device base function SetMtTouchFingerType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetMtTouchOtherFingerType, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int32_t value = 6;
    int32_t status = 1;
    int64_t blockTime = 10;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetMtTouchFingerType(inputEventArray, blockTime, value, status);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.code, BTN_TOOL_FINGER);
    EXPECT_EQ(inputEventArray.events[0].event.value, status);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_KEY);
}

/**
 * @tc.name:Test_SetEvAbsZ
 * @tc.desc:Verify device base function SetEvAbsZ
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetEvAbsZ, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 5;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetEvAbsZ(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_Z);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
}

/**
 * @tc.name:Test_SetEvAbsRx
 * @tc.desc:Verify device base function SetEvAbsRx
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetEvAbsRx, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int32_t value = 5;
    int64_t blockTime = 10;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetEvAbsRx(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_RX);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetEvAbsRy
 * @tc.desc:Verify device base function SetEvAbsRy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetEvAbsRy, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 5;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetEvAbsRy(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_RY);
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetEvAbsHat0X
 * @tc.desc:Verify device base function SetEvAbsHat0X
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetEvAbsHat0X, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 5;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetEvAbsHat0X(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_HAT0X);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetEvAbsHat0Y
 * @tc.desc:Verify device base function SetEvAbsHat0Y
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetEvAbsHat0Y, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 5;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetEvAbsHat0Y(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_HAT0Y);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
}

/**
 * @tc.name:Test_SetEvAbsRz
 * @tc.desc:Verify device base function SetEvAbsRz
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetEvAbsRz, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 5;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetEvAbsRz(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_RZ);
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetEvAbs
 * @tc.desc:Verify device base function SetEvAbs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetEvAbs, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 5;
    uint16_t code = 0;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetEvAbs(inputEventArray, blockTime, code, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, code);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetRelX
 * @tc.desc:Verify device base function SetRelX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetRelX, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 5;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetRelX(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_REL);
    EXPECT_EQ(inputEventArray.events[0].event.code, REL_X);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetRelY
 * @tc.desc:Verify device base function SetRelY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetRelY, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 5;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetRelY(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_REL);
    EXPECT_EQ(inputEventArray.events[0].event.code, REL_Y);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetRelWheel
 * @tc.desc:Verify device base function SetRelWheel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetRelWheel, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 5;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetRelWheel(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_REL);
    EXPECT_EQ(inputEventArray.events[0].event.code, REL_WHEEL);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetRelHwheel
 * @tc.desc:Verify device base function SetRelHwheel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetRelHwheel, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 5;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetRelHwheel(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_REL);
    EXPECT_EQ(inputEventArray.events[0].event.code, REL_HWHEEL);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetEvAbsWheel
 * @tc.desc:Verify device base function SetEvAbsWheel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetEvAbsWheel, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 5;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetEvAbsWheel(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_WHEEL);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetAbsMiscStartStatus
 * @tc.desc:Verify device base function SetAbsMisc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetAbsMiscStartStatus, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 1;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetAbsMisc(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_MISC);
    EXPECT_EQ(inputEventArray.events[0].event.value, 15);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetAbsMiscEndStatus
 * @tc.desc:Verify device base function SetAbsMisc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetAbsMiscEndStatus, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 2;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetAbsMisc(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_MISC);
    EXPECT_EQ(inputEventArray.events[0].event.value, 0);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetAbsTiltX
 * @tc.desc:Verify device base function SetAbsTiltX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetAbsTiltX, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 20;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetAbsTiltX(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_TILT_X);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetAbsTiltY
 * @tc.desc:Verify device base function SetAbsTiltY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetAbsTiltY, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 20;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetAbsTiltY(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_TILT_Y);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetAbsPressure
 * @tc.desc:Verify device base function SetAbsPressure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetAbsPressure, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 20;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetAbsPressure(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_PRESSURE);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetAbsDistance
 * @tc.desc:Verify device base function SetAbsDistance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetAbsDistance, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 20;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetAbsDistance(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_DISTANCE);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetBtnPen
 * @tc.desc:Verify device base function SetBtnPen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetBtnPen, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 20;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetBtnPen(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_KEY);
    EXPECT_EQ(inputEventArray.events[0].event.code, BTN_TOOL_PEN);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetBtnStylus
 * @tc.desc:Verify device base function SetBtnStylus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetBtnStylus, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 20;
    uint16_t code = BTN_STYLUS;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetBtnStylus(inputEventArray, blockTime, code, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_KEY);
    EXPECT_EQ(inputEventArray.events[0].event.code, BTN_STYLUS);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetBtnRubber
 * @tc.desc:Verify device base function SetBtnRubber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetBtnRubber, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 20;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetBtnRubber(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_KEY);
    EXPECT_EQ(inputEventArray.events[0].event.code, BTN_TOOL_RUBBER);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetMscSerial
 * @tc.desc:Verify device base function SetMscSerial
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetMscSerial, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 20;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetMscSerial(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_MSC);
    EXPECT_EQ(inputEventArray.events[0].event.code, MSC_SERIAL);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetSynMtReport
 * @tc.desc:Verify device base function SetSynMtReport
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetSynMtReport, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 0;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetSynMtReport(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_SYN);
    EXPECT_EQ(inputEventArray.events[0].event.code, SYN_MT_REPORT);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}

/**
 * @tc.name:Test_SetThrottle
 * @tc.desc:Verify device base function SetThrottle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceBaseTest, Test_SetThrottle, TestSize.Level1)
{
    InputEventArray inputEventArray = {};
    int64_t blockTime = 10;
    int32_t value = 0;
    DeviceBaseDemo deviceBaseDemo;
    deviceBaseDemo.SetThrottle(inputEventArray, blockTime, value);
    EXPECT_GT(inputEventArray.events.size(), 0);
    if (inputEventArray.events.size() <= 0) {
    }
    EXPECT_EQ(inputEventArray.events[0].event.type, EV_ABS);
    EXPECT_EQ(inputEventArray.events[0].event.code, ABS_THROTTLE);
    EXPECT_EQ(inputEventArray.events[0].event.value, value);
    EXPECT_EQ(inputEventArray.events[0].blockTime, blockTime);
}
} // namespace MMI
} // namespace OHOS