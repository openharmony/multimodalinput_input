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

#include <cstdio>
#include <gtest/gtest.h>

#include "libinput.h"
#include "mouse_transform_processor.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class MouseTransformProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

private:
    MouseTransformProcessor g_processor { 0 };
    int32_t prePointerSpeed { 5 };
    int32_t prePrimaryButton { 0 };
    int32_t preScrollRows { 3 };
    int32_t preTouchpadPointerSpeed { 9 };
    int32_t preRightClickType { 1 };
    bool preScrollSwitch { true };
    bool preScrollDirection { true };
    bool preTapSwitch { true };
};

void MouseTransformProcessorTest::SetUpTestCase(void)
{
}

void MouseTransformProcessorTest::TearDownTestCase(void)
{
}

void MouseTransformProcessorTest::SetUp()
{
    prePointerSpeed = g_processor.GetPointerSpeed();
    prePrimaryButton = g_processor.GetMousePrimaryButton();
    preScrollRows = g_processor.GetMouseScrollRows();
    g_processor.GetTouchpadPointerSpeed(preTouchpadPointerSpeed);
    g_processor.GetTouchpadRightClickType(preRightClickType);
    g_processor.GetTouchpadScrollSwitch(preScrollSwitch);
    g_processor.GetTouchpadScrollDirection(preScrollDirection);
    g_processor.GetTouchpadTapSwitch(preTapSwitch);
}

void MouseTransformProcessorTest::TearDown()
{
    g_processor.SetPointerSpeed(prePointerSpeed);
    g_processor.SetMousePrimaryButton(prePrimaryButton);
    g_processor.SetMouseScrollRows(preScrollRows);
    g_processor.SetTouchpadPointerSpeed(preTouchpadPointerSpeed);
    g_processor.SetTouchpadRightClickType(preRightClickType);
    g_processor.SetTouchpadScrollSwitch(preScrollSwitch);
    g_processor.SetTouchpadScrollDirection(preScrollDirection);
    g_processor.SetTouchpadTapSwitch(preTapSwitch);
}

/**
 * @tc.name: MouseDeviceStateTest_GetPointerEvent_001
 * @tc.desc: Test GetPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetPointerEvent_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    ASSERT_TRUE(processor.GetPointerEvent() != nullptr);
    processor.InitAbsolution();
    int32_t displayId = 0;
    processor.OnDisplayLost(displayId);
}

/**
 * @tc.name: MouseTransformProcessorTest_Dump_002
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_Dump_002, TestSize.Level1)
{
    std::vector<std::string> args;
    std::vector<std::string> idNames;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t fd = 0;
    processor.Dump(fd, args);
    ASSERT_EQ(args, idNames);
}

/**
 * @tc.name: MouseTransformProcessorTest_NormalizeMoveMouse_003
 * @tc.desc: Test NormalizeMoveMouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_NormalizeMoveMouse_003, TestSize.Level1)
{
    bool isNormalize = false;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t offsetX = 0;
    int32_t offsetY = 0;
    ASSERT_EQ(processor.NormalizeMoveMouse(offsetX, offsetY), isNormalize);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetDisplayId_004
 * @tc.desc: Test GetDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetDisplayId_004, TestSize.Level1)
{
    int32_t idNames = -1;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    ASSERT_EQ(processor.GetDisplayId(), idNames);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetPointerSpeed_005
 * @tc.desc: Test SetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetPointerSpeed_005, TestSize.Level1)
{
    int32_t idNames = 0;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = 5;
    ASSERT_EQ(processor.SetPointerSpeed(speed), idNames);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetPointerSpeed_006
 * @tc.desc: Test GetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetPointerSpeed_006, TestSize.Level1)
{
    int32_t idNames = 5;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = 5;
    processor.SetPointerSpeed(speed);
    ASSERT_EQ(processor.GetPointerSpeed(), idNames);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetPointerLocation_008
 * @tc.desc: Test SetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetPointerLocation_008, TestSize.Level1)
{
    int32_t idNames = -1;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t x = 0;
    int32_t y = 0;
    ASSERT_EQ(processor.SetPointerLocation(x, y), idNames);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetPointerSpeed_009
 * @tc.desc: Test GetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetPointerSpeed_009, TestSize.Level1)
{
    int32_t idNames = 1;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = 0;
    processor.SetPointerSpeed(speed);
    ASSERT_EQ(processor.GetPointerSpeed(), idNames);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetMousePrimaryButton_010
 * @tc.desc: Test SetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetMousePrimaryButton_010, TestSize.Level1)
{
    int32_t deviceId = 1;
    MouseTransformProcessor processor(deviceId);
    int32_t primaryButton = 1;
    ASSERT_TRUE(processor.SetMousePrimaryButton(primaryButton) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetMousePrimaryButton_011
 * @tc.desc: Test GetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetMousePrimaryButton_011, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t primaryButton = 1;
    processor.SetMousePrimaryButton(primaryButton);
    int32_t primaryButtonRes = 1;
    ASSERT_TRUE(processor.GetMousePrimaryButton() == primaryButtonRes);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetMouseScrollRows_012
 * @tc.desc: Test SetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetMouseScrollRows_012, TestSize.Level1)
{
    int32_t deviceId = 1;
    MouseTransformProcessor processor(deviceId);
    int32_t rows = 1;
    ASSERT_TRUE(processor.SetMouseScrollRows(rows) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetMouseScrollRows_013
 * @tc.desc: Test GetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetMouseScrollRows_013, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t rows = 1;
    processor.SetMouseScrollRows(rows);
    int32_t newRows = 1;
    ASSERT_TRUE(processor.GetMouseScrollRows() == newRows);
}
/**
 * @tc.name: MouseTransformProcessorTest_SetTouchpadScrollSwitch_014
 * @tc.desc: Test SetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetTouchpadScrollSwitch_014, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    bool flag = false;
    ASSERT_TRUE(processor.SetTouchpadScrollSwitch(flag) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetTouchpadScrollSwitch_015
 * @tc.desc: Test GetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetTouchpadScrollSwitch_015, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    bool flag = true;
    processor.SetTouchpadScrollSwitch(flag);
    bool newFlag = true;
    ASSERT_TRUE(processor.GetTouchpadScrollSwitch(flag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetTouchpadScrollSwitch_014
 * @tc.desc: Test SetTouchpadScrollDirection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetTouchpadScrollDirection_016, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    bool state = false;
    ASSERT_TRUE(processor.SetTouchpadScrollDirection(state) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetTouchpadScrollDirection_017
 * @tc.desc: Test GetTouchpadScrollDirection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetTouchpadScrollDirection_017, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    bool state = true;
    processor.SetTouchpadScrollDirection(state);
    bool newState = true;
    ASSERT_TRUE(processor.GetTouchpadScrollDirection(state) == RET_OK);
    ASSERT_TRUE(state == newState);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetTouchpadTapSwitch_018
 * @tc.desc: Test SetTouchpadTapSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetTouchpadTapSwitch_018, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    bool flag = false;
    ASSERT_TRUE(processor.SetTouchpadTapSwitch(flag) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetTouchpadTapSwitch_019
 * @tc.desc: Test GetTouchpadTapSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetTouchpadTapSwitch_019, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    bool flag = false;
    processor.SetTouchpadTapSwitch(flag);
    bool newFlag = false;
    ASSERT_TRUE(processor.GetTouchpadTapSwitch(flag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetTouchpadPointerSpeed_020
 * @tc.desc: Test SetTouchpadPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetTouchpadPointerSpeed_020, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = 2;
    ASSERT_TRUE(processor.SetTouchpadPointerSpeed(speed) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetTouchpadPointerSpeed_021
 * @tc.desc: Test GetTouchpadPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetTouchpadPointerSpeed_021, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = 2;
    processor.SetTouchpadPointerSpeed(speed);
    int32_t newSpeed = 3;
    ASSERT_TRUE(processor.GetTouchpadPointerSpeed(newSpeed) == RET_OK);
    ASSERT_TRUE(speed == newSpeed);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetTouchpadPointerSpeed_022
 * @tc.desc: Test SetTouchpadPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetTouchpadPointerSpeed_022, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = 8;
    ASSERT_TRUE(processor.SetTouchpadPointerSpeed(speed) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetTouchpadPointerSpeed_023
 * @tc.desc: Test GetTouchpadPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetTouchpadPointerSpeed_023, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = 8;
    processor.SetTouchpadPointerSpeed(speed);
    int32_t newSpeed = 7;
    ASSERT_TRUE(processor.GetTouchpadPointerSpeed(newSpeed) == RET_OK);
    ASSERT_TRUE(speed == newSpeed);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetTouchpadRightClickType_024
 * @tc.desc: Test SetTouchpadRightClickType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetTouchpadRightClickType_024, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    int32_t type = 2;
    ASSERT_TRUE(processor.SetTouchpadRightClickType(type) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetTouchpadRightClickType_025
 * @tc.desc: Test GetTouchpadRightClickType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetTouchpadRightClickType_025, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    int32_t type = 1;
    processor.SetTouchpadRightClickType(type);
    int32_t newType = 3;
    ASSERT_TRUE(processor.GetTouchpadRightClickType(newType) == RET_OK);
    ASSERT_TRUE(type == newType);
}
}
}