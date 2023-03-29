/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
};

void MouseTransformProcessorTest::SetUpTestCase(void)
{
}

void MouseTransformProcessorTest::TearDownTestCase(void)
{
}

void MouseTransformProcessorTest::SetUp()
{
}

void MouseTransformProcessorTest::TearDown()
{
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
    processor.GetPointerEvent();
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
 * @tc.name: MouseTransformProcessorTest_GetSpeedGain_007
 * @tc.desc: Test GetSpeedGain
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetSpeedGain_007, TestSize.Level1)
{
    double vin = 0;
    double gain = 0;
    bool isGain = false;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    ASSERT_EQ(processor.GetSpeedGain(vin, gain), isGain);
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
 * @tc.name: MouseTransformProcessorTest_GetSpeed_009
 * @tc.desc: Test GetSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetSpeed_009, TestSize.Level1)
{
    int32_t idNames = 5;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(deviceId);
    ASSERT_EQ(processor.GetSpeed(), idNames);

    int32_t speed = 0;
    processor.SetConfigPointerSpeed(speed);
    speed = 6;
    processor.SetConfigPointerSpeed(speed);
    speed = 15;
    processor.SetConfigPointerSpeed(speed);
    ASSERT_EQ(processor.GetSpeed(), idNames);
}
}
}