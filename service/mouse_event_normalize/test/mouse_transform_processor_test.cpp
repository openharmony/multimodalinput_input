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
    MouseTransformProcessor processor(0);
    processor.GetPointerEvent();
    processor.InitAbsolution();
    processor.OnDisplayLost(0);
}

/**
 * @tc.name: MouseTransformProcessorTest_Dump_002
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_Dump_002, TestSize.Level1)
{
    std::vector<std::string> args = {};
    std::vector<std::string> idNames = {};
    MouseTransformProcessor processor(0);
    processor.Dump(0, args);
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
    bool idNames = false;
    MouseTransformProcessor processor(0);
    ASSERT_EQ(processor.NormalizeMoveMouse(0, 0), idNames);
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
    MouseTransformProcessor processor(0);
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
    MouseTransformProcessor processor(0);
    ASSERT_EQ(processor.SetPointerSpeed(5), idNames);
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
    MouseTransformProcessor processor(0);
    processor.SetPointerSpeed(5);
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
    double gain = 0;
    bool idNames = false;
    MouseTransformProcessor processor(0);
    ASSERT_EQ(processor.GetSpeedGain(0, gain), idNames);
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
    MouseTransformProcessor processor(0);
    ASSERT_EQ(processor.SetPointerLocation(0, 0), idNames);
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
    MouseTransformProcessor processor(1);
    ASSERT_EQ(processor.GetSpeed(), idNames);

    idNames = 5;
    processor.SetConfigPointerSpeed(0);
    processor.SetConfigPointerSpeed(6);
    processor.SetConfigPointerSpeed(15);
    ASSERT_EQ(processor.GetSpeed(), idNames);
}
}
}