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
#include <gtest/gtest.h>
#include "manipulation_event.h"
#include "mmi_point.h"

namespace {
using namespace testing::ext;
using namespace OHOS;

class ManipulationEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

ManipulationEvent maniPulationEvent;
HWTEST_F(ManipulationEventTest, Initialize_003, TestSize.Level1)
{
    ManipulationEvent maniPulationEventTmp;
    maniPulationEventTmp.Initialize(maniPulationEvent);
}

HWTEST_F(ManipulationEventTest, GetStartTime_001, TestSize.Level1)
{
    int32_t retResult = maniPulationEvent.GetStartTime();
    EXPECT_EQ(0, retResult);
}

HWTEST_F(ManipulationEventTest, GetStartTime_002, TestSize.Level1)
{
    int32_t retResult = maniPulationEvent.GetStartTime();
    EXPECT_NE(2, retResult);
}

HWTEST_F(ManipulationEventTest, GetPhase_001, TestSize.Level1)
{
    int32_t retResult = maniPulationEvent.GetPhase();
    EXPECT_EQ(0, retResult);
}

HWTEST_F(ManipulationEventTest, GetPhase_002, TestSize.Level1)
{
    int32_t retResult = maniPulationEvent.GetPhase();
    EXPECT_NE(2, retResult);
}

HWTEST_F(ManipulationEventTest, GetPointerPosition_001, TestSize.Level1)
{
    MmiPoint tmpMultiPoint(1, 1, 1);
    MmiPoint retResult = maniPulationEvent.GetPointerPosition(0);
    EXPECT_NE(tmpMultiPoint.GetX(), retResult.GetX());
}

HWTEST_F(ManipulationEventTest, GetPointerPosition_002, TestSize.Level1)
{
    MmiPoint tmpMultiPoint(1, 1, 1);
    MmiPoint retResult = maniPulationEvent.GetPointerPosition(1);
    EXPECT_NE(tmpMultiPoint.GetX(), retResult.GetX());
}

HWTEST_F(ManipulationEventTest, SetScreenOffset, TestSize.Level1)
{
    maniPulationEvent.SetScreenOffset(3, 3);
}

HWTEST_F(ManipulationEventTest, GetPointerScreenPosition_001, TestSize.Level1)
{
    MmiPoint tmpMultiPoint(3, 3, 3);
    MmiPoint retResult = maniPulationEvent.GetPointerScreenPosition(0);
    EXPECT_NE(tmpMultiPoint.GetX(), retResult.GetX());
}

HWTEST_F(ManipulationEventTest, GetPointerScreenPosition_002, TestSize.Level1)
{
    MmiPoint tmpMultiPoint(3, 3, 3);
    MmiPoint retResult = maniPulationEvent.GetPointerScreenPosition(1);
    EXPECT_NE(tmpMultiPoint.GetX(), retResult.GetX());
}

HWTEST_F(ManipulationEventTest, GetPointerScreenPosition_003, TestSize.Level1)
{
    MmiPoint tmpMultiPoint(3, 3, 3);
    MmiPoint retResult = maniPulationEvent.GetPointerScreenPosition(0);
    EXPECT_NE(tmpMultiPoint.GetY(), retResult.GetY());
}

HWTEST_F(ManipulationEventTest, GetPointerScreenPosition_004, TestSize.Level1)
{
    MmiPoint tmpMultiPoint(3, 3, 3);
    MmiPoint retResult = maniPulationEvent.GetPointerScreenPosition(0);
    EXPECT_NE(tmpMultiPoint.GetZ(), retResult.GetZ());
}

HWTEST_F(ManipulationEventTest, GetPointerScreenPosition_005, TestSize.Level1)
{
    MmiPoint tmpMultiPoint(4, 4, 4);
    MmiPoint retResult = maniPulationEvent.GetPointerScreenPosition(1);
    EXPECT_NE(tmpMultiPoint.GetX(), retResult.GetX());
}

HWTEST_F(ManipulationEventTest, GetPointerScreenPosition_006, TestSize.Level1)
{
    MmiPoint tmpMultiPoint(4, 4, 4);
    MmiPoint retResult = maniPulationEvent.GetPointerScreenPosition(0);
    EXPECT_NE(tmpMultiPoint.GetY(), retResult.GetY());
}

HWTEST_F(ManipulationEventTest, GetPointerScreenPosition_007, TestSize.Level1)
{
    MmiPoint tmpMultiPoint(4, 4, 4);
    MmiPoint retResult = maniPulationEvent.GetPointerScreenPosition(0);
    EXPECT_NE(tmpMultiPoint.GetZ(), retResult.GetZ());
}

HWTEST_F(ManipulationEventTest, GetPointerCount_001, TestSize.Level1)
{
    int32_t retResult = maniPulationEvent.GetPointerCount();
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(ManipulationEventTest, GetPointerCount_002, TestSize.Level1)
{
    int32_t retResult = maniPulationEvent.GetPointerCount();
    EXPECT_NE(retResult, 2);
}

HWTEST_F(ManipulationEventTest, GetPointerId_001, TestSize.Level1)
{
    int32_t retResult = maniPulationEvent.GetPointerId(0);
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(ManipulationEventTest, GetPointerId_002, TestSize.Level1)
{
    int32_t retResult = maniPulationEvent.GetPointerId(1);
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(ManipulationEventTest, GetForce_001, TestSize.Level1)
{
    float retResult = maniPulationEvent.GetForce(0);
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(ManipulationEventTest, GetForce_002, TestSize.Level1)
{
    float retResult = maniPulationEvent.GetForce(1);
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(ManipulationEventTest, GetRadius_001, TestSize.Level1)
{
    float retResult = maniPulationEvent.GetRadius(0);
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(ManipulationEventTest, GetRadius_002, TestSize.Level1)
{
    float retResult = maniPulationEvent.GetRadius(1);
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(ManipulationEventTest, GetPointerCount_L_001, TestSize.Level1)
{
    int32_t retResult = maniPulationEvent.GetPointerCount();
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(ManipulationEventTest, GetPointerCount_L_002, TestSize.Level1)
{
    int32_t retResult = maniPulationEvent.GetPointerCount();
    EXPECT_NE(retResult, 1);
}

HWTEST_F(ManipulationEventTest, GetPointerId_L_001, TestSize.Level1)
{
    int32_t retResult = maniPulationEvent.GetPointerId(0);
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(ManipulationEventTest, GetPointerId_L_002, TestSize.Level1)
{
    int32_t retResult = maniPulationEvent.GetPointerId(1);
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(ManipulationEventTest, GetForce_L_001, TestSize.Level1)
{
    float retResult = maniPulationEvent.GetForce(0);
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(ManipulationEventTest, GetForce_L_002, TestSize.Level1)
{
    float retResult = maniPulationEvent.GetForce(1);
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(ManipulationEventTest, GetRadius_L_001, TestSize.Level1)
{
    float retResult = maniPulationEvent.GetRadius(0);
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(ManipulationEventTest, GetRadius_L_002, TestSize.Level1)
{
    float retResult = maniPulationEvent.GetRadius(1);
    EXPECT_EQ(retResult, 0);
}
} // namespace
