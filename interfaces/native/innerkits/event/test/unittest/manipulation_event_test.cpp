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

#include "manipulation_event.h"
#include "mmi_point.h"

#include <gtest/gtest.h>

namespace OHOS {
using namespace testing::ext;

class ManipulationEventTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ManipulationEventTest::SetUpTestCase() {}

void ManipulationEventTest::TearDownTestCase() {}

void ManipulationEventTest::SetUp() {}

void ManipulationEventTest::TearDown() {}

/**
 * @tc.name: ManipulationEventTest_GetStartTime_001
 * @tc.desc:get start time.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(ManipulationEventTest,
        ManipulationEventTest_GetStartTime_001, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    ManipulationProperty manipulationProperty;
    ManipulationEvent event;
    manipulationProperty.startTime = 100;
    event.Initialize(multiProperty, manipulationProperty);

    EXPECT_EQ(100, event.GetStartTime());
}

/**
 * @tc.name: ManipulationEventTest_GetPhase_002
 * @tc.desc:get phase.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(ManipulationEventTest,
        ManipulationEventTest_GetPhase_002, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    ManipulationProperty manipulationProperty;
    ManipulationEvent event;
    manipulationProperty.operationState = 100;
    event.Initialize(multiProperty, manipulationProperty);

    EXPECT_EQ(100, event.GetPhase());
}

/**
 * @tc.name: ManipulationEventTest_GetPointerPosition_003
 * @tc.desc:get phase.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(ManipulationEventTest,
        ManipulationEventTest_GetPointerPosition_003, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    ManipulationProperty manipulationProperty;
    ManipulationEvent event;
    MmiPoint mp(200, 100);
    manipulationProperty.offsetX = 100;
    manipulationProperty.offsetY = 50;
    manipulationProperty.mp = mp;
    event.Initialize(multiProperty, manipulationProperty);

    EXPECT_EQ(100.0, event.GetPointerPosition(0).GetX());
    EXPECT_EQ(50.0, event.GetPointerPosition(0).GetY());
}
} // namespace OHOS
