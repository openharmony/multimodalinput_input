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

#include "touch_event.h"
#include <gtest/gtest.h>
#include "event_factory.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MMI;

class TouchEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

TouchEvent g_touchEvent;
HWTEST_F(TouchEventTest, Initialize_tmp_F, TestSize.Level1)
{
    TouchEvent touchEventTmp;
    touchEventTmp.Initialize(touchEventTmp);
}

HWTEST_F(TouchEventTest, setMultimodalEvent, TestSize.Level1)
{
    MultimodalEventPtr touchEventPtr = EventFactory::CreateEvent(EventType::EVENT_TOUCH);
    g_touchEvent.setMultimodalEvent(touchEventPtr);
}

HWTEST_F(TouchEventTest, GetAction_F, TestSize.Level1)
{
    int32_t retResult = g_touchEvent.GetAction();
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(TouchEventTest, GetIndex_F, TestSize.Level1)
{
    int32_t retResult = g_touchEvent.GetIndex();
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(TouchEventTest, GetForcePrecision_F, TestSize.Level1)
{
    float retResult = g_touchEvent.GetForcePrecision();
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(TouchEventTest, GetMaxForce_F, TestSize.Level1)
{
    float retResult = g_touchEvent.GetMaxForce();
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(TouchEventTest, GetTapCount_F, TestSize.Level1)
{
    float retResult = g_touchEvent.GetTapCount();
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(TouchEventTest, GetMultimodalEvent_F, TestSize.Level1)
{
    auto retResult = g_touchEvent.GetMultimodalEvent();
    EXPECT_TRUE(retResult != nullptr);
}

HWTEST_F(TouchEventTest, Initialize_tmp_L, TestSize.Level1)
{
    TouchEvent touchEventTmp;
    touchEventTmp.Initialize(g_touchEvent);
}

HWTEST_F(TouchEventTest, GetAction_L, TestSize.Level1)
{
    int32_t retResult = g_touchEvent.GetAction();
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(TouchEventTest, GetIndex_L, TestSize.Level1)
{
    int32_t retResult = g_touchEvent.GetIndex();
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(TouchEventTest, GetForcePrecision_L, TestSize.Level1)
{
    float retResult = g_touchEvent.GetForcePrecision();
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(TouchEventTest, GetMaxForce_L, TestSize.Level1)
{
    float retResult = g_touchEvent.GetMaxForce();
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(TouchEventTest, GetTapCount_L, TestSize.Level1)
{
    float retResult = g_touchEvent.GetTapCount();
    EXPECT_EQ(retResult, 0);
}

HWTEST_F(TouchEventTest, GetMultimodalEvent_L, TestSize.Level1)
{
    auto retResult = g_touchEvent.GetMultimodalEvent();
    EXPECT_TRUE(retResult != nullptr);
}
} // namespace
