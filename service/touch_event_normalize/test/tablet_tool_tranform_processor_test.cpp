/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "define_multimodal.h"
#include "tablet_tool_tranform_processor.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class TabletToolTranformProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TabletToolTranformProcessorTest::SetUpTestCase(void)
{
}

void TabletToolTranformProcessorTest::TearDownTestCase(void)
{
}

void TabletToolTranformProcessorTest::SetUp()
{
}

void TabletToolTranformProcessorTest::TearDown()
{
}

/**
 * @tc.name: TabletToolTranformProcessorTest_AxisEvent
 * @tc.desc: Test AxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, OnEvent_AxisEvent, TestSize.Level1)
{
    int32_t deviceID = 1;
    TabletToolTransformProcessor processor(deviceID);
    libinput_event* event = nullptr;
    auto type = libinput_event_get_type(event);
    type = LIBINPUT_EVENT_TABLET_TOOL_AXIS;
    auto result = processor.OnEvent(event);
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ProximityEvent
 * @tc.desc: Test ProximityEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, OnEvent_ProximityEvent, TestSize.Level1)
{
    int32_t deviceID = 1;
    TabletToolTransformProcessor processor(deviceID);
    libinput_event* event = nullptr;
    auto type = libinput_event_get_type(event);
    type = LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY;
    auto result = processor.OnEvent(event);
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_TipEvent
 * @tc.desc: Test TipEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, OnEvent_TipEvent, TestSize.Level1)
{
    int32_t deviceID = 1;
    TabletToolTransformProcessor processor(deviceID);
    libinput_event* event = nullptr;
    auto type = libinput_event_get_type(event);
    type = LIBINPUT_EVENT_TABLET_TOOL_TIP;
    auto result = processor.OnEvent(event);
    ASSERT_EQ(result, nullptr);
}
}
}