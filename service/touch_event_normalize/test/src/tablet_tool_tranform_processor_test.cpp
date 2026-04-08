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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "input_device_manager.h"
#include "input_windows_manager_mock.h"
#include "libinput_mock.h"
#include "tablet_tool_tranform_processor.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TabletToolTranformProcessorTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

namespace {
// Screen dimensions (pixels)
constexpr int32_t SCREEN_WIDTH_LANDSCAPE { 1920 };
constexpr int32_t SCREEN_HEIGHT_LANDSCAPE { 1080 };
constexpr int32_t SCREEN_WIDTH_PORTRAIT { 1080 };
constexpr int32_t SCREEN_HEIGHT_PORTRAIT { 1920 };

// Tablet dimensions (device units)
constexpr double TABLET_WIDTH_LANDSCAPE { 20000.0 };
constexpr double TABLET_HEIGHT_LANDSCAPE { 10000.0 };
constexpr double TABLET_WIDTH_PORTRAIT { 4000.0 };
constexpr double TABLET_HEIGHT_PORTRAIT { 20000.0 };

// Tablet coordinate offsets
constexpr double TABLET_OFFSET_X { 500.0 };
constexpr double TABLET_OFFSET_Y { 200.0 };

// Large tablet dimensions
constexpr double TABLET_WIDTH_LARGE { 30000.0 };
constexpr double TABLET_HEIGHT_LARGE { 15000.0 };
constexpr double TABLET_HEIGHT_EXTRA_LARGE { 25000.0 };

// Proportional tablet dimensions (matching screen ratio)
constexpr double TABLET_WIDTH_PROPORTIONAL { 19200.0 };
constexpr double TABLET_HEIGHT_PROPORTIONAL { 10800.0 };

// Precision tolerance for floating point comparisons
constexpr double PRECISION_TOLERANCE { 0.001 };

// Device IDs for testing
constexpr int32_t TEST_DEVICE_ID_BASE { 28 };
constexpr int32_t TEST_DISPLAY_ID_LANDSCAPE { 1 };
constexpr int32_t TEST_DISPLAY_ID_PORTRAIT { 0 };
} // namespace

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
 * @tc.name: TabletToolTranformProcessorTest_OnEvent_001
 * @tc.desc: Verify that TabletToolTranformProcessor can correctly handle events when receive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event *event = nullptr;
    std::shared_ptr<PointerEvent> ret = processor.OnEvent(event);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTip_001
 * @tc.desc: Tablet tool transformation processor test, testing under the tip function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTip_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event_tablet_tool event {};

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillOnce(Return(&event));
    EXPECT_CALL(libinputMock, TabletToolGetTipState).WillOnce(Return(LIBINPUT_TABLET_TOOL_TIP_DOWN));
    processor.pointerEvent_ = PointerEvent::Create();
    bool ret = processor.OnTip(&event.base);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipDown_001
 * @tc.desc: Test the OnTipDown method in the TabletToolTranformProcessor class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipDown_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event_tablet_tool *event = nullptr;
    bool ret = processor.OnTipDown(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipDown_002
 * @tc.desc: Test the OnTipDown method in the TabletToolTranformProcessor class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipDown_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event_tablet_tool event = {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    processor.pointerEvent_ = PointerEvent::Create();
    EXPECT_NO_FATAL_FAILURE(processor.OnTipDown(&event));
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipDown_003
 * @tc.desc: Test the OnTipDown method in the TabletToolTranformProcessor class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipDown_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event_tablet_tool event = {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    processor.pointerEvent_ = PointerEvent::Create();
    PointerEvent::PointerItem pointerItem = {};
    pointerItem.SetPointerId(0);
    processor.pointerEvent_->AddPointerItem(pointerItem);
    EXPECT_NO_FATAL_FAILURE(processor.OnTipDown(&event));
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipDown_004
 * @tc.desc: Test the OnTipDown method in the TabletToolTranformProcessor class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipDown_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    EXPECT_CALL(*WIN_MGR_MOCK, CalculateTipPoint).WillOnce(Return(true));
    TabletToolTransformProcessor processor(deviceId);
    libinput_event_tablet_tool event = {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    processor.pointerEvent_ = PointerEvent::Create();
    EXPECT_TRUE(processor.OnTipDown(&event));
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipMotion_001
 * @tc.desc: Test the response of TabletToolTranformProcessor when the tip is moving
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipMotion_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event *event = nullptr;
    bool ret = processor.OnTipMotion(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipMotion_002
 * @tc.desc: Test the function OnTipMotion in TabletToolTranformProcessorTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipMotion_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event event = {};
    processor.pointerEvent_ = PointerEvent::Create();
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_event_tablet_tool eventTabletTool = {};
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillOnce(Return(&eventTabletTool));
    EXPECT_NO_FATAL_FAILURE(processor.OnTipMotion(&event));
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipMotion_003
 * @tc.desc: Test the function OnTipMotion in TabletToolTranformProcessorTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipMotion_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*WIN_MGR_MOCK, CalculateTipPoint).WillOnce(Return(true));
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event event = {};
    processor.pointerEvent_ = PointerEvent::Create();
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_event_tablet_tool eventTabletTool = {};
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillOnce(Return(&eventTabletTool));
    EXPECT_TRUE(processor.OnTipMotion(&event));
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipMotion_004
 * @tc.desc: Test the function OnTipMotion in TabletToolTranformProcessorTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipMotion_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*WIN_MGR_MOCK, CalculateTipPoint).WillOnce(Return(true));
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event event = {};
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(processor.pointerEvent_, nullptr);
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_event_tablet_tool eventTabletTool = {};
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillOnce(Return(&eventTabletTool));
    EXPECT_CALL(libinputMock, TabletToolGetTipState).WillOnce(Return(LIBINPUT_TABLET_TOOL_TIP_DOWN));
    EXPECT_TRUE(processor.OnTipMotion(&event));
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipProximity_001
 * @tc.desc: Test the function TabletToolTranformProcessorTest_OnTipProximity_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipProximity_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event *event = nullptr;
    bool ret = processor.OnTipProximity(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: DrawTouchGraphicIdle_005
 * @tc.desc: Test the function TabletToolTransformProcessor::DrawTouchGraphicIdle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, DrawTouchGraphicIdle_005, TestSize.Level1)
{
    EXPECT_CALL(*WIN_MGR_MOCK, DrawTouchGraphic).Times(Exactly(1));
 
    int32_t deviceId { 2 };
    TabletToolTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(processor.pointerEvent_, nullptr);
    processor.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_LEVITATE_MOVE);
    EXPECT_NO_FATAL_FAILURE(processor.DrawTouchGraphicIdle());
    EXPECT_EQ(processor.pointerEvent_->GetPointerAction(), PointerEvent::POINTER_ACTION_LEVITATE_MOVE);
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipProximity_002
 * @tc.desc: Test the function TabletToolTranformProcessorTest_OnTipProximity_002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipProximity_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event event = {};
    event.type = LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY;
    libinput_event_tablet_tool eventTabletTool {};
    eventTabletTool.base = event;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillOnce(Return(&eventTabletTool));
    EXPECT_CALL(libinputMock, TabletToolGetProximityState).WillOnce(
        Return(libinput_tablet_tool_proximity_state::LIBINPUT_TABLET_TOOL_PROXIMITY_STATE_OUT));
    processor.pointerEvent_ = PointerEvent::Create();
    EXPECT_FALSE(processor.OnTipProximity(&event));
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipProximity_003
 * @tc.desc: Test the function TabletToolTranformProcessorTest_OnTipProximity_003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipProximity_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*WIN_MGR_MOCK, CalculateTipPoint).WillOnce(Return(true));
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event event = {};
    event.type = LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY;
    libinput_event_tablet_tool eventTabletTool {};
    eventTabletTool.base = event;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillOnce(Return(&eventTabletTool));
    EXPECT_CALL(libinputMock, TabletToolGetProximityState).WillOnce(
        Return(libinput_tablet_tool_proximity_state::LIBINPUT_TABLET_TOOL_PROXIMITY_STATE_OUT));
    processor.pointerEvent_ = PointerEvent::Create();
    EXPECT_TRUE(processor.OnTipProximity(&event));
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipUp_001
 * @tc.desc: Test case for the OnTipUp method of the TabletToolTranformProcessor class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipUp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event_tablet_tool *event = nullptr;
    bool ret = processor.OnTipUp(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_GetToolType_01
 * @tc.desc: Tablet tool transformation processor test, testing under the tip function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_GetToolType_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, TabletToolGetToolType).WillOnce(Return(1));
    libinput_event_tablet_tool* tabletEvent = nullptr;
    int32_t ret = processor.GetToolType(tabletEvent);
    EXPECT_EQ(ret, PointerEvent::TOOL_TYPE_PEN);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_GetToolType_02
 * @tc.desc: Tablet tool transformation processor test, testing under the tip function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_GetToolType_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    libinput_event_tablet_tool* tabletEvent = nullptr;
    TabletToolTransformProcessor processor(deviceId);
    libinput_tablet_tool event {};

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, TabletToolGetToolType).WillOnce(Return(0));
    EXPECT_CALL(libinputMock, TabletToolGetTool).WillOnce(Return(&event));
    EXPECT_CALL(libinputMock, TabletToolGetType).WillOnce(Return(LIBINPUT_TABLET_TOOL_TYPE_PEN));

    int32_t ret = processor.GetToolType(tabletEvent);
    EXPECT_EQ(ret, PointerEvent::TOOL_TYPE_PEN);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_GetToolType_03
 * @tc.desc: Tablet tool transformation processor test, testing under the tip function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_GetToolType_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    libinput_event_tablet_tool* tabletEvent = nullptr;
    TabletToolTransformProcessor processor(deviceId);
    libinput_tablet_tool event {};

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, TabletToolGetToolType).WillOnce(Return(0));
    EXPECT_CALL(libinputMock, TabletToolGetTool).WillOnce(Return(&event));
    EXPECT_CALL(libinputMock, TabletToolGetType).WillOnce(Return(LIBINPUT_TABLET_TOOL_TYPE_ERASER));

    int32_t ret = processor.GetToolType(tabletEvent);
    EXPECT_EQ(ret, PointerEvent::TOOL_TYPE_RUBBER);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_GetToolType_04
 * @tc.desc: Tablet tool transformation processor test, testing under the tip function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_GetToolType_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    libinput_event_tablet_tool* tabletEvent = nullptr;
    TabletToolTransformProcessor processor(deviceId);
    libinput_tablet_tool event {};

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, TabletToolGetToolType).WillOnce(Return(0));
    EXPECT_CALL(libinputMock, TabletToolGetTool).WillOnce(Return(&event));
    EXPECT_CALL(libinputMock, TabletToolGetType).WillOnce(Return(LIBINPUT_TABLET_TOOL_TYPE_BRUSH));

    int32_t ret = processor.GetToolType(tabletEvent);
    EXPECT_EQ(ret, PointerEvent::TOOL_TYPE_BRUSH);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_GetToolType_05
 * @tc.desc: Tablet tool transformation processor test, testing under the tip function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_GetToolType_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    libinput_event_tablet_tool* tabletEvent = nullptr;
    TabletToolTransformProcessor processor(deviceId);
    libinput_tablet_tool event {};

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, TabletToolGetToolType).WillOnce(Return(0));
    EXPECT_CALL(libinputMock, TabletToolGetTool).WillOnce(Return(&event));
    EXPECT_CALL(libinputMock, TabletToolGetType).WillOnce(Return(LIBINPUT_TABLET_TOOL_TYPE_PENCIL));

    int32_t ret = processor.GetToolType(tabletEvent);
    EXPECT_EQ(ret, PointerEvent::TOOL_TYPE_PENCIL);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_GetToolType_06
 * @tc.desc: Tablet tool transformation processor test, testing under the tip function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_GetToolType_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    libinput_event_tablet_tool* tabletEvent = nullptr;
    TabletToolTransformProcessor processor(deviceId);
    libinput_tablet_tool event {};

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, TabletToolGetToolType).WillOnce(Return(0));
    EXPECT_CALL(libinputMock, TabletToolGetTool).WillOnce(Return(&event));
    EXPECT_CALL(libinputMock, TabletToolGetType).WillOnce(Return(LIBINPUT_TABLET_TOOL_TYPE_AIRBRUSH));

    int32_t ret = processor.GetToolType(tabletEvent);
    EXPECT_EQ(ret, PointerEvent::TOOL_TYPE_AIRBRUSH);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_GetToolType_07
 * @tc.desc: Tablet tool transformation processor test, testing under the tip function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_GetToolType_07, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    libinput_event_tablet_tool* tabletEvent = nullptr;
    TabletToolTransformProcessor processor(deviceId);
    libinput_tablet_tool event {};

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, TabletToolGetToolType).WillOnce(Return(0));
    EXPECT_CALL(libinputMock, TabletToolGetTool).WillOnce(Return(&event));
    EXPECT_CALL(libinputMock, TabletToolGetType).WillOnce(Return(LIBINPUT_TABLET_TOOL_TYPE_MOUSE));

    int32_t ret = processor.GetToolType(tabletEvent);
    EXPECT_EQ(ret, PointerEvent::TOOL_TYPE_MOUSE);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_GetToolType_08
 * @tc.desc: Tablet tool transformation processor test, testing under the tip function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_GetToolType_08, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    libinput_event_tablet_tool* tabletEvent = nullptr;
    TabletToolTransformProcessor processor(deviceId);
    libinput_tablet_tool event {};

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, TabletToolGetToolType).WillOnce(Return(0));
    EXPECT_CALL(libinputMock, TabletToolGetTool).WillOnce(Return(&event));
    EXPECT_CALL(libinputMock, TabletToolGetType).WillOnce(Return(LIBINPUT_TABLET_TOOL_TYPE_LENS));

    int32_t ret = processor.GetToolType(tabletEvent);
    EXPECT_EQ(ret, PointerEvent::TOOL_TYPE_LENS);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnEvent_002
 * @tc.desc: Test the function OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnEvent_002, TestSize.Level1)
{
    int32_t deviceId = 2;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event_tablet_tool event {};

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_TABLET_TOOL_AXIS));

    auto pointerEvent = processor.OnEvent(&event.base);
    ASSERT_TRUE(pointerEvent == nullptr);
}

/**
 * @tc.name: DrawTouchGraphicDrawing_006
 * @tc.desc: Test the function DrawTouchGraphicDrawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, DrawTouchGraphicDrawing_006, TestSize.Level1)
{
    EXPECT_CALL(*WIN_MGR_MOCK, DrawTouchGraphic).Times(Exactly(2));
    int32_t deviceId { 2 };
    TabletToolTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(processor.pointerEvent_, nullptr);
    processor.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    EXPECT_NO_FATAL_FAILURE(processor.DrawTouchGraphicDrawing());

    int32_t pointerId = 1;
    PointerEvent::PointerItem item {};
    item.SetPressed(false);
    item.SetPointerId(pointerId);
    processor.pointerEvent_->RemoveAllPointerItems();
    processor.pointerEvent_->UpdatePointerItem(pointerId, item);
    EXPECT_NO_FATAL_FAILURE(processor.DrawTouchGraphicDrawing());
    EXPECT_EQ(processor.pointerEvent_->GetPointerAction(), PointerEvent::POINTER_ACTION_MOVE);
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: DrawTouchGraphicDrawing_007
 * @tc.desc: Test the function TabletToolTransformProcessor::DrawTouchGraphicDrawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, DrawTouchGraphicDrawing_007, TestSize.Level1)
{
    EXPECT_CALL(*WIN_MGR_MOCK, DrawTouchGraphic).Times(Exactly(1));
 
    int32_t deviceId { 2 };
    TabletToolTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(processor.pointerEvent_, nullptr);
    processor.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_LEVITATE_MOVE);
    EXPECT_NO_FATAL_FAILURE(processor.DrawTouchGraphicDrawing());
    EXPECT_EQ(processor.pointerEvent_->GetPointerAction(), PointerEvent::POINTER_ACTION_LEVITATE_MOVE);
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TabletToolTranformProcessorTest_IsTabletPointer_001
 * @tc.desc: Test IsTabletPointer when device is a pointer device (mouse)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_IsTabletPointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 6 };
    auto mockDev = std::make_shared<InputDeviceManagerMock::HiddenInputDevice>();
    EXPECT_CALL(*mockDev, IsMouse()).WillOnce(Return(true));
    InputDeviceManagerMock::GetInstance()->AddInputDevice(deviceId, mockDev);

    TabletToolTransformProcessor processor(deviceId);
    EXPECT_TRUE(processor.IsTabletPointer());
    InputDeviceManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TabletToolTranformProcessorTest_InitializeCalibration_001
 * @tc.desc: Test InitializeCalibration with null device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_InitializeCalibration_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 6 };
    int32_t displayId { 0 };
    TabletToolTransformProcessor processor(deviceId);
    EXPECT_FALSE(processor.InitializeCalibration(nullptr, displayId));
}

/**
 * @tc.name: TabletToolTranformProcessorTest_InitializeCalibration_002
 * @tc.desc: Test InitializeCalibration with null display info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_InitializeCalibration_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*WIN_MGR_MOCK, GetPhysicalDisplay(_)).WillOnce(Return(nullptr));

    int32_t deviceId { 6 };
    int32_t displayId { 0 };
    TabletToolTransformProcessor processor(deviceId);
    libinput_device rawDev {};
    EXPECT_FALSE(processor.InitializeCalibration(&rawDev, displayId));
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TabletToolTranformProcessorTest_InitializeCalibration_003
 * @tc.desc: Test InitializeCalibration with calibration disabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_InitializeCalibration_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId { 0 };
    int32_t displayWidth { 1920 };
    int32_t displayHeight { 1080 };
    OLD::DisplayInfo displayInfo {
        .id = displayId,
        .validWidth = displayWidth,
        .validHeight = displayHeight,
        .direction = Direction::DIRECTION0,
    };
    EXPECT_CALL(*WIN_MGR_MOCK, GetPhysicalDisplay(_)).WillOnce(Return(&displayInfo));
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetAxisMin).WillRepeatedly(Return(0));
    constexpr int32_t xMax { 20000 };
    constexpr int32_t yMax { 15000 };
    EXPECT_CALL(libinputMock, DeviceGetAxisMax).WillOnce(Return(xMax)).WillRepeatedly(Return(yMax));

    int32_t deviceId { 6 };
    TabletToolTransformProcessor processor(deviceId);
    libinput_device rawDev {};
    EXPECT_TRUE(processor.InitializeCalibration(&rawDev, displayId));
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TabletToolTranformProcessorTest_InitializeCalibration_004
 * @tc.desc: Test InitializeCalibration with tabletRatio > screenRatio (landscape tablet)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_InitializeCalibration_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId { 0 };
    int32_t displayWidth { 1920 };
    int32_t displayHeight { 1080 };
    OLD::DisplayInfo displayInfo {
        .id = displayId,
        .validWidth = displayWidth,
        .validHeight = displayHeight,
        .direction = Direction::DIRECTION0,
    };
    EXPECT_CALL(*WIN_MGR_MOCK, GetPhysicalDisplay(_)).WillOnce(Return(&displayInfo));
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetAxisMin).WillRepeatedly(Return(0));
    constexpr int32_t xMax { 30000 };
    constexpr int32_t yMax { 15000 };
    EXPECT_CALL(libinputMock, DeviceGetAxisMax).WillOnce(Return(xMax)).WillRepeatedly(Return(yMax));

    int32_t deviceId { 6 };
    TabletToolTransformProcessor processor(deviceId);
    libinput_device rawDev {};
    EXPECT_TRUE(processor.InitializeCalibration(&rawDev, displayId));
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TabletToolTranformProcessorTest_InitializeCalibration_005
 * @tc.desc: Test InitializeCalibration with tabletRatio < screenRatio (portrait tablet)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_InitializeCalibration_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId { 0 };
    int32_t displayWidth { 1920 };
    int32_t displayHeight { 1080 };
    OLD::DisplayInfo displayInfo {
        .id = displayId,
        .validWidth = displayWidth,
        .validHeight = displayHeight,
        .direction = Direction::DIRECTION0,
    };
    EXPECT_CALL(*WIN_MGR_MOCK, GetPhysicalDisplay(_)).WillOnce(Return(&displayInfo));
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetAxisMin).WillRepeatedly(Return(0));
    constexpr int32_t xMax { 15000 };
    constexpr int32_t yMax { 25000 };
    EXPECT_CALL(libinputMock, DeviceGetAxisMax).WillOnce(Return(xMax)).WillRepeatedly(Return(yMax));

    int32_t deviceId { 6 };
    TabletToolTransformProcessor processor(deviceId);
    libinput_device rawDev {};
    EXPECT_TRUE(processor.InitializeCalibration(&rawDev, displayId));
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TabletToolTranformProcessorTest_InitializeCalibration_006
 * @tc.desc: Test InitializeCalibration with orientation swap (landscape tablet, portrait screen)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_InitializeCalibration_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId { 0 };
    int32_t displayWidth { 1080 };
    int32_t displayHeight { 1920 };
    OLD::DisplayInfo displayInfo {
        .id = displayId,
        .validWidth = displayWidth,
        .validHeight = displayHeight,
        .direction = Direction::DIRECTION0,
    };
    EXPECT_CALL(*WIN_MGR_MOCK, GetPhysicalDisplay(_)).WillOnce(Return(&displayInfo));
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetAxisMin).WillRepeatedly(Return(0));
    constexpr int32_t xMax { 30000 };
    constexpr int32_t yMax { 15000 };
    EXPECT_CALL(libinputMock, DeviceGetAxisMax).WillOnce(Return(xMax)).WillRepeatedly(Return(yMax));

    int32_t deviceId { 6 };
    TabletToolTransformProcessor processor(deviceId);
    libinput_device rawDev {};
    EXPECT_TRUE(processor.InitializeCalibration(&rawDev, displayId));
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: CalculateCalibratedTipPoint_001
 * @tc.desc: Test CalculateCalibratedTipPoint with null tablet event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, CalculateCalibratedTipPoint_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 6 };
    TabletToolTransformProcessor processor(deviceId);
    int32_t targetDisplayId { 0 };
    PhysicalCoordinate coord {};
    PointerEvent::PointerItem pointerItem {};
    bool ret = processor.CalculateCalibratedTipPoint(nullptr, targetDisplayId, coord, pointerItem);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CalculateCalibratedTipPoint_002
 * @tc.desc: Test CalculateCalibratedTipPoint when device is not a tablet pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, CalculateCalibratedTipPoint_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 6 };
    auto mockDev = std::make_shared<InputDeviceManagerMock::HiddenInputDevice>();
    EXPECT_CALL(*mockDev, IsMouse()).WillOnce(Return(false));
    InputDeviceManagerMock::GetInstance()->AddInputDevice(deviceId, mockDev);

    TabletToolTransformProcessor processor(deviceId);
    libinput_event_tablet_tool tabletEvent {};
    int32_t targetDisplayId { 0 };
    PhysicalCoordinate coord {};
    PointerEvent::PointerItem pointerItem {};

    EXPECT_CALL(*WIN_MGR_MOCK, CalculateTipPoint).WillOnce(Return(true));

    bool ret = processor.CalculateCalibratedTipPoint(&tabletEvent, targetDisplayId, coord, pointerItem);
    EXPECT_TRUE(ret);
    InputDeviceManagerMock::ReleaseInstance();
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: CalculateCalibratedTipPoint_003
 * @tc.desc: Test CalculateCalibratedTipPoint when device is a tablet pointer but fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, CalculateCalibratedTipPoint_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 6 };
    auto mockDev = std::make_shared<InputDeviceManagerMock::HiddenInputDevice>();
    EXPECT_CALL(*mockDev, IsMouse()).WillOnce(Return(true));
    InputDeviceManagerMock::GetInstance()->AddInputDevice(deviceId, mockDev);

    TabletToolTransformProcessor processor(deviceId);
    libinput_event_tablet_tool tabletEvent {};
    int32_t targetDisplayId { 0 };
    PhysicalCoordinate coord {};
    PointerEvent::PointerItem pointerItem {};

    bool ret = processor.CalculateCalibratedTipPoint(&tabletEvent, targetDisplayId, coord, pointerItem);
    EXPECT_FALSE(ret);
    InputDeviceManagerMock::ReleaseInstance();
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TabletToolTranformProcessorTest_IsScreenChanged_001
 * @tc.desc: Test IsScreenChanged when calibration is not set (no value)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_IsScreenChanged_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 7 };
    TabletToolTransformProcessor processor(deviceId);
    int32_t currentDisplayId { 0 };
    EXPECT_FALSE(processor.IsScreenChanged(currentDisplayId));
}

/**
 * @tc.name: TabletToolTranformProcessorTest_IsScreenChanged_002
 * @tc.desc: Test IsScreenChanged when display ID changes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_IsScreenChanged_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId { 0 };
    int32_t displayWidth { 1920 };
    int32_t displayHeight { 1080 };
    OLD::DisplayInfo displayInfo {
        .id = displayId,
        .validWidth = displayWidth,
        .validHeight = displayHeight,
        .direction = Direction::DIRECTION0,
    };
    EXPECT_CALL(*WIN_MGR_MOCK, GetPhysicalDisplay(_)).WillRepeatedly(Return(&displayInfo));
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetAxisMin).WillRepeatedly(Return(0));
    constexpr int32_t xMax { 30000 };
    constexpr int32_t yMax { 15000 };
    EXPECT_CALL(libinputMock, DeviceGetAxisMax).WillOnce(Return(xMax)).WillRepeatedly(Return(yMax));

    int32_t deviceId { 7 };
    TabletToolTransformProcessor processor(deviceId);
    libinput_device rawDev {};
    EXPECT_TRUE(processor.InitializeCalibration(&rawDev, displayId));

    EXPECT_FALSE(processor.IsScreenChanged(displayId));
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TabletToolTranformProcessorTest_IsScreenChanged_003
 * @tc.desc: Test IsScreenChanged when display ID remains the same
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_IsScreenChanged_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId { 0 };
    int32_t displayWidth { 1920 };
    int32_t displayHeight { 1080 };
    OLD::DisplayInfo displayInfo {
        .id = displayId,
        .validWidth = displayWidth,
        .validHeight = displayHeight,
        .direction = Direction::DIRECTION0,
    };
    EXPECT_CALL(*WIN_MGR_MOCK, GetPhysicalDisplay(_)).WillOnce(Return(&displayInfo));
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetAxisMin).WillRepeatedly(Return(0));
    constexpr int32_t xMax { 30000 };
    constexpr int32_t yMax { 15000 };
    EXPECT_CALL(libinputMock, DeviceGetAxisMax).WillOnce(Return(xMax)).WillRepeatedly(Return(yMax));

    int32_t deviceId { 7 };
    TabletToolTransformProcessor processor(deviceId);
    libinput_device rawDev {};
    EXPECT_TRUE(processor.InitializeCalibration(&rawDev, displayId));

    displayInfo.direction = Direction::DIRECTION180;
    EXPECT_CALL(*WIN_MGR_MOCK, GetPhysicalDisplay(_)).WillRepeatedly(Return(&displayInfo));
    EXPECT_TRUE(processor.IsScreenChanged(displayId));
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: CalculateScreenCoordinateWithCalibration_001
 * @tc.desc: Test CalculateScreenCoordinateWithCalibration when tabletEvent is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, CalculateScreenCoordinateWithCalibration_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 8 };
    TabletToolTransformProcessor processor(deviceId);
    OLD::DisplayInfo displayInfo {};
    PhysicalCoordinate coord {};
    bool ret = processor.CalculateScreenCoordinateWithCalibration(nullptr, displayInfo, coord);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CalculateScreenCoordinateWithCalibration_002
 * @tc.desc: Test CalculateScreenCoordinateWithCalibration when calibration is not set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, CalculateScreenCoordinateWithCalibration_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId { 0 };
    int32_t displayWidth { 1920 };
    int32_t displayHeight { 1080 };
    OLD::DisplayInfo displayInfo {
        .id = displayId,
        .validWidth = displayWidth,
        .validHeight = displayHeight,
        .direction = Direction::DIRECTION0,
    };
    EXPECT_CALL(*WIN_MGR_MOCK, GetPhysicalDisplay(_)).WillOnce(Return(&displayInfo));
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetAxisMin).WillRepeatedly(Return(0));
    EXPECT_CALL(libinputMock, DeviceGetAxisMax).WillRepeatedly(Return(0));

    int32_t deviceId { 8 };
    TabletToolTransformProcessor processor(deviceId);
    libinput_device rawDev {};
    EXPECT_TRUE(processor.InitializeCalibration(&rawDev, displayId));

    libinput_event_tablet_tool tabletEvent {};
    PhysicalCoordinate coord {};
    bool ret = processor.CalculateScreenCoordinateWithCalibration(&tabletEvent, displayInfo, coord);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_CalculateScreenCoordinateWithCalibration_003
 * @tc.desc: Test CalculateScreenCoordinateWithCalibration when tabletWidth is zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, CalculateScreenCoordinateWithCalibration_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId { 0 };
    int32_t displayWidth { 1920 };
    int32_t displayHeight { 1080 };
    OLD::DisplayInfo displayInfo {
        .id = displayId,
        .validWidth = displayWidth,
        .validHeight = displayHeight,
        .direction = Direction::DIRECTION0,
    };
    EXPECT_CALL(*WIN_MGR_MOCK, GetPhysicalDisplay(_)).WillOnce(Return(&displayInfo));
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetAxisMin).WillRepeatedly(Return(0));
    constexpr int32_t xMax { 30000 };
    constexpr int32_t yMax { 15000 };
    EXPECT_CALL(libinputMock, DeviceGetAxisMax).WillOnce(Return(xMax)).WillRepeatedly(Return(yMax));
    double rawX { 100 };
    EXPECT_CALL(libinputMock, TabletToolGetXTransformed).WillRepeatedly(Return(rawX));
    double rawY { 200 };
    EXPECT_CALL(libinputMock, TabletToolGetYTransformed).WillRepeatedly(Return(rawY));

    int32_t deviceId { 8 };
    TabletToolTransformProcessor processor(deviceId);
    libinput_device rawDev {};
    EXPECT_TRUE(processor.InitializeCalibration(&rawDev, displayId));

    libinput_event_tablet_tool tabletEvent {};
    PhysicalCoordinate coord {};
    bool ret = processor.CalculateScreenCoordinateWithCalibration(&tabletEvent, displayInfo, coord);
    EXPECT_TRUE(ret);
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: CalculateWithCalibration_001
 * @tc.desc: Test CalculateWithCalibration with null tablet event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, CalculateWithCalibration_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 9 };
    int32_t targetDisplayId { 0 };
    PhysicalCoordinate coord {};
    TabletToolTransformProcessor processor(deviceId);
    bool ret = processor.CalculateWithCalibration(nullptr, targetDisplayId, coord);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CalculateWithCalibration_002
 * @tc.desc: Test CalculateWithCalibration with negative displayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, CalculateWithCalibration_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 9 };
    auto mockDev = std::make_shared<InputDeviceManagerMock::HiddenInputDevice>();
    libinput_device rawDev {};
    EXPECT_CALL(*mockDev, GetRawDevice()).WillRepeatedly(Return(&rawDev));
    InputDeviceManagerMock::GetInstance()->AddInputDevice(deviceId, mockDev);

    int32_t mainDisplayId { 0 };
    int32_t displayWidth { 1920 };
    int32_t displayHeight { 1080 };
    OLD::DisplayInfo displayInfo {
        .id = mainDisplayId,
        .validWidth = displayWidth,
        .validHeight = displayHeight,
        .direction = Direction::DIRECTION0,
    };

    EXPECT_CALL(*WIN_MGR_MOCK, GetMainDisplayId(_)).WillOnce(Return(mainDisplayId));
    EXPECT_CALL(*WIN_MGR_MOCK, GetPhysicalDisplay(_)).WillRepeatedly(Return(&displayInfo));

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetAxisMin).WillRepeatedly(Return(0));
    constexpr int32_t xMax { 20000 };
    constexpr int32_t yMax { 15000 };
    EXPECT_CALL(libinputMock, DeviceGetAxisMax).WillOnce(Return(xMax)).WillRepeatedly(Return(yMax));
    double rawX { 10000 };
    EXPECT_CALL(libinputMock, TabletToolGetXTransformed).WillRepeatedly(Return(rawX));
    double rawY { 7500 };
    EXPECT_CALL(libinputMock, TabletToolGetYTransformed).WillRepeatedly(Return(rawY));

    libinput_event_tablet_tool tabletEvent {};
    int32_t targetDisplayId { -1 };
    PhysicalCoordinate coord {};
    TabletToolTransformProcessor processor(deviceId);
    bool ret = processor.CalculateWithCalibration(&tabletEvent, targetDisplayId, coord);
    EXPECT_TRUE(ret);
    EXPECT_DOUBLE_EQ(targetDisplayId, mainDisplayId);
    InputDeviceManagerMock::ReleaseInstance();
    InputWindowsManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ReadTabletCalibrationConfig_001
 * @tc.desc: Test ReadTabletCalibrationConfig when jsonCfg is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, ReadTabletCalibrationConfig_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 15 };
    TabletToolTransformProcessor processor(deviceId);

    char cfgPath[] { "/etc/input/config.json" };
    bool enabled = true;
    cJSON* jsonCfg = cJSON_CreateArray();

    bool ret = processor.ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);

    EXPECT_FALSE(ret);
    cJSON_Delete(jsonCfg);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ReadTabletCalibrationConfig_002
 * @tc.desc: Test ReadTabletCalibrationConfig when TabletCalibration is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, ReadTabletCalibrationConfig_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 16 };
    TabletToolTransformProcessor processor(deviceId);

    char cfgPath[] { "/etc/input/config.json" };
    bool enabled = true;
    cJSON* jsonCfg = cJSON_CreateObject();

    bool ret = processor.ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);

    EXPECT_TRUE(ret);
    cJSON_Delete(jsonCfg);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ReadTabletCalibrationConfig_003
 * @tc.desc: Test ReadTabletCalibrationConfig when TabletCalibration is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, ReadTabletCalibrationConfig_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 17 };
    TabletToolTransformProcessor processor(deviceId);

    char cfgPath[] { "/etc/input/config.json" };
    bool enabled = true;
    cJSON* jsonCfg = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonCfg, "TabletCalibration", cJSON_CreateArray());

    bool ret = processor.ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);

    EXPECT_FALSE(ret);
    cJSON_Delete(jsonCfg);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ReadTabletCalibrationConfig_004
 * @tc.desc: Test ReadTabletCalibrationConfig when enabled field is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, ReadTabletCalibrationConfig_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 18 };
    TabletToolTransformProcessor processor(deviceId);

    char cfgPath[] { "/etc/input/config.json" };
    bool enabled = true;
    cJSON* jsonCfg = cJSON_CreateObject();
    cJSON* tabletCalibration = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonCfg, "TabletCalibration", tabletCalibration);

    bool ret = processor.ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);

    EXPECT_TRUE(ret);
    cJSON_Delete(jsonCfg);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ReadTabletCalibrationConfig_005
 * @tc.desc: Test ReadTabletCalibrationConfig when enabled is not a boolean
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, ReadTabletCalibrationConfig_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 19 };
    TabletToolTransformProcessor processor(deviceId);

    char cfgPath[] { "/etc/input/config.json" };
    bool enabled = true;
    cJSON* jsonCfg = cJSON_CreateObject();
    cJSON* tabletCalibration = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonCfg, "TabletCalibration", tabletCalibration);
    cJSON_AddItemToObject(tabletCalibration, "enabled", cJSON_CreateNumber(1));

    bool ret = processor.ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);
    EXPECT_FALSE(ret);
    cJSON_Delete(jsonCfg);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ReadTabletCalibrationConfig_006
 * @tc.desc: Test ReadTabletCalibrationConfig when enabled is set to true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, ReadTabletCalibrationConfig_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 20 };
    TabletToolTransformProcessor processor(deviceId);

    char cfgPath[] { "/etc/input/config.json" };
    bool enabled = false;
    cJSON* jsonCfg = cJSON_CreateObject();
    cJSON* tabletCalibration = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonCfg, "TabletCalibration", tabletCalibration);
    cJSON_AddItemToObject(tabletCalibration, "enabled", cJSON_CreateTrue());

    bool ret = processor.ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);

    EXPECT_TRUE(ret);
    EXPECT_TRUE(enabled);
    cJSON_Delete(jsonCfg);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ReadTabletCalibrationConfig_007
 * @tc.desc: Test ReadTabletCalibrationConfig when enabled is set to false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, ReadTabletCalibrationConfig_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 21 };
    TabletToolTransformProcessor processor(deviceId);

    char cfgPath[] { "/etc/input/config.json" };
    bool enabled = true;
    cJSON* jsonCfg = cJSON_CreateObject();
    cJSON* tabletCalibration = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonCfg, "TabletCalibration", tabletCalibration);
    cJSON_AddItemToObject(tabletCalibration, "enabled", cJSON_CreateFalse());

    bool ret = processor.ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(enabled);
    cJSON_Delete(jsonCfg);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ReadTabletCalibrationConfig_008
 * @tc.desc: Test ReadTabletCalibrationConfig with complete valid config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, ReadTabletCalibrationConfig_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 22 };
    TabletToolTransformProcessor processor(deviceId);

    const char* cfgPath = "/etc/input/input_product_config.json";
    bool enabled = false;
    cJSON* jsonCfg = cJSON_CreateObject();
    cJSON* tabletCalibration = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonCfg, "TabletCalibration", tabletCalibration);
    cJSON_AddItemToObject(tabletCalibration, "enabled", cJSON_CreateTrue());

    bool ret = processor.ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(enabled);
    cJSON_Delete(jsonCfg);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ReadTabletCalibrationConfig_009
 * @tc.desc: Test ReadTabletCalibrationConfig with enabled as string (invalid type)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, ReadTabletCalibrationConfig_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 23;
    TabletToolTransformProcessor processor(deviceId);

    const char* cfgPath = "/etc/input/config.json";
    bool enabled = true;
    cJSON* jsonCfg = cJSON_CreateObject();
    cJSON* tabletCalibration = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonCfg, "TabletCalibration", tabletCalibration);
    cJSON_AddItemToObject(tabletCalibration, "enabled", cJSON_CreateString("true"));

    bool ret = processor.ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);
    EXPECT_FALSE(ret);
    cJSON_Delete(jsonCfg);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ReadTabletCalibrationConfig_010
 * @tc.desc: Test ReadTabletCalibrationConfig with additional config fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, ReadTabletCalibrationConfig_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 24;
    TabletToolTransformProcessor processor(deviceId);

    const char* cfgPath = "/etc/input/config.json";
    bool enabled = false;
    cJSON* jsonCfg = cJSON_CreateObject();
    cJSON* tabletCalibration = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonCfg, "TabletCalibration", tabletCalibration);
    cJSON_AddItemToObject(tabletCalibration, "enabled", cJSON_CreateTrue());
    cJSON_AddItemToObject(tabletCalibration, "otherField", cJSON_CreateString("test"));

    bool ret = processor.ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(enabled);
    cJSON_Delete(jsonCfg);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ReadTabletCalibrationConfig_011
 * @tc.desc: Test ReadTabletCalibrationConfig when enabled is cJSON_False
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, ReadTabletCalibrationConfig_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 25;
    TabletToolTransformProcessor processor(deviceId);

    const char* cfgPath = "/etc/input/config.json";
    bool enabled = true;
    cJSON* jsonCfg = cJSON_CreateObject();
    cJSON* tabletCalibration = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonCfg, "TabletCalibration", tabletCalibration);
    cJSON* jsonEnabled = cJSON_CreateBool(false);
    cJSON_AddItemToObject(tabletCalibration, "enabled", jsonEnabled);

    bool ret = processor.ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(enabled);
    cJSON_Delete(jsonCfg);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ReadTabletCalibrationConfig_012
 * @tc.desc: Test ReadTabletCalibrationConfig when jsonCfg is empty object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, ReadTabletCalibrationConfig_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 26;
    TabletToolTransformProcessor processor(deviceId);

    const char* cfgPath = "/etc/input/config.json";
    bool enabled = true;
    cJSON* jsonCfg = cJSON_CreateObject();

    bool ret = processor.ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);
    EXPECT_TRUE(ret);
    cJSON_Delete(jsonCfg);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ReadTabletCalibrationConfig_013
 * @tc.desc: Test ReadTabletCalibrationConfig with nested JSON structure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, ReadTabletCalibrationConfig_013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 27;
    TabletToolTransformProcessor processor(deviceId);

    const char* cfgPath = "/etc/input/config.json";
    bool enabled = false;
    cJSON* jsonCfg = cJSON_CreateObject();
    cJSON* otherSection = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonCfg, "OtherConfig", otherSection);
    cJSON* tabletCalibration = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonCfg, "TabletCalibration", tabletCalibration);
    cJSON_AddItemToObject(tabletCalibration, "enabled", cJSON_CreateTrue());

    bool ret = processor.ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(enabled);
    cJSON_Delete(jsonCfg);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_ReadTabletCalibrationConfig_014
 * @tc.desc: Test ReadTabletCalibrationConfig with enabled field as cJSON_Null (invalid)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, ReadTabletCalibrationConfig_014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = TEST_DEVICE_ID_BASE + 0;
    TabletToolTransformProcessor processor(deviceId);

    const char* cfgPath = "/etc/input/config.json";
    bool enabled = true;
    cJSON* jsonCfg = cJSON_CreateObject();
    cJSON* tabletCalibration = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonCfg, "TabletCalibration", tabletCalibration);
    cJSON_AddItemToObject(tabletCalibration, "enabled", cJSON_CreateNull());

    bool ret = processor.ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);
    EXPECT_FALSE(ret);
    cJSON_Delete(jsonCfg);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_CalculateCalibration_001
 * @tc.desc: Test CalculateCalibration when tabletWidth is zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_CalculateCalibration_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = TEST_DEVICE_ID_BASE + 1;
    TabletToolTransformProcessor processor(deviceId);

    OLD::DisplayInfo displayInfo {};
    displayInfo.id = TEST_DISPLAY_ID_LANDSCAPE;
    displayInfo.validWidth = SCREEN_WIDTH_LANDSCAPE;
    displayInfo.validHeight = SCREEN_HEIGHT_LANDSCAPE;

    TabletToolTransformProcessor::TabletCalibration calib {};
    calib.tabletMinX = 0.0;
    calib.tabletMaxX = 0.0; // tabletWidth = 0
    calib.tabletMinY = 0.0;
    calib.tabletMaxY = TABLET_HEIGHT_LANDSCAPE;

    double origMinX = calib.calibratedMinX;
    double origMaxX = calib.calibratedMaxX;
    double origMinY = calib.calibratedMinY;
    double origMaxY = calib.calibratedMaxY;

    processor.CalculateCalibration(displayInfo, calib);

    // When tabletWidth is zero, calibration values should remain unchanged
    EXPECT_DOUBLE_EQ(calib.calibratedMinX, origMinX);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxX, origMaxX);
    EXPECT_DOUBLE_EQ(calib.calibratedMinY, origMinY);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxY, origMaxY);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_CalculateCalibration_002
 * @tc.desc: Test CalculateCalibration when tabletHeight is zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_CalculateCalibration_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = TEST_DEVICE_ID_BASE + 2;
    TabletToolTransformProcessor processor(deviceId);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = TEST_DISPLAY_ID_LANDSCAPE;
    displayInfo.validWidth = SCREEN_WIDTH_LANDSCAPE;
    displayInfo.validHeight = SCREEN_HEIGHT_LANDSCAPE;

    TabletToolTransformProcessor::TabletCalibration calib;
    calib.tabletMinX = 0.0;
    calib.tabletMaxX = TABLET_WIDTH_LANDSCAPE;
    calib.tabletMinY = 0.0;
    calib.tabletMaxY = 0.0; // tabletHeight = 0

    double origMinX = calib.calibratedMinX;
    double origMaxX = calib.calibratedMaxX;
    double origMinY = calib.calibratedMinY;
    double origMaxY = calib.calibratedMaxY;

    processor.CalculateCalibration(displayInfo, calib);

    // When tabletHeight is zero, calibration values should remain unchanged
    EXPECT_DOUBLE_EQ(calib.calibratedMinX, origMinX);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxX, origMaxX);
    EXPECT_DOUBLE_EQ(calib.calibratedMinY, origMinY);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxY, origMaxY);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_CalculateCalibration_003
 * @tc.desc: Test CalculateCalibration when screenWidth is zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_CalculateCalibration_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = TEST_DEVICE_ID_BASE + 3;
    TabletToolTransformProcessor processor(deviceId);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = TEST_DISPLAY_ID_LANDSCAPE;
    displayInfo.validWidth = 0; // screenWidth = 0
    displayInfo.validHeight = SCREEN_HEIGHT_LANDSCAPE;

    TabletToolTransformProcessor::TabletCalibration calib;
    calib.tabletMinX = 0.0;
    calib.tabletMaxX = TABLET_WIDTH_LANDSCAPE;
    calib.tabletMinY = 0.0;
    calib.tabletMaxY = TABLET_HEIGHT_LANDSCAPE;

    double origMinX = calib.calibratedMinX;
    double origMaxX = calib.calibratedMaxX;
    double origMinY = calib.calibratedMinY;
    double origMaxY = calib.calibratedMaxY;

    processor.CalculateCalibration(displayInfo, calib);

    // When screenWidth is zero, calibration values should remain unchanged
    EXPECT_DOUBLE_EQ(calib.calibratedMinX, origMinX);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxX, origMaxX);
    EXPECT_DOUBLE_EQ(calib.calibratedMinY, origMinY);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxY, origMaxY);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_CalculateCalibration_004
 * @tc.desc: Test CalculateCalibration when screenHeight is zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_CalculateCalibration_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = TEST_DEVICE_ID_BASE + 4;
    TabletToolTransformProcessor processor(deviceId);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = TEST_DISPLAY_ID_LANDSCAPE;
    displayInfo.validWidth = SCREEN_WIDTH_LANDSCAPE;
    displayInfo.validHeight = 0; // screenHeight = 0

    TabletToolTransformProcessor::TabletCalibration calib;
    calib.tabletMinX = 0.0;
    calib.tabletMaxX = TABLET_WIDTH_LANDSCAPE;
    calib.tabletMinY = 0.0;
    calib.tabletMaxY = TABLET_HEIGHT_LANDSCAPE;

    double origMinX = calib.calibratedMinX;
    double origMaxX = calib.calibratedMaxX;
    double origMinY = calib.calibratedMinY;
    double origMaxY = calib.calibratedMaxY;

    processor.CalculateCalibration(displayInfo, calib);

    // When screenHeight is zero, calibration values should remain unchanged
    EXPECT_DOUBLE_EQ(calib.calibratedMinX, origMinX);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxX, origMaxX);
    EXPECT_DOUBLE_EQ(calib.calibratedMinY, origMinY);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxY, origMaxY);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_CalculateCalibration_005
 * @tc.desc: Test CalculateCalibration with landscape tablet and landscape screen, tabletRatio > screenRatio
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_CalculateCalibration_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = TEST_DEVICE_ID_BASE + 5;
    TabletToolTransformProcessor processor(deviceId);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = TEST_DISPLAY_ID_LANDSCAPE;
    displayInfo.validWidth = SCREEN_WIDTH_LANDSCAPE;
    displayInfo.validHeight = SCREEN_HEIGHT_LANDSCAPE;

    TabletToolTransformProcessor::TabletCalibration calib;
    calib.tabletMinX = 0.0;
    calib.tabletMaxX = TABLET_WIDTH_LARGE;
    calib.tabletMinY = 0.0;
    calib.tabletMaxY = TABLET_HEIGHT_LARGE;

    processor.CalculateCalibration(displayInfo, calib);

    double tabletWidth = TABLET_WIDTH_LARGE;
    double tabletHeight = TABLET_HEIGHT_LARGE;
    double tabletRatio = tabletWidth / tabletHeight;
    double screenRatio = static_cast<double>(SCREEN_WIDTH_LANDSCAPE) / SCREEN_HEIGHT_LANDSCAPE;

    EXPECT_GT(tabletRatio, screenRatio);

    double newHeight = tabletHeight;
    double newWidth = newHeight * screenRatio;
    double expectedMinX = (tabletWidth - newWidth) / 2.0 + calib.tabletMinX;
    double expectedMaxX = expectedMinX + newWidth;

    EXPECT_DOUBLE_EQ(calib.calibratedMinY, calib.tabletMinY);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxY, calib.tabletMaxY);
    EXPECT_NEAR(calib.calibratedMinX, expectedMinX, PRECISION_TOLERANCE);
    EXPECT_NEAR(calib.calibratedMaxX, expectedMaxX, PRECISION_TOLERANCE);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_CalculateCalibration_006
 * @tc.desc: Test CalculateCalibration with portrait tablet and landscape screen (no swap needed),
 *           tabletRatio <= screenRatio
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_CalculateCalibration_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = TEST_DEVICE_ID_BASE + 6;
    TabletToolTransformProcessor processor(deviceId);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = TEST_DISPLAY_ID_PORTRAIT;
    displayInfo.validWidth = SCREEN_WIDTH_PORTRAIT;
    displayInfo.validHeight = SCREEN_HEIGHT_PORTRAIT;

    TabletToolTransformProcessor::TabletCalibration calib;
    calib.tabletMinX = 0.0;
    calib.tabletMaxX = TABLET_WIDTH_PORTRAIT;
    calib.tabletMinY = 0.0;
    calib.tabletMaxY = TABLET_HEIGHT_PORTRAIT;

    processor.CalculateCalibration(displayInfo, calib);

    double tabletWidth = TABLET_WIDTH_PORTRAIT;
    double tabletHeight = TABLET_HEIGHT_PORTRAIT;
    double tabletRatio = tabletWidth / tabletHeight;
    double screenRatio = static_cast<double>(SCREEN_WIDTH_PORTRAIT) / SCREEN_HEIGHT_PORTRAIT;

    EXPECT_LE(tabletRatio, screenRatio);

    double newWidth = tabletWidth;
    double newHeight = newWidth / screenRatio;
    double expectedMinY = (tabletHeight - newHeight) / 2.0 + calib.tabletMinY;
    double expectedMaxY = expectedMinY + newHeight;

    EXPECT_DOUBLE_EQ(calib.calibratedMinX, calib.tabletMinX);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxX, calib.tabletMaxX);
    EXPECT_NEAR(calib.calibratedMinY, expectedMinY, PRECISION_TOLERANCE);
    EXPECT_NEAR(calib.calibratedMaxY, expectedMaxY, PRECISION_TOLERANCE);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_CalculateCalibration_007
 * @tc.desc: Test CalculateCalibration with landscape tablet and portrait screen (requires swap),
 *           tabletRatio > screenRatio after swap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_CalculateCalibration_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = TEST_DEVICE_ID_BASE + 7;
    TabletToolTransformProcessor processor(deviceId);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = TEST_DISPLAY_ID_PORTRAIT;
    displayInfo.validWidth = SCREEN_WIDTH_PORTRAIT;
    displayInfo.validHeight = SCREEN_HEIGHT_PORTRAIT;

    TabletToolTransformProcessor::TabletCalibration calib;
    calib.tabletMinX = 0.0;
    calib.tabletMaxX = TABLET_WIDTH_LARGE;
    calib.tabletMinY = 0.0;
    calib.tabletMaxY = TABLET_HEIGHT_LARGE;

    processor.CalculateCalibration(displayInfo, calib);

    double tabletWidth = TABLET_WIDTH_LARGE;
    double tabletHeight = TABLET_HEIGHT_LARGE;
    double tabletRatio = tabletWidth / tabletHeight;
    // After swap: screenWidth=1920, screenHeight=1080
    double screenRatio = static_cast<double>(SCREEN_HEIGHT_PORTRAIT) / SCREEN_WIDTH_PORTRAIT;

    EXPECT_GT(tabletRatio, screenRatio);

    double newHeight = tabletHeight;
    double newWidth = newHeight * screenRatio;
    double expectedMinX = (tabletWidth - newWidth) / 2.0 + calib.tabletMinX;
    double expectedMaxX = expectedMinX + newWidth;

    EXPECT_DOUBLE_EQ(calib.calibratedMinY, calib.tabletMinY);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxY, calib.tabletMaxY);
    EXPECT_NEAR(calib.calibratedMinX, expectedMinX, PRECISION_TOLERANCE);
    EXPECT_NEAR(calib.calibratedMaxX, expectedMaxX, PRECISION_TOLERANCE);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_CalculateCalibration_008
 * @tc.desc: Test CalculateCalibration with portrait tablet and landscape screen (requires swap)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_CalculateCalibration_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = TEST_DEVICE_ID_BASE + 8;
    TabletToolTransformProcessor processor(deviceId);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = TEST_DISPLAY_ID_LANDSCAPE;
    displayInfo.validWidth = SCREEN_WIDTH_LANDSCAPE;
    displayInfo.validHeight = SCREEN_HEIGHT_LANDSCAPE;

    TabletToolTransformProcessor::TabletCalibration calib;
    calib.tabletMinX = 0.0;
    calib.tabletMaxX = TABLET_WIDTH_PORTRAIT;
    calib.tabletMinY = 0.0;
    calib.tabletMaxY = TABLET_HEIGHT_EXTRA_LARGE;

    processor.CalculateCalibration(displayInfo, calib);

    double tabletWidth = TABLET_WIDTH_PORTRAIT;
    double tabletHeight = TABLET_HEIGHT_EXTRA_LARGE;
    double tabletRatio = tabletWidth / tabletHeight;
    double screenRatio = static_cast<double>(SCREEN_HEIGHT_LANDSCAPE) / SCREEN_WIDTH_LANDSCAPE;

    EXPECT_LE(tabletRatio, screenRatio);

    double newWidth = tabletWidth;
    double newHeight = newWidth / screenRatio;
    double expectedMinY = (tabletHeight - newHeight) / 2.0 + calib.tabletMinY;
    double expectedMaxY = expectedMinY + newHeight;

    EXPECT_DOUBLE_EQ(calib.calibratedMinX, calib.tabletMinX);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxX, calib.tabletMaxX);
    EXPECT_NEAR(calib.calibratedMinY, expectedMinY, PRECISION_TOLERANCE);
    EXPECT_NEAR(calib.calibratedMaxY, expectedMaxY, PRECISION_TOLERANCE);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_CalculateCalibration_009
 * @tc.desc: Test CalculateCalibration with equal ratios (edge case)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_CalculateCalibration_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = TEST_DEVICE_ID_BASE + 9;
    TabletToolTransformProcessor processor(deviceId);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = TEST_DISPLAY_ID_PORTRAIT;
    displayInfo.validWidth = SCREEN_WIDTH_LANDSCAPE;
    displayInfo.validHeight = SCREEN_HEIGHT_LANDSCAPE;

    TabletToolTransformProcessor::TabletCalibration calib;
    calib.tabletMinX = 0.0;
    calib.tabletMaxX = TABLET_WIDTH_PROPORTIONAL;
    calib.tabletMinY = 0.0;
    calib.tabletMaxY = TABLET_HEIGHT_PROPORTIONAL;

    processor.CalculateCalibration(displayInfo, calib);

    double tabletWidth = TABLET_WIDTH_PROPORTIONAL;
    double tabletHeight = TABLET_HEIGHT_PROPORTIONAL;
    double tabletRatio = tabletWidth / tabletHeight;
    double screenRatio = static_cast<double>(SCREEN_WIDTH_LANDSCAPE) / SCREEN_HEIGHT_LANDSCAPE;

    EXPECT_DOUBLE_EQ(tabletRatio, screenRatio);

    EXPECT_DOUBLE_EQ(calib.calibratedMinX, calib.tabletMinX);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxX, calib.tabletMaxX);
    EXPECT_DOUBLE_EQ(calib.calibratedMinY, calib.tabletMinY);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxY, calib.tabletMaxY);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_CalculateCalibration_010
 * @tc.desc: Test CalculateCalibration with offset tablet coordinates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_CalculateCalibration_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = TEST_DEVICE_ID_BASE + 10;
    TabletToolTransformProcessor processor(deviceId);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = TEST_DISPLAY_ID_PORTRAIT;
    displayInfo.validWidth = SCREEN_WIDTH_LANDSCAPE;
    displayInfo.validHeight = SCREEN_HEIGHT_LANDSCAPE;

    TabletToolTransformProcessor::TabletCalibration calib;
    calib.tabletMinX = TABLET_OFFSET_X;
    calib.tabletMaxX = TABLET_OFFSET_X + TABLET_WIDTH_LANDSCAPE - TABLET_WIDTH_PORTRAIT;
    calib.tabletMinY = TABLET_OFFSET_Y;
    calib.tabletMaxY = TABLET_OFFSET_Y + TABLET_HEIGHT_LANDSCAPE * 0.8;

    processor.CalculateCalibration(displayInfo, calib);

    double tabletWidth = TABLET_WIDTH_LANDSCAPE - TABLET_WIDTH_PORTRAIT;
    double tabletHeight = TABLET_HEIGHT_LANDSCAPE * 0.8;
    double tabletRatio = tabletWidth / tabletHeight;
    double screenRatio = static_cast<double>(SCREEN_WIDTH_LANDSCAPE) / SCREEN_HEIGHT_LANDSCAPE;

    EXPECT_GT(tabletRatio, screenRatio);

    double newHeight = tabletHeight;
    double newWidth = newHeight * screenRatio;
    double expectedMinX = (tabletWidth - newWidth) / 2.0 + calib.tabletMinX;
    double expectedMaxX = expectedMinX + newWidth;

    EXPECT_DOUBLE_EQ(calib.calibratedMinY, calib.tabletMinY);
    EXPECT_DOUBLE_EQ(calib.calibratedMaxY, calib.tabletMaxY);
    EXPECT_NEAR(calib.calibratedMinX, expectedMinX, PRECISION_TOLERANCE);
    EXPECT_NEAR(calib.calibratedMaxX, expectedMaxX, PRECISION_TOLERANCE);
}
} // namespace MMI
} // namespace OHOS