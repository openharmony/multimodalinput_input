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
#include <gmock/gmock.h>

#include "libinput_mock.h"
#include "define_multimodal.h"
#include "tablet_tool_tranform_processor.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TabletToolTranformProcessorTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

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
}
}