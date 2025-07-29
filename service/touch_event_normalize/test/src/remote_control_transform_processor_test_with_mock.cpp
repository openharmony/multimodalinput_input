/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

 #include "remote_control_transform_processor.h"

 #include <gtest/gtest.h>
 #include <gmock/gmock.h>
 #include <linux/input.h>
 
 #include "libinput_mock.h"
 #include "input_windows_manager_mock.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
constexpr int32_t PRINT_INTERVAL_COUNT { 100 };
} // namespace

class RemoteControlTransformProcessorTestWithMock : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RemoteControlTransformProcessorTestWithMock::SetUpTestCase(void)
{
}

void RemoteControlTransformProcessorTestWithMock::TearDownTestCase(void)
{
}

void RemoteControlTransformProcessorTestWithMock::SetUp()
{
}

void RemoteControlTransformProcessorTestWithMock::TearDown()
{
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_InitToolTypes_001
 * @tc.desc: Test the funcation InitToolTypes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, InitToolTypes_001, TestSize.Level1)
{
    int32_t deviceId = 7;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.InitToolTypes();
    ASSERT_EQ(processor.vecToolType_.size(), 16);
    ASSERT_EQ(processor.vecToolType_[0].first, BTN_TOOL_PEN);
    ASSERT_EQ(processor.vecToolType_[0].second, PointerEvent::TOOL_TYPE_PEN);
    ASSERT_EQ(processor.vecToolType_[1].first, BTN_TOOL_RUBBER);
    ASSERT_EQ(processor.vecToolType_[1].second, PointerEvent::TOOL_TYPE_RUBBER);
    ASSERT_EQ(processor.vecToolType_[2].first, BTN_TOOL_BRUSH);
    ASSERT_EQ(processor.vecToolType_[2].second, PointerEvent::TOOL_TYPE_BRUSH);
    ASSERT_EQ(processor.vecToolType_[3].first, BTN_TOOL_PENCIL);
    ASSERT_EQ(processor.vecToolType_[3].second, PointerEvent::TOOL_TYPE_PENCIL);
    ASSERT_EQ(processor.vecToolType_[4].first, BTN_TOOL_AIRBRUSH);
    ASSERT_EQ(processor.vecToolType_[4].second, PointerEvent::TOOL_TYPE_AIRBRUSH);
    ASSERT_EQ(processor.vecToolType_[5].first, BTN_TOOL_FINGER);
    ASSERT_EQ(processor.vecToolType_[5].second, PointerEvent::TOOL_TYPE_FINGER);
    ASSERT_EQ(processor.vecToolType_[6].first, BTN_TOOL_MOUSE);
    ASSERT_EQ(processor.vecToolType_[6].second, PointerEvent::TOOL_TYPE_MOUSE);
    ASSERT_EQ(processor.vecToolType_[7].first, BTN_TOOL_LENS);
    ASSERT_EQ(processor.vecToolType_[7].second, PointerEvent::TOOL_TYPE_LENS);
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_HandlePostInner_001
 * @tc.desc: Test HandlePostInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, HandlePostInner_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = nullptr;
    EXPECT_EQ(processor.pointerEvent_, nullptr);
    libinput_event event;
    ASSERT_FALSE(processor.HandlePostInner(&event));
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_HandlePostInner_002
 * @tc.desc: Test HandlePostInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, HandlePostInner_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    EXPECT_NE(processor.pointerEvent_, nullptr);
    MouseLocation expectLocation = {3, 3, 3};
    EXPECT_CALL(*WIN_MGR_MOCK, GetMouseInfo).WillRepeatedly(Return(expectLocation));
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetTouchEvent).WillOnce(Return(NULL));
    libinput_event event;
    ASSERT_FALSE(processor.HandlePostInner(&event));
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_HandlePostInner_003
 * @tc.desc: Test HandlePostInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, HandlePostInner_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    EXPECT_NE(processor.pointerEvent_, nullptr);
    MouseLocation expectLocation = {3, 3, 3};
    EXPECT_CALL(*WIN_MGR_MOCK, GetMouseInfo).WillRepeatedly(Return(expectLocation));
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_event_touch touchEvent;
    EXPECT_CALL(libinputMock, GetTouchEvent).WillOnce(Return(&touchEvent));
    EXPECT_CALL(libinputMock, TouchEventGetPressure).WillOnce(Return(100.0));
    EXPECT_CALL(libinputMock, TouchEventGetContactLongAxis).WillOnce(Return(100));
    EXPECT_CALL(libinputMock, TouchEventGetContactShortAxis).WillOnce(Return(100));
    EXPECT_CALL(libinputMock, TouchEventGetSeatSlot).WillOnce(Return(100));
    libinput_event event;
    ASSERT_TRUE(processor.HandlePostInner(&event));
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_OnEventTouchMotion_001
 * @tc.desc: Test OnEventTouchMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, OnEventTouchMotion_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = nullptr;
    EXPECT_EQ(processor.pointerEvent_, nullptr);
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetTouchEvent).Times(0);
    libinput_event event;
    ASSERT_FALSE(processor.OnEventTouchMotion(&event));
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_OnEventTouchMotion_002
 * @tc.desc: Test OnEventTouchMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, OnEventTouchMotion_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    EXPECT_NE(processor.pointerEvent_, nullptr);
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetTouchEvent).WillOnce(Return(NULL));
    libinput_event event;
    ASSERT_FALSE(processor.OnEventTouchMotion(&event));
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_OnEventTouchMotion_003
 * @tc.desc: Test OnEventTouchMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, OnEventTouchMotion_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    EXPECT_NE(processor.pointerEvent_, nullptr);
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_event_touch touchEvent;
    EXPECT_CALL(libinputMock, GetTouchEvent).WillOnce(Return(&touchEvent));
    EXPECT_CALL(*WIN_MGR_MOCK, TouchPointToDisplayPoint).WillRepeatedly(Return(false));
    libinput_event event;
    ASSERT_FALSE(processor.OnEventTouchMotion(&event));
}


/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_OnEventTouchMotion_004
 * @tc.desc: Test OnEventTouchMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, OnEventTouchMotion_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    EXPECT_NE(processor.pointerEvent_, nullptr);
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_event_touch touchEvent;
    EXPECT_CALL(libinputMock, GetTouchEvent).WillOnce(Return(&touchEvent));
    EXPECT_CALL(*WIN_MGR_MOCK, TouchPointToDisplayPoint).WillRepeatedly(Return(true));
    libinput_event event;
    ASSERT_TRUE(processor.OnEventTouchMotion(&event));
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_OnEvent_001
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, OnEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = nullptr;
    EXPECT_EQ(processor.pointerEvent_, nullptr);
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).Times(0);
    ASSERT_EQ(processor.OnEvent(NULL), nullptr);
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_OnEvent_002
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, OnEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = nullptr;
    EXPECT_EQ(processor.pointerEvent_, nullptr);
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_TOUCH_DOWN));
    libinput_event event;
    ASSERT_EQ(processor.OnEvent(&event), processor.pointerEvent_);
    EXPECT_NE(processor.pointerEvent_, nullptr);
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_OnEvent_003
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, OnEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = nullptr;
    EXPECT_EQ(processor.pointerEvent_, nullptr);
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_TOUCH_UP));
    libinput_event event;
    ASSERT_EQ(processor.OnEvent(&event), processor.pointerEvent_);
    EXPECT_NE(processor.pointerEvent_, nullptr);
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_OnEvent_004
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, OnEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = nullptr;
    EXPECT_EQ(processor.pointerEvent_, nullptr);
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_TOUCH_CANCEL));
    libinput_event event;
    ASSERT_EQ(processor.OnEvent(&event), nullptr);
    EXPECT_NE(processor.pointerEvent_, nullptr);
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_OnEvent_005
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, OnEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = nullptr;
    EXPECT_EQ(processor.pointerEvent_, nullptr);
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_TOUCH_MOTION));
    libinput_event_touch touchEvent;
    EXPECT_CALL(libinputMock, GetTouchEvent).WillRepeatedly(Return(NULL));
    MouseLocation expectLocation = {3, 3, 3};
    EXPECT_CALL(*WIN_MGR_MOCK, GetMouseInfo).WillRepeatedly(Return(expectLocation));
    processor.processedCount_ = PRINT_INTERVAL_COUNT - 1;
    libinput_event event;
    ASSERT_EQ(processor.OnEvent(&event), nullptr);
    EXPECT_NE(processor.pointerEvent_, nullptr);
    EXPECT_EQ(processor.processedCount_, 0);
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_OnEvent_006
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, OnEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = nullptr;
    EXPECT_EQ(processor.pointerEvent_, nullptr);
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_TOUCH_MOTION));
    libinput_event_touch touchEvent;
    EXPECT_CALL(libinputMock, GetTouchEvent).WillRepeatedly(Return(&touchEvent));
    EXPECT_CALL(*WIN_MGR_MOCK, TouchPointToDisplayPoint).WillOnce(Return(true));
    MouseLocation expectLocation = {3, 3, 3};
    EXPECT_CALL(*WIN_MGR_MOCK, GetMouseInfo).WillRepeatedly(Return(expectLocation));
    EXPECT_CALL(*WIN_MGR_MOCK, UpdateTargetPointer).WillRepeatedly(Return(0));
    processor.processedCount_ = PRINT_INTERVAL_COUNT - 1;
    libinput_event event;
    ASSERT_EQ(processor.OnEvent(&event), processor.pointerEvent_);
    EXPECT_NE(processor.pointerEvent_, nullptr);
    EXPECT_EQ(processor.processedCount_, PRINT_INTERVAL_COUNT);
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_OnEvent_007
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, OnEvent_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = nullptr;
    EXPECT_EQ(processor.pointerEvent_, nullptr);
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_TOUCH_MOTION));
    libinput_event_touch touchEvent;
    EXPECT_CALL(libinputMock, GetTouchEvent).WillRepeatedly(Return(&touchEvent));
    EXPECT_CALL(*WIN_MGR_MOCK, TouchPointToDisplayPoint).WillOnce(Return(True));
    MouseLocation expectLocation = {3, 3, 3};
    EXPECT_CALL(*WIN_MGR_MOCK, GetMouseInfo).WillRepeatedly(Return(expectLocation));
    EXPECT_CALL(*WIN_MGR_MOCK, UpdateTargetPointer).WillRepeatedly(Return(0));
    processor.processedCount_ = PRINT_INTERVAL_COUNT;
    libinput_event event;
    ASSERT_EQ(processor.OnEvent(&event), processor.pointerEvent_);
    EXPECT_NE(processor.pointerEvent_, nullptr);
    EXPECT_EQ(processor.processedCount_, PRINT_INTERVAL_COUNT + 1);
}

/**
 * @tc.name: RemoteControlTransformProcessorTestWithMock_OnEvent_008
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTestWithMock, OnEvent_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = nullptr;
    EXPECT_EQ(processor.pointerEvent_, nullptr);
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_TOUCH_MOTION));
    libinput_event_touch touchEvent;
    EXPECT_CALL(libinputMock, GetTouchEvent).WillRepeatedly(Return(NULL));
    MouseLocation expectLocation = {3, 3, 3};
    EXPECT_CALL(*WIN_MGR_MOCK, GetMouseInfo).WillRepeatedly(Return(expectLocation));
    processor.processedCount_ = PRINT_INTERVAL_COUNT;
    libinput_event event;
    ASSERT_EQ(processor.OnEvent(&event), nullptr);
    EXPECT_NE(processor.pointerEvent_, nullptr);
    EXPECT_EQ(processor.processedCount_, PRINT_INTERVAL_COUNT + 1);
}
} // namespace MMI
} // namespace OHOS