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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "libinput_interface.h"
#include "touchpad_transform_processor.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchPadGestureTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

class LibinputInterfaceMock : public LibinputInterface {
public:
    LibinputInterfaceMock() = default;
    ~LibinputInterfaceMock() override = default;

    MOCK_METHOD1(GetEventType, enum libinput_event_type (struct libinput_event *event));
    MOCK_METHOD1(GetTipState, enum libinput_tablet_tool_tip_state (struct libinput_event_tablet_tool *event));
    MOCK_METHOD1(TabletToolGetType, enum libinput_tablet_tool_type (struct libinput_tablet_tool *tool));
    MOCK_METHOD1(GetGestureEvent, struct libinput_event_gesture* (struct libinput_event *event));
    MOCK_METHOD1(GetTabletToolEvent, struct libinput_event_tablet_tool* (struct libinput_event *event));
    MOCK_METHOD1(GestureEventGetTime, uint32_t (struct libinput_event_gesture *event));
    MOCK_METHOD1(GestureEventGetFingerCount, int (struct libinput_event_gesture *event));
    MOCK_METHOD1(TabletToolGetTool, struct libinput_tablet_tool* (struct libinput_event_tablet_tool *event));
    MOCK_METHOD1(TabletToolGetToolType, int32_t (struct libinput_event_tablet_tool *event));
    MOCK_METHOD2(GestureEventGetDevCoordsX, int (struct libinput_event_gesture *, uint32_t));
    MOCK_METHOD2(GestureEventGetDevCoordsY, int (struct libinput_event_gesture *, uint32_t));
};

class TouchPadGestureTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TouchPadGestureTest::SetUpTestCase(void)
{}

void TouchPadGestureTest::TearDownTestCase(void)
{}

void TouchPadGestureTest::SetUp()
{}

void TouchPadGestureTest::TearDown()
{}

/**
 * @tc.name: TouchPadGestureTest_OnEventTouchPadSwipeBegin_001
 * @tc.desc: Test the funcation OnEventTouchPadSwipeBegin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadGestureTest, OnEventTouchPadSwipeBegin_001, TestSize.Level1)
{
    libinput_event_gesture event {};

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN));
    EXPECT_CALL(libinputMock, GetGestureEvent).WillOnce(Return(&event));
    EXPECT_CALL(libinputMock, GestureEventGetTime).WillOnce(Return(1));
    EXPECT_CALL(libinputMock, GestureEventGetFingerCount).WillOnce(Return(1));
    EXPECT_CALL(libinputMock, GestureEventGetDevCoordsX).WillOnce(Return(150));
    EXPECT_CALL(libinputMock, GestureEventGetDevCoordsY).WillOnce(Return(250));

    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    auto pointerEvent = processor.OnEvent(&event.base);
    ASSERT_TRUE(pointerEvent == nullptr);
}
} // namespace MMI
} // namespace OHOS