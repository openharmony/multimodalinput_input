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

#include <cstdio>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "libinput_mock.h"
#include "preferences_manager_mock.h"
#include "mouse_transform_processor.h"

#include "input_device_manager.h"

#include "display_manager.h"
#include "mouse_device_state.h"
#include "i_input_windows_manager.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseTransformProcessorMockTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
constexpr uint32_t TP_CLICK_FINGER_ONE { 1 };
constexpr uint32_t TP_RIGHT_CLICK_FINGER_CNT { 2 };
constexpr int32_t BTN_RIGHT_MENUE_CODE { 0x118 };
}
class MouseTransformProcessorMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MouseTransformProcessorMockTest::SetUpTestCase(void)
{}

void MouseTransformProcessorMockTest::TearDownTestCase(void)
{}

void MouseTransformProcessorMockTest::SetUp()
{}

void MouseTransformProcessorMockTest::TearDown()
{}

/**
 * @tc.name: MouseTransformProcessorMockTest_Normalize_01
 * @tc.desc: Normalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorMockTest, MouseTransformProcessorMockTest_Normalize_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);

    libinput_event event {};
    libinput_event_pointer pointerevent {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD));
    EXPECT_CALL(libinputMock, LibinputGetPointerEvent).WillOnce(Return(&pointerevent));

    int32_t ret = processor.Normalize(&event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MouseTransformProcessorMockTest_Normalize_02
 * @tc.desc: Normalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorMockTest, MouseTransformProcessorMockTest_Normalize_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    MouseTransformProcessor processor(deviceId);

    libinput_event event {};
    libinput_event_pointer pointerevent {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD));
    EXPECT_CALL(libinputMock, LibinputGetPointerEvent).WillOnce(Return(&pointerevent));

    int32_t ret = processor.Normalize(&event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MouseTransformProcessorMockTest_Normalize_03
 * @tc.desc: Normalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorMockTest, MouseTransformProcessorMockTest_Normalize_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    MouseTransformProcessor processor(deviceId);

    libinput_event event {};
    libinput_event_pointer pointerevent {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_AXIS));
    EXPECT_CALL(libinputMock, LibinputGetPointerEvent).WillOnce(Return(&pointerevent));

    int32_t ret = processor.Normalize(&event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MouseTransformProcessorMockTest_HandleAxisBeginEndInner_01
 * @tc.desc: HandleAxisBeginEndInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorMockTest, MouseTransformProcessorMockTest_HandleAxisBeginEndInner_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    MouseTransformProcessor processor(deviceId);
    libinput_event event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TOUCHPAD_DOWN));
    processor.isPressed_ = false;
    int32_t ret = processor.HandleAxisBeginEndInner(&event);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorMockTest_HandleAxisBeginEndInner_02
 * @tc.desc: HandleAxisBeginEndInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorMockTest, MouseTransformProcessorMockTest_HandleAxisBeginEndInner_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    MouseTransformProcessor processor(deviceId);
    libinput_event event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TOUCHPAD_UP));
    processor.isPressed_ = false;
    int32_t ret = processor.HandleAxisBeginEndInner(&event);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorMockTest_HandleAxisInner_01
 * @tc.desc: HandleAxisInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorMockTest, MouseTransformProcessorMockTest_HandleAxisInner_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    MouseTransformProcessor processor(deviceId);
    bool tpScrollSwitch;

    libinput_event_pointer event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetAxisSource).WillRepeatedly(Return(LIBINPUT_POINTER_AXIS_SOURCE_FINGER));
    tpScrollSwitch = false;
    int32_t ret = processor.HandleAxisInner(&event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MouseTransformProcessorMockTest_HandleAxisInner_02
 * @tc.desc: HandleAxisInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorMockTest, MouseTransformProcessorMockTest_HandleAxisInner_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 5;
    MouseTransformProcessor processor(deviceId);
    bool tpScrollSwitch;

    libinput_event_pointer event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetAxisSource).WillRepeatedly(Return(LIBINPUT_POINTER_AXIS_SOURCE_FINGER));
    tpScrollSwitch = false;
    int32_t ret = processor.HandleAxisInner(&event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MouseTransformProcessorMockTest_HandleTwoFingerButton_01
 * @tc.desc: HandleTouchpadTwoFingerButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorMockTest, MouseTransformProcessorMockTest_HandleTwoFingerButton_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    MouseTransformProcessor processor(deviceId);
    uint32_t button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE;
    int32_t evenType = LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;

    libinput_event_pointer event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, PointerEventGetFingerCount).WillRepeatedly(Return(TP_RIGHT_CLICK_FINGER_CNT));
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadTwoFingerButton(&event, evenType, button));
}

/**
 * @tc.name: MouseTransformProcessorMockTest_HandleTwoFingerButton_02
 * @tc.desc: HandleTouchpadTwoFingerButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorMockTest, MouseTransformProcessorMockTest_HandleTwoFingerButton_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 5;
    MouseTransformProcessor processor(deviceId);
    uint32_t button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE;
    int32_t evenType = LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;

    libinput_event_pointer event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, PointerEventGetFingerCount).WillRepeatedly(Return(TP_CLICK_FINGER_ONE));
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadTwoFingerButton(&event, evenType, button));
}

/**
 * @tc.name: MouseTransformProcessorMockTest_HandleTwoFingerButton_03
 * @tc.desc: HandleTouchpadTwoFingerButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorMockTest, MouseTransformProcessorMockTest_HandleTwoFingerButton_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 5;
    MouseTransformProcessor processor(deviceId);
    uint32_t button = BTN_RIGHT_MENUE_CODE;
    int32_t evenType = LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;

    libinput_event_pointer event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, PointerEventGetFingerCount).WillRepeatedly(Return(TP_CLICK_FINGER_ONE));
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadTwoFingerButton(&event, evenType, button));
}

/**
 * @tc.name: MouseTransformProcessorMockTest_HandleMotionInner_01
 * @tc.desc: HandleMotionInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorMockTest, MouseTransformProcessorMockTest_HandleMotionInner_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 5;
    MouseTransformProcessor processor(deviceId);

    libinput_event_pointer pointerevent {};
    libinput_event event {};

    CursorPosition cursorPos = WIN_MGR->GetCursorPos();
    EXPECT_TRUE(cursorPos.displayId < 0);

    int32_t ret = processor.HandleMotionInner(&pointerevent, &event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MouseTransformProcessorMockTest_HandleMotionInner_02
 * @tc.desc: HandleMotionInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorMockTest, MouseTransformProcessorMockTest_HandleMotionInner_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 7;
    Direction direction;
    MouseTransformProcessor processor(deviceId);
    libinput_event_pointer pointerevent {};
    libinput_event event {};

    NiceMock<LibinputInterfaceMock> libinputMock;
    CursorPosition cursorPos = WIN_MGR->GetCursorPos();
    cursorPos.displayId = 2;
    EXPECT_CALL(libinputMock, PointerGetDxUnaccelerated).WillRepeatedly(Return(2.5));
    EXPECT_CALL(libinputMock, PointerGetDxUnaccelerated).WillRepeatedly(Return(3.5));

    direction = DIRECTION0;
    int32_t ret = processor.HandleMotionInner(&pointerevent, &event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MouseTransformProcessorMockTest_HandleMotionInner_03
 * @tc.desc: HandleMotionInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorMockTest, MouseTransformProcessorMockTest_HandleMotionInner_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 8;
    Direction direction;
    MouseTransformProcessor processor(deviceId);
    libinput_event_pointer pointerevent {};
    libinput_event event {};

    NiceMock<LibinputInterfaceMock> libinputMock;
    CursorPosition cursorPos = WIN_MGR->GetCursorPos();
    cursorPos.displayId = 2;
    EXPECT_CALL(libinputMock, PointerGetDxUnaccelerated).WillRepeatedly(Return(2.5));
    EXPECT_CALL(libinputMock, PointerGetDxUnaccelerated).WillRepeatedly(Return(3.5));
    direction = DIRECTION90;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD));
    int32_t ret = processor.HandleMotionInner(&pointerevent, &event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MouseTransformProcessorMockTest_HandleMotionInner_04
 * @tc.desc: HandleMotionInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorMockTest, MouseTransformProcessorMockTest_HandleMotionInner_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 8;
    Direction direction;
    MouseTransformProcessor processor(deviceId);
    libinput_event_pointer pointerevent {};
    libinput_event event {};

    NiceMock<LibinputInterfaceMock> libinputMock;
    CursorPosition cursorPos = WIN_MGR->GetCursorPos();
    cursorPos.displayId = 2;
    EXPECT_CALL(libinputMock, PointerGetDxUnaccelerated).WillRepeatedly(Return(2.5));
    EXPECT_CALL(libinputMock, PointerGetDxUnaccelerated).WillRepeatedly(Return(3.5));
    direction = DIRECTION90;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD));

    int32_t ret = processor.HandleMotionInner(&pointerevent, &event);
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace MMI
} // namespace OHOS