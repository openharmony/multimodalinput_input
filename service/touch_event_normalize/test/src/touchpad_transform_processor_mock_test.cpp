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
#include "pointer_event.h"
#include "preferences_manager_mock.h"
#include "touchpad_transform_processor.h"

#include "input_device_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchPadTransformProcessorMockTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

class TouchPadTransformProcessorMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TouchPadTransformProcessorMockTest::SetUpTestCase(void)
{}

void TouchPadTransformProcessorMockTest::TearDownTestCase(void)
{}

void TouchPadTransformProcessorMockTest::SetUp()
{}

void TouchPadTransformProcessorMockTest::TearDown()
{}

/**
 * @tc.name: TouchPadTransformProcessorMockTest_OnEvent_01
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorMockTest, TouchPadTransformProcessorMockTest_OnEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    libinput_event event {};
    
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(testing::Return(LIBINPUT_EVENT_TOUCHPAD_DOWN));

    auto pointerEvent = processor.OnEvent(&event);
    ASSERT_TRUE(pointerEvent == nullptr);
}

/**
 * @tc.name: TouchPadTransformProcessorMockTest_OnEvent_02
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorMockTest, TouchPadTransformProcessorMockTest_OnEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    libinput_event event {};
    
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(testing::Return(LIBINPUT_EVENT_TOUCHPAD_UP));

    auto pointerEvent = processor.OnEvent(&event);
    ASSERT_TRUE(pointerEvent == nullptr);
}

/**
 * @tc.name: TouchPadTransformProcessorMockTest_OnEvent_03
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorMockTest, TouchPadTransformProcessorMockTest_OnEvent_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    libinput_event event {};
    
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(testing::Return(LIBINPUT_EVENT_TOUCHPAD_MOTION));

    auto pointerEvent = processor.OnEvent(&event);
    ASSERT_TRUE(pointerEvent == nullptr);
}

/**
 * @tc.name: TouchPadTransformProcessorMockTest_OnEvent_04
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorMockTest, TouchPadTransformProcessorMockTest_OnEvent_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    libinput_event event {};
    
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(testing::Return(LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN));

    auto pointerEvent = processor.OnEvent(&event);
    ASSERT_TRUE(pointerEvent == nullptr);
}

/**
 * @tc.name: TouchPadTransformProcessorMockTest_OnEvent_05
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorMockTest, TouchPadTransformProcessorMockTest_OnEvent_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    libinput_event event {};
    
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(testing::Return(LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE));

    auto pointerEvent = processor.OnEvent(&event);
    ASSERT_TRUE(pointerEvent == nullptr);
}

/**
 * @tc.name: TouchPadTransformProcessorMockTest_OnEvent_06
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorMockTest, TouchPadTransformProcessorMockTest_OnEvent_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    libinput_event event {};
    
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(testing::Return(LIBINPUT_EVENT_GESTURE_SWIPE_END));

    auto pointerEvent = processor.OnEvent(&event);
    ASSERT_TRUE(pointerEvent == nullptr);
}

/**
 * @tc.name: TouchPadTransformProcessorMockTest_OnEvent_07
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorMockTest, TouchPadTransformProcessorMockTest_OnEvent_07, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    libinput_event event {};
    
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(testing::Return(LIBINPUT_EVENT_GESTURE_PINCH_BEGIN));

    auto pointerEvent = processor.OnEvent(&event);
    ASSERT_TRUE(pointerEvent == nullptr);
}

/**
 * @tc.name: TouchPadTransformProcessorMockTest_OnEvent_08
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorMockTest, TouchPadTransformProcessorMockTest_OnEvent_08, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    libinput_event event {};
    
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(testing::Return(LIBINPUT_EVENT_GESTURE_PINCH_UPDATE));

    auto pointerEvent = processor.OnEvent(&event);
    ASSERT_TRUE(pointerEvent == nullptr);
}

/**
 * @tc.name: TouchPadTransformProcessorMockTest_OnEvent_09
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorMockTest, TouchPadTransformProcessorMockTest_OnEvent_09, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    libinput_event event {};
    
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(testing::Return(LIBINPUT_EVENT_GESTURE_PINCH_END));

    auto pointerEvent = processor.OnEvent(&event);
    ASSERT_TRUE(pointerEvent == nullptr);
}

/**
 * @tc.name: TouchPadTransformProcessorMock_SetTouchPadSwipeData_01
 * @tc.desc: SetTouchPadSwipeData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorMockTest, TouchPadTransformProcessorMock_SetTouchPadSwipeData_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    TouchPadTransformProcessor processor(deviceId);
    int32_t action = PointerEvent::POINTER_ACTION_SWIPE_UPDATE;
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);

    libinput_event_gesture gestureevent {};
    libinput_event event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetGestureEvent).WillRepeatedly(Return(&gestureevent));
    EXPECT_CALL(libinputMock, GestureEventGetTime).WillRepeatedly(Return(1000));
    EXPECT_CALL(libinputMock, GestureEventGetFingerCount).WillRepeatedly(Return(-1));

    int32_t ret = processor.SetTouchPadSwipeData(&event, action);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TouchPadTransformProcessorMock_SetTouchPadSwipeData_02
 * @tc.desc: SetTouchPadSwipeData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorMockTest, TouchPadTransformProcessorMock_SetTouchPadSwipeData_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    TouchPadTransformProcessor processor(deviceId);
    int32_t action = PointerEvent::POINTER_ACTION_SWIPE_UPDATE;
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);

    libinput_event_gesture gestureevent {};
    libinput_event event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetGestureEvent).WillRepeatedly(Return(&gestureevent));
    EXPECT_CALL(libinputMock, GestureEventGetTime).WillRepeatedly(Return(1000));
    EXPECT_CALL(libinputMock, GestureEventGetFingerCount).WillRepeatedly(Return(0));

    int32_t ret = processor.SetTouchPadSwipeData(&event, action);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TouchPadTransformProcessorMock_SetTouchPadSwipeData_03
 * @tc.desc: SetTouchPadSwipeData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorMockTest, TouchPadTransformProcessorMock_SetTouchPadSwipeData_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    TouchPadTransformProcessor processor(deviceId);
    int32_t action = PointerEvent::POINTER_ACTION_SWIPE_UPDATE;
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);

    libinput_event_gesture gestureevent {};
    libinput_event event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetGestureEvent).WillRepeatedly(Return(&gestureevent));
    EXPECT_CALL(libinputMock, GestureEventGetTime).WillRepeatedly(Return(1000));
    EXPECT_CALL(libinputMock, GestureEventGetFingerCount).WillRepeatedly(Return(7));

    int32_t ret = processor.SetTouchPadSwipeData(&event, action);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TouchPadTransformProcessorMock_SetTouchPadPinchData_01
 * @tc.desc: SetTouchPadPinchData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorMockTest, TouchPadTransformProcessorMock_SetTouchPadPinchData_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 5;
    TouchPadTransformProcessor processor(deviceId);
    int32_t action = PointerEvent::POINTER_ACTION_AXIS_UPDATE;
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);

    libinput_event_gesture gestureevent {};
    libinput_event event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetGestureEvent).WillRepeatedly(Return(&gestureevent));
    EXPECT_CALL(libinputMock, GestureEventGetFingerCount).WillRepeatedly(Return(-1));

    int32_t ret = processor.SetTouchPadPinchData(&event, action);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TouchPadTransformProcessorMock_SetTouchPadPinchData_02
 * @tc.desc: SetTouchPadPinchData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorMockTest, TouchPadTransformProcessorMock_SetTouchPadPinchData_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 5;
    TouchPadTransformProcessor processor(deviceId);
    int32_t action = PointerEvent::POINTER_ACTION_AXIS_UPDATE;
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);

    libinput_event_gesture gestureevent {};
    libinput_event event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetGestureEvent).WillRepeatedly(Return(&gestureevent));
    EXPECT_CALL(libinputMock, GestureEventGetFingerCount).WillRepeatedly(Return(6));

    int32_t ret = processor.SetTouchPadPinchData(&event, action);
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace MMI
} // namespace OHOS