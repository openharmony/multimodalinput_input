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
#include "gesture_transform_processor.h"
#include "libinput_mock.h"
#include "input_device_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "GestureTransformProcessorMockTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

class GestureTransformProcessorMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void GestureTransformProcessorMockTest::SetUpTestCase(void)
{}

void GestureTransformProcessorMockTest::TearDownTestCase(void)
{}

void GestureTransformProcessorMockTest::SetUp()
{}

void GestureTransformProcessorMockTest::TearDown()
{}

/**
 * @tc.name: GestureTransformProcessorMockTest_OnEvent_02
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureTransformProcessorMockTest, GestureTransformProcessorMockTest_OnEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    GestureTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    libinput_event event {};
    libinput_event_gesture gestureEvent {};
    
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetGestureEvent).WillRepeatedly(testing::Return(&gestureEvent));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(testing::Return(LIBINPUT_EVENT_GESTURE_PINCH_UPDATE));

    auto pointerEvent = processor.OnEvent(&event);
    ASSERT_TRUE(pointerEvent != nullptr);
}

/**
 * @tc.name: GestureTransformProcessorMockTest_OnEvent_03
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureTransformProcessorMockTest, GestureTransformProcessorMockTest_OnEvent_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    GestureTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    libinput_event event {};
    libinput_event_gesture gestureEvent {};
    
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetGestureEvent).WillRepeatedly(testing::Return(&gestureEvent));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(testing::Return(LIBINPUT_EVENT_GESTURE_PINCH_END));

    auto pointerEvent = processor.OnEvent(&event);
    ASSERT_TRUE(pointerEvent != nullptr);
}

/**
 * @tc.name: GestureTransformProcessorMockTest_OnEvent_04
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureTransformProcessorMockTest, GestureTransformProcessorMockTest_OnEvent_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 4;
    GestureTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    libinput_event event {};
    libinput_event_gesture gestureEvent {};
    
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetGestureEvent).WillRepeatedly(testing::Return(&gestureEvent));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(testing::Return(LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN));

    auto pointerEvent = processor.OnEvent(&event);
    ASSERT_TRUE(pointerEvent == nullptr);
}

/**
 * @tc.name: GestureTransformProcessorMockTest_OnEvent_05
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureTransformProcessorMockTest, GestureTransformProcessorMockTest_OnEvent_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 5;
    GestureTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    libinput_event event {};
    libinput_event_gesture gestureEvent {};
    
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetGestureEvent).WillRepeatedly(testing::Return(&gestureEvent));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(testing::Return(LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE));

    auto pointerEvent = processor.OnEvent(&event);
    ASSERT_TRUE(pointerEvent == nullptr);
}

/**
 * @tc.name: GestureTransformProcessorMockTest_OnEvent_06
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureTransformProcessorMockTest, GestureTransformProcessorMockTest_OnEvent_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    GestureTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    libinput_event event {};
    libinput_event_gesture gestureEvent {};
    
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetGestureEvent).WillRepeatedly(testing::Return(&gestureEvent));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(testing::Return(LIBINPUT_EVENT_GESTURE_SWIPE_END));

    auto pointerEvent = processor.OnEvent(&event);
    ASSERT_TRUE(pointerEvent == nullptr);
}
} // namespace MMI
} // namespace OHOS