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
#include "libinput_mock.h"
#include "preferences_manager_mock.h"
#include "touchpad_transform_processor.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchPadGestureTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

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

    EXPECT_CALL(*PREFERENCES_MGR_MOCK, GetBoolValue).WillOnce(Return(true));

    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    auto pointerEvent = processor.OnEvent(&event.base);
    ASSERT_TRUE(pointerEvent != nullptr);
    EXPECT_EQ(pointerEvent->GetSourceType(), PointerEvent::SOURCE_TYPE_TOUCHPAD);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
}
} // namespace MMI
} // namespace OHOS