/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "define_multimodal.h"
#include "joystick_transform_processor.h"
#include "touch_transform_processor.h"
#include "touch_event_normalize.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchEventNormalizeTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t LIBINPUT_HOMEPAGE_BUTTON_CODE = 172;
constexpr int32_t LIBINPUT_BUTTON_NONE = -1;
} // namespace
class TouchEventNormalizeTest : public testing::Test {
public:
    void SetUp();
    void TearDown();

private:
    bool prePinchSwitch_ { true };
    bool preSwipeSwitch_ { true };
    bool preRotateSwitch_ { true };
};

class JoystickTransformProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class TouchTransformProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

void TouchEventNormalizeTest::SetUp()
{
    TouchEventHdr->GetTouchpadPinchSwitch(prePinchSwitch_);
    TouchEventHdr->GetTouchpadSwipeSwitch(preSwipeSwitch_);
    TouchEventHdr->GetTouchpadRotateSwitch(preRotateSwitch_);
}

void TouchEventNormalizeTest::TearDown()
{
    TouchEventHdr->SetTouchpadPinchSwitch(prePinchSwitch_);
    TouchEventHdr->SetTouchpadSwipeSwitch(preSwipeSwitch_);
    TouchEventHdr->SetTouchpadRotateSwitch(preRotateSwitch_);
}

/**
 * @tc.name: JoystickTransformProcessorTest_LibinputButtonToPointer
 * @tc.desc: Test LibinputButtonToPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickTransformProcessorTest, JoystickTransformProcessorTest_LibinputButtonToPointer, TestSize.Level1)
{
    int32_t deviceId = 123;
    JoystickTransformProcessor joystickTransformProcessor(deviceId);
    uint32_t button = LIBINPUT_HOMEPAGE_BUTTON_CODE;
    ASSERT_EQ(joystickTransformProcessor.LibinputButtonToPointer(button), PointerEvent::JOYSTICK_BUTTON_HOMEPAGE);

    button = LIBINPUT_BUTTON_NONE;
    ASSERT_EQ(joystickTransformProcessor.LibinputButtonToPointer(button), PointerEvent::BUTTON_NONE);
}

/**
 * @tc.name: TouchTransformProcessorTest_UpdatePointerItemProperties
 * @tc.desc: Test UpdatePointerItemProperties
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, TouchTransformProcessorTest_UpdatePointerItemProperties, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchTransformProcessor touchTransformProcessor(deviceId);
    PointerEvent::PointerItem item;
    EventTouch touchInfo;
    touchInfo.point.x = 125;
    touchInfo.point.y = 300;
    touchInfo.toolRect.point.x = 300;
    touchInfo.toolRect.point.y = 600;
    touchInfo.toolRect.width = 720;
    touchInfo.toolRect.height = 1000;
    ASSERT_NO_FATAL_FAILURE(touchTransformProcessor.UpdatePointerItemProperties(item, touchInfo));
}

/**
 * @tc.name: TouchEventNormalizeTest_MakeTransformProcessor
 * @tc.desc: Test Gets the TransformProcessor pointer based on the device type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_MakeTransformProcessor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 123456;
    ASSERT_NE(TouchEventHdr->MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::TOUCH), nullptr);
    ASSERT_NE(TouchEventHdr->MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::TABLET_TOOL), nullptr);
    ASSERT_NE(TouchEventHdr->MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::TOUCH_PAD), nullptr);
    ASSERT_NE(TouchEventHdr->MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::GESTURE), nullptr);
    ASSERT_NE(TouchEventHdr->MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::JOYSTICK), nullptr);
    ASSERT_EQ(TouchEventHdr->MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::KNUCKLE), nullptr);
}

/**
 * @tc.name: TouchEventNormalizeTest_SetTouchpadPinchSwitch_01
 * @tc.desc: Test SetTouchpadPinchSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_SetTouchpadPinchSwitch_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    ASSERT_TRUE(TouchEventHdr->SetTouchpadPinchSwitch(flag) == RET_OK);
}

/**
 * @tc.name: TouchEventNormalizeTest_GetTouchpadPinchSwitch_02
 * @tc.desc: Test GetTouchpadPinchSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_GetTouchpadPinchSwitch_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = true;
    TouchEventHdr->SetTouchpadPinchSwitch(flag);
    bool newFlag = true;
    ASSERT_TRUE(TouchEventHdr->GetTouchpadPinchSwitch(flag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: TouchEventNormalizeTest_SetTouchpadSwipeSwitch_03
 * @tc.desc: Test SetTouchpadSwipeSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_SetTouchpadSwipeSwitch_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    ASSERT_TRUE(TouchEventHdr->SetTouchpadSwipeSwitch(flag) == RET_OK);
}

/**
 * @tc.name: TouchEventNormalizeTest_GetTouchpadSwipeSwitch_04
 * @tc.desc: Test GetTouchpadSwipeSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_GetTouchpadSwipeSwitch_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = true;
    TouchEventHdr->SetTouchpadSwipeSwitch(flag);
    bool newFlag = true;
    ASSERT_TRUE(TouchEventHdr->GetTouchpadSwipeSwitch(flag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: TouchEventNormalizeTest_SetTouchpadRotateSwitch_05
 * @tc.desc: Test SetTouchpadRotateSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_SetTouchpadRotateSwitch_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool rotateSwitch = false;
    ASSERT_TRUE(TouchEventHdr->SetTouchpadRotateSwitch(rotateSwitch) == RET_OK);
}

/**
 * @tc.name: TouchEventNormalizeTest_GetTouchpadRotateSwitch_06
 * @tc.desc: Test GetTouchpadRotateSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_GetTouchpadRotateSwitch_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool rotateSwitch = true;
    TouchEventHdr->SetTouchpadRotateSwitch(rotateSwitch);
    bool newRotateSwitch = true;
    ASSERT_TRUE(TouchEventHdr->GetTouchpadRotateSwitch(rotateSwitch) == RET_OK);
    ASSERT_TRUE(rotateSwitch == newRotateSwitch);
}
} // namespace MMI
} // namespace OHOS