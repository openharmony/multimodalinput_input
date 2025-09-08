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
using namespace testing::ext;

class TouchEventNormalizeTest : public testing::Test {
public:
    void SetUp();
    void TearDown();

private:
    bool prePinchSwitch_ { true };
    bool preSwipeSwitch_ { true };
    bool preRotateSwitch_ { true };
    bool preDoubleTapDragSwitch_ { true };
    int32_t preScrollRows_ { 3 };
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
    TOUCH_EVENT_HDR->GetTouchpadPinchSwitch(prePinchSwitch_);
    TOUCH_EVENT_HDR->GetTouchpadSwipeSwitch(preSwipeSwitch_);
    TOUCH_EVENT_HDR->GetTouchpadRotateSwitch(preRotateSwitch_);
    TOUCH_EVENT_HDR->GetTouchpadScrollRows();
    TOUCH_EVENT_HDR->GetTouchpadDoubleTapAndDragState(preDoubleTapDragSwitch_);
}

void TouchEventNormalizeTest::TearDown()
{
    TOUCH_EVENT_HDR->SetTouchpadPinchSwitch(prePinchSwitch_);
    TOUCH_EVENT_HDR->SetTouchpadSwipeSwitch(preSwipeSwitch_);
    TOUCH_EVENT_HDR->SetTouchpadRotateSwitch(preRotateSwitch_);
    TOUCH_EVENT_HDR->SetTouchpadScrollRows(preScrollRows_);
    TOUCH_EVENT_HDR->SetTouchpadDoubleTapAndDragState(preDoubleTapDragSwitch_);
}

/**
 * @tc.name: TouchTransformProcessorTest_UpdatePointerItemProperties
 * @tc.desc: Test UpdatePointerItemByTouchInfo
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
    ASSERT_NO_FATAL_FAILURE(touchTransformProcessor.UpdatePointerItemByTouchInfo(item, touchInfo));
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
    ASSERT_NE(TOUCH_EVENT_HDR->MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::TOUCH), nullptr);
    ASSERT_NE(TOUCH_EVENT_HDR->MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::TABLET_TOOL), nullptr);
    ASSERT_NE(TOUCH_EVENT_HDR->MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::TOUCH_PAD), nullptr);
    ASSERT_NE(TOUCH_EVENT_HDR->MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::GESTURE), nullptr);
    ASSERT_NE(TOUCH_EVENT_HDR->MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::REMOTE_CONTROL),
        nullptr);
    ASSERT_EQ(TOUCH_EVENT_HDR->MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::KNUCKLE), nullptr);
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
    ASSERT_TRUE(TOUCH_EVENT_HDR->SetTouchpadPinchSwitch(flag) == RET_OK);
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
    bool flag = false;
    ASSERT_TRUE(TOUCH_EVENT_HDR->SetTouchpadPinchSwitch(flag) == RET_OK);
    flag = true;
    TOUCH_EVENT_HDR->SetTouchpadPinchSwitch(flag);
    bool newFlag = true;
    TOUCH_EVENT_HDR->GetTouchpadPinchSwitch(newFlag);
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
    ASSERT_TRUE(TOUCH_EVENT_HDR->SetTouchpadSwipeSwitch(flag) == RET_OK);
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
    bool flag = false;
    ASSERT_TRUE(TOUCH_EVENT_HDR->SetTouchpadSwipeSwitch(flag) == RET_OK);
    flag = true;
    TOUCH_EVENT_HDR->SetTouchpadSwipeSwitch(flag);
    bool newFlag = true;
    TOUCH_EVENT_HDR->GetTouchpadSwipeSwitch(newFlag);
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
    ASSERT_TRUE(TOUCH_EVENT_HDR->SetTouchpadRotateSwitch(rotateSwitch) == RET_OK);
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
    bool rotateSwitch = false;
    ASSERT_TRUE(TOUCH_EVENT_HDR->SetTouchpadRotateSwitch(rotateSwitch) == RET_OK);
    rotateSwitch = true;
    TOUCH_EVENT_HDR->SetTouchpadRotateSwitch(rotateSwitch);
    bool newRotateSwitch = true;
    TOUCH_EVENT_HDR->GetTouchpadRotateSwitch(newRotateSwitch);
}

/**
 * @tc.name: TouchEventNormalizeTest_SetTouchpadScrollRows_07
 * @tc.desc: Test SetTouchpadScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_SetTouchpadScrollRows_07, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t rows = 50;
    ASSERT_TRUE(TOUCH_EVENT_HDR->SetTouchpadScrollRows(rows) == RET_OK);
}

/**
 * @tc.name: TouchEventNormalizeTest_GetTouchpadScrollRows_08
 * @tc.desc: Test GetTouchpadScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_GetTouchpadScrollRows_08, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t rows = 50;
    TOUCH_EVENT_HDR->SetTouchpadScrollRows(rows);
    int32_t newRows = TOUCH_EVENT_HDR->GetTouchpadScrollRows();
    ASSERT_TRUE(rows == newRows);
}
} // namespace MMI
} // namespace OHOS