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

#include "libinput.h"
#include "define_multimodal.h"
#include "touchpad_transform_processor.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class TouchPadTransformProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

private:
    TouchPadTransformProcessor g_processor_ { 0 };
    bool prePinchSwitch_ { true };
    bool preSwipeSwitch_ { true };
    bool preRotateSwitch_ { true };
};

void TouchPadTransformProcessorTest::SetUpTestCase(void)
{
}

void TouchPadTransformProcessorTest::TearDownTestCase(void)
{
}

void TouchPadTransformProcessorTest::SetUp()
{
    g_processor_.GetTouchpadPinchSwitch(prePinchSwitch_);
    g_processor_.GetTouchpadSwipeSwitch(preSwipeSwitch_);
    g_processor_.GetTouchpadRotateSwitch(preRotateSwitch_);
}

void TouchPadTransformProcessorTest::TearDown()
{
    g_processor_.SetTouchpadPinchSwitch(prePinchSwitch_);
    g_processor_.SetTouchpadSwipeSwitch(preSwipeSwitch_);
    g_processor_.SetTouchpadRotateSwitch(preRotateSwitch_);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_SetTouchpadPinchSwitch_01
 * @tc.desc: Test SetTouchpadPinchSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_SetTouchpadPinchSwitch_01, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    bool flag = false;
    ASSERT_TRUE(processor.SetTouchpadPinchSwitch(flag) == RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetTouchpadPinchSwitch_02
 * @tc.desc: Test GetTouchpadPinchSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetTouchpadPinchSwitch_02, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    bool flag = false;
    processor.SetTouchpadPinchSwitch(flag);
    bool newFlag = false;
    ASSERT_TRUE(processor.GetTouchpadPinchSwitch(flag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_SetTouchpadSwipeSwitch_03
 * @tc.desc: Test SetTouchpadSwipeSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_SetTouchpadSwipeSwitch_03, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    bool flag = false;
    ASSERT_TRUE(processor.SetTouchpadSwipeSwitch(flag) == RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetTouchpadSwipeSwitch_04
 * @tc.desc: Test GetTouchpadSwipeSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetTouchpadSwipeSwitch_04, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    bool flag = false;
    processor.SetTouchpadSwipeSwitch(flag);
    bool newFlag = false;
    ASSERT_TRUE(processor.GetTouchpadSwipeSwitch(flag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_SetTouchpadRotateSwitch_05
 * @tc.desc: Test SetTouchpadRotateSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_SetTouchpadRotateSwitch_05, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    bool rotateSwitch = false;
    ASSERT_TRUE(processor.SetTouchpadRotateSwitch(rotateSwitch) == RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetTouchpadRotateSwitch_06
 * @tc.desc: Test GetTouchpadRotateSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetTouchpadRotateSwitch_06, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    bool rotateSwitch = false;
    processor.SetTouchpadRotateSwitch(rotateSwitch);
    bool newRotateSwitch = false;
    ASSERT_TRUE(processor.GetTouchpadRotateSwitch(newRotateSwitch) == RET_OK);
    ASSERT_TRUE(rotateSwitch == newRotateSwitch);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_SetTouchPadMultiTapData
 * @tc.desc: Test SetTouchPadMultiTapData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_SetTouchPadMultiTapData, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(processor.pointerEvent_, nullptr);
    ASSERT_EQ(processor.SetTouchPadMultiTapData(), RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_ProcessTouchPadPinchDataEvent
 * @tc.desc: Test ProcessTouchPadPinchDataEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_ProcessTouchPadPinchDataEvent, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    int32_t fingerCount = 2;
    int32_t action = PointerEvent::POINTER_ACTION_AXIS_BEGIN;
    double scale = 8.5;
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(processor.pointerEvent_, nullptr);
    processor.pointerEvent_->SetFingerCount(2);
    ASSERT_NO_FATAL_FAILURE(processor.ProcessTouchPadPinchDataEvent(fingerCount, action, scale));

    fingerCount = 1;
    processor.pointerEvent_->SetFingerCount(1);
    ASSERT_NO_FATAL_FAILURE(processor.ProcessTouchPadPinchDataEvent(fingerCount, action, scale));

    fingerCount = 3;
    ASSERT_NO_FATAL_FAILURE(processor.ProcessTouchPadPinchDataEvent(fingerCount, action, scale));
}
} // namespace MMI
} // namespace OHOS