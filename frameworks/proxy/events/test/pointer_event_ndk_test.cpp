/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <fstream>
#include <gtest/gtest.h>

#include "oh_input_manager.h"
#include "pointer_event.h"
#include "pointer_event_ndk.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerEventNdkTest"

struct Input_TouchEvent {
    int32_t action;
    int32_t id;
    int32_t displayX;
    int32_t displayY;
    int64_t actionTime { -1 };
    int32_t windowId { -1 };
    int32_t displayId { -1 };
};

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class PointerEventNdkTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: PointerEventNdkTest_OH_Input_TouchEventToPointerEvent_Normal
 * @tc.desc: Test the function OH_Input_TouchEventToPointerEvent with normal parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventNdkTest, PointerEventNdkTest_OH_Input_TouchEventToPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = 100;
    inputTouchEvent.action = TOUCH_ACTION_DOWN;
    inputTouchEvent.id = 1;
    inputTouchEvent.displayX = 100;
    inputTouchEvent.displayY = 200;

    std::shared_ptr<OHOS::MMI::PointerEvent> result
        = OH_Input_TouchEventToPointerEvent(&inputTouchEvent);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: PointerEventNdkTest_OH_Input_TouchEventToPointerEvent_InvalidActionTime
 * @tc.desc: Test the function OH_Input_TouchEventToPointerEvent with invalid actionTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventNdkTest, PointerEventNdkTest_OH_Input_TouchEventToPointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = -1;
    inputTouchEvent.action = TOUCH_ACTION_DOWN;
    inputTouchEvent.id = 1;
    inputTouchEvent.displayX = 100;
    inputTouchEvent.displayY = 200;

    std::shared_ptr<OHOS::MMI::PointerEvent> result
        = OH_Input_TouchEventToPointerEvent(&inputTouchEvent);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: PointerEventNdkTest_OH_Input_TouchEventToPointerEvent_InvalidAction
 * @tc.desc: Test the function OH_Input_TouchEventToPointerEvent with invalid action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventNdkTest, PointerEventNdkTest_OH_Input_TouchEventToPointerEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = 100;
    inputTouchEvent.action = static_cast<Input_TouchEventAction>(10);
    inputTouchEvent.id = 1;
    inputTouchEvent.displayX = 100;
    inputTouchEvent.displayY = 200;

    std::shared_ptr<OHOS::MMI::PointerEvent> result
        = OH_Input_TouchEventToPointerEvent(&inputTouchEvent);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: PointerEventNdkTest_OH_Input_TouchEventToPointerEvent_InvalidDisplayX
 * @tc.desc: Test the function OH_Input_TouchEventToPointerEvent with invalid displayX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventNdkTest, PointerEventNdkTest_OH_Input_TouchEventToPointerEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = 100;
    inputTouchEvent.action = TOUCH_ACTION_DOWN;
    inputTouchEvent.id = 1;
    inputTouchEvent.displayX = -1;
    inputTouchEvent.displayY = 200;

    std::shared_ptr<OHOS::MMI::PointerEvent> result
        = OH_Input_TouchEventToPointerEvent(&inputTouchEvent);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: PointerEventNdkTest_OH_Input_TouchEventToPointerEvent_InvalidDisplayY
 * @tc.desc: Test the function OH_Input_TouchEventToPointerEvent with invalid displayY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventNdkTest, PointerEventNdkTest_OH_Input_TouchEventToPointerEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = 100;
    inputTouchEvent.action = TOUCH_ACTION_DOWN;
    inputTouchEvent.id = 1;
    inputTouchEvent.displayX = 100;
    inputTouchEvent.displayY = -1;

    std::shared_ptr<OHOS::MMI::PointerEvent> result
        = OH_Input_TouchEventToPointerEvent(&inputTouchEvent);
    EXPECT_EQ(result, nullptr);
}
} // namespace MMI
} // namespace OHOS