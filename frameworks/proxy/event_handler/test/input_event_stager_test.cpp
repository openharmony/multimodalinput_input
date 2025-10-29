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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <fstream>

#include "error_multimodal.h"
#include "i_input_event_consumer.h"
#include "input_event_hook_handler.h"
#include "input_event_stager.h"
#include "mmi_log.h"
#include "multimodal_input_connect_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEventStagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
} // namespace

class InputEventStagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: InputEventStagerTest_GetKeyEvent_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventStagerTest, InputEventStagerTest_GetKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t eventId = 0;
    auto event = INPUT_EVENT_STAGER.GetKeyEvent(eventId);
    EXPECT_TRUE(event == nullptr);
    INPUT_EVENT_STAGER.stashKeyEvents_.clear();
    INPUT_EVENT_STAGER.stashTouchEvents_.clear();
    INPUT_EVENT_STAGER.stashMouseEvents_.clear();
}

/**
 * @tc.name: InputEventStagerTest_GetKeyEvent_002
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventStagerTest, InputEventStagerTest_GetKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    int32_t eventId = 0;
    keyEvent->SetId(eventId);
    INPUT_EVENT_STAGER.stashKeyEvents_.push_back({ keyEvent, INPUT_EVENT_STAGER.GetNowMs() });
    auto event = INPUT_EVENT_STAGER.GetKeyEvent(eventId);
    EXPECT_TRUE(event != nullptr);
    INPUT_EVENT_STAGER.stashKeyEvents_.clear();
    INPUT_EVENT_STAGER.stashTouchEvents_.clear();
    INPUT_EVENT_STAGER.stashMouseEvents_.clear();
}

/**
 * @tc.name: InputEventStagerTest_GetTouchEvent_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventStagerTest, InputEventStagerTest_GetTouchEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t eventId = 0;
    auto event = INPUT_EVENT_STAGER.GetTouchEvent(eventId);
    EXPECT_TRUE(event == nullptr);
    INPUT_EVENT_STAGER.stashKeyEvents_.clear();
    INPUT_EVENT_STAGER.stashTouchEvents_.clear();
    INPUT_EVENT_STAGER.stashMouseEvents_.clear();
}

/**
 * @tc.name: InputEventStagerTest_GetTouchEvent_002
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventStagerTest, InputEventStagerTest_GetTouchEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    int32_t eventId = 0;
    pointerEvent->SetId(eventId);
    INPUT_EVENT_STAGER.stashTouchEvents_.push_back({ pointerEvent, INPUT_EVENT_STAGER.GetNowMs() });
    auto event = INPUT_EVENT_STAGER.GetTouchEvent(eventId);
    EXPECT_TRUE(event != nullptr);
    INPUT_EVENT_STAGER.stashKeyEvents_.clear();
    INPUT_EVENT_STAGER.stashTouchEvents_.clear();
    INPUT_EVENT_STAGER.stashMouseEvents_.clear();
}

/**
 * @tc.name: InputEventStagerTest_GetMouseEvent_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventStagerTest, InputEventStagerTest_GetMouseEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t eventId = 0;
    auto event = INPUT_EVENT_STAGER.GetMouseEvent(eventId);
    EXPECT_TRUE(event == nullptr);
    INPUT_EVENT_STAGER.stashKeyEvents_.clear();
    INPUT_EVENT_STAGER.stashTouchEvents_.clear();
    INPUT_EVENT_STAGER.stashMouseEvents_.clear();
}

/**
 * @tc.name: InputEventStagerTest_GetMouseEvent_002
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventStagerTest, InputEventStagerTest_GetMouseEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    int32_t eventId = 0;
    pointerEvent->SetId(eventId);
    INPUT_EVENT_STAGER.stashMouseEvents_.push_back({ pointerEvent, INPUT_EVENT_STAGER.GetNowMs() });
    auto event = INPUT_EVENT_STAGER.GetMouseEvent(eventId);
    EXPECT_TRUE(event != nullptr);
    INPUT_EVENT_STAGER.stashKeyEvents_.clear();
    INPUT_EVENT_STAGER.stashTouchEvents_.clear();
    INPUT_EVENT_STAGER.stashMouseEvents_.clear();
}

/**
 * @tc.name: InputEventStagerTest_ClearStashEvents_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventStagerTest, InputEventStagerTest_ClearStashEvents_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    int32_t eventId = 0;
    keyEvent->SetId(eventId);
    INPUT_EVENT_STAGER.stashKeyEvents_.push_back({ keyEvent, INPUT_EVENT_STAGER.GetNowMs() });
    HookEventType hookEventType = 1;
    INPUT_EVENT_STAGER.ClearStashEvents(hookEventType);
    EXPECT_TRUE(INPUT_EVENT_STAGER.stashKeyEvents_.empty());
    INPUT_EVENT_STAGER.stashKeyEvents_.clear();
    INPUT_EVENT_STAGER.stashTouchEvents_.clear();
    INPUT_EVENT_STAGER.stashMouseEvents_.clear();
}

/**
 * @tc.name: InputEventStagerTest_ClearStashEvents_002
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventStagerTest, InputEventStagerTest_ClearStashEvents_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    int32_t eventId = 0;
    pointerEvent->SetId(eventId);
    INPUT_EVENT_STAGER.stashTouchEvents_.push_back({ pointerEvent, INPUT_EVENT_STAGER.GetNowMs() });
    HookEventType hookEventType = 2;
    INPUT_EVENT_STAGER.ClearStashEvents(hookEventType);
    EXPECT_TRUE(INPUT_EVENT_STAGER.stashTouchEvents_.empty());
    INPUT_EVENT_STAGER.stashKeyEvents_.clear();
    INPUT_EVENT_STAGER.stashTouchEvents_.clear();
    INPUT_EVENT_STAGER.stashMouseEvents_.clear();
}

/**
 * @tc.name: InputEventStagerTest_ClearStashEvents_003
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventStagerTest, InputEventStagerTest_ClearStashEvents_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    int32_t eventId = 0;
    pointerEvent->SetId(eventId);
    INPUT_EVENT_STAGER.stashMouseEvents_.push_back({ pointerEvent, INPUT_EVENT_STAGER.GetNowMs() });
    HookEventType hookEventType = 4;
    INPUT_EVENT_STAGER.ClearStashEvents(hookEventType);
    EXPECT_TRUE(INPUT_EVENT_STAGER.stashMouseEvents_.empty());
    INPUT_EVENT_STAGER.stashKeyEvents_.clear();
    INPUT_EVENT_STAGER.stashTouchEvents_.clear();
    INPUT_EVENT_STAGER.stashMouseEvents_.clear();
}

/**
 * @tc.name: InputEventStagerTest_ClearStashEvents_004
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventStagerTest, InputEventStagerTest_ClearStashEvents_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    HookEventType hookEventType = 8;
    INPUT_EVENT_STAGER.ClearStashEvents(hookEventType);
    bool flag = INPUT_EVENT_STAGER.stashKeyEvents_.empty() &&
        INPUT_EVENT_STAGER.stashTouchEvents_.empty() &&
        INPUT_EVENT_STAGER.stashMouseEvents_.empty();
    EXPECT_TRUE(flag);
    INPUT_EVENT_STAGER.stashKeyEvents_.clear();
    INPUT_EVENT_STAGER.stashTouchEvents_.clear();
    INPUT_EVENT_STAGER.stashMouseEvents_.clear();
}
} // namespace MMI
} // namespace OHOS
