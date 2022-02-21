/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "define_multimodal.h"
#include "input_manager.h"
#include "key_event.h"
#include "key_event_pre.h"
#include "multimodal_standardized_event_manager.h"
#include "proto.h"
#include "pointer_event.h"
#include "run_shell_util.h"
#include "util.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;
class PointerEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    static std::shared_ptr<PointerEvent> createPointEvent();
};

std::shared_ptr<PointerEvent> PointerEventTest::createPointEvent()
{
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    int64_t downTime = GetMillisTime();
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code£¬set the PointerId = 0
    item.SetGlobalX(823);   // test code£¬set the GlobalX = 823
    item.SetGlobalY(723);   // test code£¬set the GlobalY = 723
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);    // test code£¬set the Pressure = 5
    item.SetDeviceId(1);    // test code£¬set the DeviceId = 1
    item.SetDownTime(downTime);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerId(0);  // test code£¬set the PointerId = 1
    pointerEvent->SetDeviceId(1);
    pointerEvent->SetActionTime(downTime);
    pointerEvent->SetActionStartTime(downTime);
    pointerEvent->SetTargetDisplayId(0);
    pointerEvent->SetTargetWindowId(-1);
    pointerEvent->SetAgentWindowId(-1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    return pointerEvent;
}

/**
 * @tc.name:PointerEventTest_keyEventAndPointerEvent_001
 * @tc.desc:Verify ctrl(left) + point event
 * @tc.type: FUNC
 * @tc.require: AR000GOACS
 * @tc.author: yangguang
 */
HWTEST_F(PointerEventTest, PointerEventTest_keyEventAndPointerEvent_001, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string log1 = "Pressed keyCode=";
    std::vector<std::string> beforeRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, beforeRunLogs) == RET_OK);

    std::shared_ptr<PointerEvent> pointerEvent = createPointEvent();
    // KEYCODE_CTRL_LEFT = 2072
    std::vector<int32_t> pressedKeys { OHOS::MMI::KeyEvent::KEYCODE_CTRL_LEFT };
    pointerEvent->SetPressedKeys(pressedKeys);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    std::vector<std::string> afterRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, afterRunLogs) == RET_OK);
    EXPECT_FALSE(afterRunLogs.empty());
    if (beforeRunLogs.empty()) {
        EXPECT_TRUE(afterRunLogs.size() > beforeRunLogs.size());
        EXPECT_TRUE(afterRunLogs.back().find(log1) != afterRunLogs.back().npos);
    } else {
        EXPECT_TRUE(std::strcmp(afterRunLogs.back().c_str(), beforeRunLogs.back().c_str()) != 0);
    }
}

/**
 * @tc.name:PointerEventTest_keyEventAndPointerEvent_002
 * @tc.desc:Verify ctrl(right) + point event
 * @tc.type: FUNC
 * @tc.require: AR000GOACS
 * @tc.author: yangguang
 */
HWTEST_F(PointerEventTest, PointerEventTest_keyEventAndPointerEvent_002, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string log1 = "Pressed keyCode=";
    std::vector<std::string> beforeRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, beforeRunLogs) == RET_OK);

    std::shared_ptr<PointerEvent> pointerEvent = createPointEvent();
    // KEYCODE_CTRL_RIGHT = 2073
    std::vector<int32_t> pressedKeys { OHOS::MMI::KeyEvent::KEYCODE_CTRL_RIGHT };
    pointerEvent->SetPressedKeys(pressedKeys);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    std::vector<std::string> afterRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, afterRunLogs) == RET_OK);
    EXPECT_FALSE(afterRunLogs.empty());
    if (beforeRunLogs.empty()) {
        EXPECT_TRUE(afterRunLogs.size() > beforeRunLogs.size());
        EXPECT_TRUE(afterRunLogs.back().find(log1) != afterRunLogs.back().npos);
    } else {
        EXPECT_TRUE(std::strcmp(afterRunLogs.back().c_str(), beforeRunLogs.back().c_str()) != 0);
    }
}

/**
 * @tc.name:PointerEventTest_keyEventAndPointerEvent_003
 * @tc.desc:Verify ctrl(left and right) + point event
 * @tc.type: FUNC
 * @tc.require: AR000GOACS
 * @tc.author: yangguang
 */
HWTEST_F(PointerEventTest, PointerEventTest_keyEventAndPointerEvent_003, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string log1 = "Pressed keyCode=";
    std::vector<std::string> beforeRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, beforeRunLogs) == RET_OK);

    std::shared_ptr<PointerEvent> pointerEvent = createPointEvent();
    // KEYCODE_CTRL_LEFT = 2072, KEYCODE_CTRL_RIGHT = 2073
    std::vector<int32_t> pressedKeys { OHOS::MMI::KeyEvent::KEYCODE_CTRL_LEFT,
        OHOS::MMI::KeyEvent::KEYCODE_CTRL_RIGHT };
    pointerEvent->SetPressedKeys(pressedKeys);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    std::vector<std::string> afterRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, afterRunLogs) == RET_OK);
    EXPECT_FALSE(afterRunLogs.empty());
    if (beforeRunLogs.empty()) {
        EXPECT_TRUE(afterRunLogs.size() > beforeRunLogs.size());
        EXPECT_TRUE(afterRunLogs.back().find(log1) != afterRunLogs.back().npos);
    } else {
        EXPECT_TRUE(std::strcmp(afterRunLogs.back().c_str(), beforeRunLogs.back().c_str()) != 0);
    }
}

HWTEST_F(PointerEventTest, PointerEventTest_CheckMousePointEvent_001, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_UNKNOWN);
    ASSERT_TRUE(!pointerEvent->IsValid());

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(-1);
    ASSERT_TRUE(!pointerEvent->IsValid());

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    PointerEvent::PointerItem item1;
    item1.SetPointerId(0);
    pointerEvent->AddPointerItem(item1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(0);
    pointerEvent->AddPointerItem(item2);
    ASSERT_TRUE(!pointerEvent->IsValid());

    auto pointerEvent1 = PointerEvent::Create();
    pointerEvent1->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent1->SetPointerId(0);
    pointerEvent1->SetButtonPressed(PointerEvent::BUTTON_NONE);
    pointerEvent1->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent1->SetButtonPressed(PointerEvent::MOUSE_BUTTON_RIGHT);
    pointerEvent1->SetButtonPressed(PointerEvent::MOUSE_BUTTON_MIDDLE);
    item1.SetPointerId(0);
    pointerEvent1->AddPointerItem(item1);
    ASSERT_TRUE(!pointerEvent1->IsValid());
}

HWTEST_F(PointerEventTest, PointerEventTest_CheckMousePointEvent_002, TestSize.Level1)
{
    auto pointerEvent1 = PointerEvent::Create();
    pointerEvent1->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent1->SetPointerId(0);
    pointerEvent1->SetButtonPressed(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    pointerEvent1->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent1->IsValid());

    auto pointerEvent2 = PointerEvent::Create();
    pointerEvent2->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent2->SetPointerId(0);
    pointerEvent2->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent2->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    item.SetPointerId(0);
    pointerEvent2->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent2->IsValid());

    auto pointerEvent3 = PointerEvent::Create();
    pointerEvent3->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent3->SetPointerId(0);
    pointerEvent3->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent3->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    pointerEvent3->SetButtonId(PointerEvent::BUTTON_NONE);
    item.SetPointerId(0);
    pointerEvent3->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent3->IsValid());
}

HWTEST_F(PointerEventTest, PointerEventTest_CheckMousePointEvent_003, TestSize.Level1)
{
    auto pointerEvent1 = PointerEvent::Create();
    pointerEvent1->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent1->SetPointerId(0);
    pointerEvent1->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent1->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent1->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    pointerEvent1->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent1->IsValid());

    auto pointerEvent2 = PointerEvent::Create();
    pointerEvent2->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent2->SetPointerId(0);
    pointerEvent2->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent2->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent2->SetButtonId(PointerEvent::BUTTON_NONE);
    item.SetPointerId(-1);
    pointerEvent2->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent2->IsValid());
}

HWTEST_F(PointerEventTest, PointerEventTest_CheckMousePointEvent_004, TestSize.Level1)
{
    auto pointerEvent1 = PointerEvent::Create();
    pointerEvent1->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent1->SetPointerId(0);
    pointerEvent1->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent1->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent1->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item;
    item.SetPointerId(2);
    pointerEvent1->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent1->IsValid());

    auto pointerEvent2 = PointerEvent::Create();
    pointerEvent2->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent2->SetPointerId(0);
    pointerEvent2->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent2->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent2->SetButtonId(PointerEvent::BUTTON_NONE);
    item.SetPointerId(0);
    item.SetDownTime(10010);
    pointerEvent2->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent2->IsValid());

    auto pointerEvent3 = PointerEvent::Create();
    pointerEvent3->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent3->SetPointerId(0);
    pointerEvent3->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent3->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent3->SetButtonId(PointerEvent::BUTTON_NONE);
    item.SetPointerId(0);
    item.SetDownTime(0);
    item.SetPressed(true);
    pointerEvent3->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent3->IsValid());
}

HWTEST_F(PointerEventTest, PointerEventTest_CheckMousePointEvent_005, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(0);
    item.SetPressed(false);
    pointerEvent->AddPointerItem(item);
    ASSERT_TRUE(pointerEvent->IsValid());
}

HWTEST_F(PointerEventTest, PointerEventTest_CheckTouchPointEvent_001, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(-1);
    ASSERT_TRUE(!pointerEvent->IsValid());

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    ASSERT_TRUE(!pointerEvent->IsValid());

    auto pointerEvent1 = PointerEvent::Create();
    pointerEvent1->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent1->SetPointerId(0);
    pointerEvent1->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    ASSERT_TRUE(!pointerEvent1->IsValid());
    
    auto pointerEvent2 = PointerEvent::Create();
    pointerEvent2->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent2->SetPointerId(0);
    pointerEvent2->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent2->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    ASSERT_TRUE(!pointerEvent2->IsValid());
}

HWTEST_F(PointerEventTest, PointerEventTest_CheckTouchPointEvent_002, TestSize.Level1)
{
    auto pointerEvent1 = PointerEvent::Create();
    pointerEvent1->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent1->SetPointerId(0);
    pointerEvent1->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent1->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item;
    item.SetPointerId(-1);
    pointerEvent1->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent1->IsValid());

    auto pointerEvent2 = PointerEvent::Create();
    pointerEvent2->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent2->SetPointerId(0);
    pointerEvent2->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent2->SetButtonId(PointerEvent::BUTTON_NONE);
    item.SetPointerId(0);
    item.SetDownTime(0);
    item.SetPressed(false);
    pointerEvent2->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent2->IsValid());
}

HWTEST_F(PointerEventTest, PointerEventTest_CheckTouchPointEvent_003, TestSize.Level1)
{
    auto pointerEvent1 = PointerEvent::Create();
    pointerEvent1->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent1->SetPointerId(0);
    pointerEvent1->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent1->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(100);
    item.SetPressed(true);
    pointerEvent1->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent1->IsValid());

    auto pointerEvent2 = PointerEvent::Create();
    pointerEvent2->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent2->SetPointerId(0);
    pointerEvent2->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent2->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item1;
    item1.SetPointerId(0);
    item1.SetDownTime(100);
    item1.SetPressed(false);
    pointerEvent2->AddPointerItem(item1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(0);
    item2.SetDownTime(100);
    item2.SetPressed(false);
    pointerEvent2->AddPointerItem(item2);
    ASSERT_TRUE(!pointerEvent2->IsValid());
}

HWTEST_F(PointerEventTest, PointerEventTest_CheckTouchPointEvent_004, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item1;
    item1.SetPointerId(1);
    item1.SetDownTime(100);
    item1.SetPressed(false);
    pointerEvent->AddPointerItem(item1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(2);
    item2.SetDownTime(100);
    item2.SetPressed(false);
    pointerEvent->AddPointerItem(item2);
    ASSERT_TRUE(!pointerEvent->IsValid());
}

HWTEST_F(PointerEventTest, PointerEventTest_CheckTouchPointEvent_005, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item1;
    item1.SetPointerId(0);
    item1.SetDownTime(100);
    item1.SetPressed(false);
    pointerEvent->AddPointerItem(item1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(1);
    item2.SetDownTime(100);
    item2.SetPressed(false);
    pointerEvent->AddPointerItem(item2);
    ASSERT_TRUE(pointerEvent->IsValid());
}
} // namespace
