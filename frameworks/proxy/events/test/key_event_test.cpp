/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <sstream>
#include "define_multimodal.h"
#include "input_manager.h"
#include "key_event.h"
#include "key_event_pre.h"
#include "multimodal_standardized_event_manager.h"
#include "proto.h"
#include "key_event.h"
#include "run_shell_util.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

class KeyEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_001, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string log1 = "OnCheckKeyEvent_001";
    std::vector<std::string> beforeRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, beforeRunLogs) == RET_OK);

	auto KeyEvent = KeyEvent::Create();
	KeyEvent->SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    ASSERT_TRUE(!KeyEvent->IsValid());

    KeyEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
	KeyEvent->SetActionTime(0);
	ASSERT_TRUE(!KeyEvent->IsValid());

	KeyEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent->SetActionTime(100);
	KeyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);
	ASSERT_TRUE(!KeyEvent->IsValid());

    std::vector<std::string> afterRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, afterRunLogs) == RET_OK);
    EXPECT_TRUE(afterRunLogs.size() > 0);
    if (beforeRunLogs.size() == 0) {
        EXPECT_TRUE(afterRunLogs.size() > beforeRunLogs.size());
        EXPECT_TRUE(afterRunLogs.back().find(log1) != afterRunLogs.back().npos);
    } else {
        EXPECT_TRUE(std::strcmp(afterRunLogs.back().c_str(), beforeRunLogs.back().c_str()) != 0);
    }
}

HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_002, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string log1 = "OnCheckKeyEvent_002";
    std::vector<std::string> beforeRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, beforeRunLogs) == RET_OK);

    auto KeyEvent1 = KeyEvent::Create();
    KeyEvent1->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent1->SetActionTime(100);
	KeyEvent1->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    KeyEvent1->AddKeyItem(item);
	ASSERT_TRUE(!KeyEvent1->IsValid());

	auto KeyEvent2 = KeyEvent::Create();
    KeyEvent2->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent2->SetActionTime(100);
	KeyEvent2->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    item.SetKeyCode(KeyEvent::KEYCODE_HOME);
	item.SetDownTime(0);
    KeyEvent2->AddKeyItem(item);
	ASSERT_TRUE(!KeyEvent2->IsValid());
	
    std::vector<std::string> afterRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, afterRunLogs) == RET_OK);
    EXPECT_TRUE(afterRunLogs.size() > 0);
    if (beforeRunLogs.size() == 0) {
        EXPECT_TRUE(afterRunLogs.size() > beforeRunLogs.size());
        EXPECT_TRUE(afterRunLogs.back().find(log1) != afterRunLogs.back().npos);
    } else {
        EXPECT_TRUE(std::strcmp(afterRunLogs.back().c_str(), beforeRunLogs.back().c_str()) != 0);
    }
}

HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_003, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string log1 = "OnCheckKeyEvent_003";
    std::vector<std::string> beforeRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, beforeRunLogs) == RET_OK);

    auto KeyEvent1 = KeyEvent::Create();
    KeyEvent1->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent1->SetActionTime(100);
	KeyEvent1->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
	KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_HOME);
	item.SetDownTime(100);
	item.SetPressed(false);
    KeyEvent1->AddKeyItem(item);
	ASSERT_TRUE(!KeyEvent1->IsValid());

	auto KeyEvent2 = KeyEvent::Create();
	KeyEvent2->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent2->SetActionTime(100);
	KeyEvent2->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    item.SetKeyCode(KeyEvent::KEYCODE_BACK);
	item.SetDownTime(100);
	item.SetPressed(false);
    KeyEvent2->AddKeyItem(item);
	ASSERT_TRUE(!KeyEvent2->IsValid());
	
    std::vector<std::string> afterRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, afterRunLogs) == RET_OK);
    EXPECT_TRUE(afterRunLogs.size() > 0);
    if (beforeRunLogs.size() == 0) {
        EXPECT_TRUE(afterRunLogs.size() > beforeRunLogs.size());
        EXPECT_TRUE(afterRunLogs.back().find(log1) != afterRunLogs.back().npos);
    } else {
        EXPECT_TRUE(std::strcmp(afterRunLogs.back().c_str(), beforeRunLogs.back().c_str()) != 0);
    }
}

HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_004, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string log1 = "OnCheckKeyEvent_004";
    std::vector<std::string> beforeRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, beforeRunLogs) == RET_OK);

    auto KeyEvent1 = KeyEvent::Create();
	KeyEvent1->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent1->SetActionTime(100);
	KeyEvent1->SetKeyAction(KeyEvent::KEY_ACTION_UP);
	KeyEvent::KeyItem item1;
    item1.SetKeyCode(KeyEvent::KEYCODE_HOME);
	item1.SetDownTime(100);
	item1.SetPressed(false);
    KeyEvent1->AddKeyItem(item1);
    KeyEvent::KeyItem item2;
    item2.SetKeyCode(KeyEvent::KEYCODE_HOME);
	item2.SetDownTime(100);
	item2.SetPressed(false);
    KeyEvent1->AddKeyItem(item2);
	ASSERT_TRUE(!KeyEvent1->IsValid());

	auto KeyEvent2 = KeyEvent::Create();
	KeyEvent2->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent2->SetActionTime(100);
	KeyEvent2->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    item1.SetKeyCode(KeyEvent::KEYCODE_HOME);
	item1.SetDownTime(100);
	item1.SetPressed(false);
    KeyEvent2->AddKeyItem(item1);
    item2.SetKeyCode(KeyEvent::KEYCODE_BACK);
	item2.SetDownTime(100);
	item2.SetPressed(false);
    KeyEvent2->AddKeyItem(item2);
	ASSERT_TRUE(!KeyEvent2->IsValid());
	
    std::vector<std::string> afterRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, afterRunLogs) == RET_OK);
    EXPECT_TRUE(afterRunLogs.size() > 0);
    if (beforeRunLogs.size() == 0) {
        EXPECT_TRUE(afterRunLogs.size() > beforeRunLogs.size());
        EXPECT_TRUE(afterRunLogs.back().find(log1) != afterRunLogs.back().npos);
    } else {
        EXPECT_TRUE(std::strcmp(afterRunLogs.back().c_str(), beforeRunLogs.back().c_str()) != 0);
    }
}

HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_005, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string log1 = "OnCheckKeyEvent_005";
    std::vector<std::string> beforeRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, beforeRunLogs) == RET_OK);
	
	auto KeyEvent = KeyEvent::Create();
	KeyEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent->SetActionTime(100);
	KeyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
	KeyEvent::KeyItem item1;
    item1.SetKeyCode(KeyEvent::KEYCODE_HOME);
	item1.SetDownTime(100);
	item1.SetPressed(false);
    KeyEvent->AddKeyItem(item1);
    KeyEvent::KeyItem item2;
    item2.SetKeyCode(KeyEvent::KEYCODE_BACK);
	item2.SetDownTime(100);
	item2.SetPressed(true);
    KeyEvent->AddKeyItem(item2);
	ASSERT_TRUE(KeyEvent->IsValid());
	
    std::vector<std::string> afterRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, afterRunLogs) == RET_OK);
    EXPECT_TRUE(afterRunLogs.size() > 0);
    if (beforeRunLogs.size() == 0) {
        EXPECT_TRUE(afterRunLogs.size() > beforeRunLogs.size());
        EXPECT_TRUE(afterRunLogs.back().find(log1) != afterRunLogs.back().npos);
    } else {
        EXPECT_TRUE(std::strcmp(afterRunLogs.back().c_str(), beforeRunLogs.back().c_str()) != 0);
    }
}
}
