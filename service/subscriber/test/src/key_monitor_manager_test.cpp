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

#include <gtest/gtest.h>

#include "bundle_name_parser.h"
#include "error_multimodal.h"
#include "key_auto_repeat.h"
#include "key_monitor_manager.h"
#include "mmi_log.h"
#include "input_windows_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyMonitorManagerTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

class KeyMonitorManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {}
    static void TearDownTestCase(void)
    {}
};

/**
 * @tc.name: KeyMonitorManagerTest_Monitor_LessThanOperator_01
 * @tc.desc: Verify the correctness of the less-than operator in Monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Monitor_LessThanOperator_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyMonitorManager::Monitor monitor1{
        .session_ = 1, .key_ = KeyEvent::KEYCODE_A, .action_ = KeyEvent::KEY_ACTION_UNKNOWN, .isRepeat_ = false};
    KeyMonitorManager::Monitor monitor2{
        .session_ = 2, .key_ = KeyEvent::KEYCODE_A, .action_ = KeyEvent::KEY_ACTION_UNKNOWN, .isRepeat_ = false};
    EXPECT_TRUE(monitor1 < monitor2);

    KeyMonitorManager::Monitor monitor3{
        .session_ = 1, .key_ = KeyEvent::KEYCODE_A, .action_ = KeyEvent::KEY_ACTION_UNKNOWN, .isRepeat_ = false};
    KeyMonitorManager::Monitor monitor4{
        .session_ = 1, .key_ = KeyEvent::KEYCODE_B, .action_ = KeyEvent::KEY_ACTION_UNKNOWN, .isRepeat_ = false};
    EXPECT_TRUE(monitor3 < monitor4);

    KeyMonitorManager::Monitor monitor5{
        .session_ = 1, .key_ = KeyEvent::KEYCODE_A, .action_ = KeyEvent::KEY_ACTION_UNKNOWN, .isRepeat_ = true};
    KeyMonitorManager::Monitor monitor6{
        .session_ = 1, .key_ = KeyEvent::KEYCODE_A, .action_ = KeyEvent::KEY_ACTION_CANCEL, .isRepeat_ = true};
    EXPECT_TRUE(monitor5 < monitor6);

    KeyMonitorManager::Monitor monitor7{
        .session_ = 1, .key_ = KeyEvent::KEYCODE_A, .action_ = KeyEvent::KEY_ACTION_UNKNOWN, .isRepeat_ = true};
    KeyMonitorManager::Monitor monitor8{
        .session_ = 1, .key_ = KeyEvent::KEYCODE_A, .action_ = KeyEvent::KEY_ACTION_UNKNOWN, .isRepeat_ = true};
    EXPECT_FALSE(monitor7 < monitor8);
}

/**
 * @tc.name: KeyMonitorManagerTest_AddMonitor_01
 * @tc.desc: Verify the AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_AddMonitor_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    std::string name = "test.name";
    KeyMonitorManager::Monitor monitor1{
        .session_ = 1, .key_ = KeyEvent::KEYCODE_VOLUME_UP, .action_ = KeyEvent::KEY_ACTION_UP, .isRepeat_ = true};
    int32_t ret = keyMonitorManager->AddMonitor(monitor1, name);
    EXPECT_EQ(ret, RET_OK);

    KeyMonitorManager::Monitor monitor2{
        .session_ = 1, .key_ = KeyEvent::KEYCODE_VOLUME_UP, .action_ = KeyEvent::KEY_ACTION_DOWN, .isRepeat_ = true};
    ret = keyMonitorManager->AddMonitor(monitor2, name);
    EXPECT_EQ(ret, RET_OK);

    ret = keyMonitorManager->AddMonitor(monitor2, name);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: KeyMonitorManagerTest_RemoveMonitor_01
 * @tc.desc: Verify the RemoveMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_RemoveMonitor_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    size_t size = keyMonitorManager->monitors_.size();
    std::string name = "test.name";

    KeyMonitorManager::Monitor monitor1{
        .session_ = 1, .key_ = KeyEvent::KEYCODE_VOLUME_UP, .action_ = KeyEvent::KEY_ACTION_DOWN, .isRepeat_ = true};
    int32_t ret = keyMonitorManager->AddMonitor(monitor1, name);
    EXPECT_EQ(ret, RET_OK);

    EXPECT_GT(keyMonitorManager->monitors_.size(), size);
    keyMonitorManager->RemoveMonitor(monitor1, name);
}
/**
 * @tc.name: KeyMonitorManagerTest_Intercept_01
 * @tc.desc: Verify the Intercept function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Intercept_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor1{
        .session_ = 0, .key_ = KeyEvent::KEYCODE_VOLUME_UP, .action_ = KeyEvent::KEY_ACTION_DOWN, .isRepeat_ = true};
    keyMonitorManager->monitors_.emplace(monitor1);
    EXPECT_EQ(keyMonitorManager->monitors_.size(), 1);

    std::shared_ptr<KeyEvent> keyEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyCode(monitor1.key_);
    keyEvent->SetKeyAction(monitor1.action_);
    EXPECT_FALSE(keyMonitorManager->Intercept(keyEvent));

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    EXPECT_FALSE(keyMonitorManager->Intercept(keyEvent));
}

/**
 * @tc.name: KeyMonitorManagerTest_Intercept_02
 * @tc.desc: Verify the Intercept function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Intercept_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    std::shared_ptr<KeyEvent> keyEvent1 = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_VOLUME_UP);
    KeyMonitorManager::Monitor monitor1{
        .session_ = 1, .key_ = KeyEvent::KEY_ACTION_DOWN, .action_ = KeyEvent::KEY_ACTION_DOWN, .isRepeat_ = true};
    keyMonitorManager->monitors_.emplace(monitor1);
    EXPECT_EQ(keyMonitorManager->monitors_.size(), 1);

    keyEvent1->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    int32_t delay = 0;
    EXPECT_FALSE(keyMonitorManager->Intercept(keyEvent1, delay));

    keyEvent1->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_FALSE(keyMonitorManager->Intercept(keyEvent1, delay));

    delay = 1;
    keyEvent1->SetKeyCode(monitor1.key_);
    keyEvent1->SetKeyAction(monitor1.action_);
    EXPECT_FALSE(keyMonitorManager->Intercept(keyEvent1, delay));

    keyEvent1->SetKeyCode(KeyEvent::KEY_ACTION_UP);
    EXPECT_FALSE(keyMonitorManager->Intercept(keyEvent1, delay));
}

/**
 * @tc.name: KeyMonitorManagerTest_OnSessionLost_01
 * @tc.desc: Verify the OnSessionLost function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_OnSessionLost_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor1{
        .session_ = 1, .key_ = KeyEvent::KEY_ACTION_DOWN, .action_ = KeyEvent::KEY_ACTION_DOWN, .isRepeat_ = true};
    int32_t session = monitor1.session_ + 1;
    keyMonitorManager->monitors_.emplace(monitor1);
    EXPECT_EQ(keyMonitorManager->monitors_.size(), 1);
    keyMonitorManager->OnSessionLost(session);
    EXPECT_EQ(keyMonitorManager->monitors_.size(), 1);
    session = monitor1.session_;
    keyMonitorManager->OnSessionLost(session);
    EXPECT_EQ(keyMonitorManager->monitors_.size(), 0);
}

/**
 * @tc.name: KeyMonitorManagerTest_Want_01
 * @tc.desc: Verify the Want function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Want_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitorT {
        .session_ = 1,
        .key_ = KeyEvent::KEYCODE_VOLUME_UP,
        .action_ = KeyEvent::KEY_ACTION_UP,
        .isRepeat_ = true
    };
    keyMonitorManager->monitors_.emplace(monitorT);
    std::shared_ptr<KeyEvent> keyEventT = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_VOLUME_UP);
    keyEventT->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    bool ret = monitorT.Want(keyEventT);
    EXPECT_FALSE(ret);
    keyEventT->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    ret = monitorT.Want(keyEventT);
    EXPECT_FALSE(ret);

    keyEventT->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);
    ret = monitorT.Want(keyEventT);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyMonitorManagerTest_Want_02
 * @tc.desc: Verify the Want function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Want_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitorT{
        .session_ = 1,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = KeyEvent::KEY_ACTION_UNKNOWN,
        .isRepeat_ = true
    };
    keyMonitorManager->monitors_.emplace(monitorT);
    std::shared_ptr<KeyEvent> keyEventT = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_VOLUME_UP);
    keyEventT->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    bool ret = monitorT.Want(keyEventT);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyMonitorManagerTest_Monitor_LessThanOperator_02
 * @tc.desc: Verify the less-than operator in Monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Monitor_LessThanOperator_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyMonitorManager::Monitor monitor11 {
        .session_ = 0,
        .key_ = KeyEvent::KEYCODE_B,
        .action_ = KeyEvent::KEY_ACTION_UNKNOWN,
        .isRepeat_ = false,
    };
    KeyMonitorManager::Monitor monitor12 {
        .session_ = 1,
        .key_ = KeyEvent::KEYCODE_A,
        .action_ = KeyEvent::KEY_ACTION_UNKNOWN,
        .isRepeat_ = false,
    };
    EXPECT_TRUE(monitor11 < monitor12);
}

/**
 * @tc.name: KeyMonitorManagerTest_Monitor_LessThanOperator_03
 * @tc.desc: Verify the less-than operator in Monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Monitor_LessThanOperator_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyMonitorManager::Monitor monitor1 {
        .session_ = 1,
        .key_ = KeyEvent::KEYCODE_C,
        .action_ = KeyEvent::KEY_ACTION_CANCEL,
        .isRepeat_ = false,
    };
    KeyMonitorManager::Monitor monitor2 {
        .session_ = 1,
        .key_ = KeyEvent::KEYCODE_C,
        .action_ = KeyEvent::KEY_ACTION_CANCEL,
        .isRepeat_ = true,
    };
    EXPECT_TRUE(monitor1 < monitor2);
}

/**
 * @tc.name: KeyMonitorManagerTest_Monitor_LessThanOperator_04
 * @tc.desc: Verify the less-than operator in Monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Monitor_LessThanOperator_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyMonitorManager::Monitor monitor13 {
        .session_ = 1,
        .key_ = KeyEvent::KEYCODE_A,
        .action_ = KeyEvent::KEY_ACTION_DOWN,
        .isRepeat_ = false,
    };

    KeyMonitorManager::Monitor monitor14 {
        .session_ = 1,
        .key_ = KeyEvent::KEYCODE_B,
        .action_ = KeyEvent::KEY_ACTION_UNKNOWN,
        .isRepeat_ = false,
    };
    EXPECT_TRUE(monitor13 < monitor14);
}

/**
 * @tc.name: KeyMonitorManagerTest_Monitor_LessThanOperator_05
 * @tc.desc: Verify the less-than operator in Monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Monitor_LessThanOperator_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyMonitorManager::Monitor monitor15 {
        .session_ = 1,
        .key_ = KeyEvent::KEYCODE_C,
        .action_ = KeyEvent::KEY_ACTION_UNKNOWN,
        .isRepeat_ = true,
    };
    KeyMonitorManager::Monitor monitor16 {
        .session_ = 1,
        .key_ = KeyEvent::KEYCODE_C,
        .action_ = KeyEvent::KEY_ACTION_CANCEL,
        .isRepeat_ = false,
    };
    EXPECT_TRUE(monitor15 < monitor16);
}

/**
 * @tc.name: KeyMonitorManagerTest_Monitor_Dump
 * @tc.desc: Verify the Monitor Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Monitor_Dump, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyMonitorManager::Monitor monitor {
        .session_ = 1001,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = KeyEvent::KEY_ACTION_DOWN,
        .isRepeat_ = false,
    };
    auto result = monitor.Dump();
    EXPECT_EQ(result, "Session:1001,Key:17,Action:2,IsRepeat:false");
}

/**
 * @tc.name: KeyMonitorManagerTest_Monitor_Dump
 * @tc.desc: Verify the Monitor Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Monitor_Dump_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyMonitorManager::Monitor monitor {
        .session_ = 500,
        .key_ = KeyEvent::KEYCODE_VOLUME_UP,
        .action_ = 999,
        .isRepeat_ = true,
    };
    auto result = monitor.Dump();
    EXPECT_EQ(result, "Session:500,Key:16,Action:999,IsRepeat:true");
}

/**
 * @tc.name: KeyMonitorManagerTest_Want_03
 * @tc.desc: Verify the Want function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Want_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor {
        .session_ = 1,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = KeyEvent::KEY_ACTION_DOWN,
        .isRepeat_ = true,
    };
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    bool result = monitor.Want(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeyMonitorManagerTest_Want_04
 * @tc.desc: Verify the Want function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Want_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor {
        .session_ = 1,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
    };
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    bool result = monitor.Want(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeyMonitorManagerTest_Want_05
 * @tc.desc: Verify the Want function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Want_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor {
        .session_ = 1,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    bool result = monitor.Want(keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: KeyMonitorManagerTest_Want_06
 * @tc.desc: Verify the Want function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Want_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor {
        .session_ = 1,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    int32_t repeatCode = KeyRepeat->GetRepeatKeyCode();
    
    bool result = monitor.Want(keyEvent);
    EXPECT_NE(repeatCode, KeyEvent::KEYCODE_VOLUME_DOWN);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: KeyMonitorManagerTest_Want_07
 * @tc.desc: Verify the Want function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Want_07, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor {
        .session_ = 1,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_DOWN_AND_UP,
        .isRepeat_ = false,
    };
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(999);
    
    bool result = monitor.Want(keyEvent);
    EXPECT_FALSE(result);

    KeyMonitorManager::Monitor monitor1 {
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = 999,
        .isRepeat_ = false,
    };
    std::shared_ptr<KeyEvent> keyEvent1 = KeyEvent::Create();
    keyEvent1->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent1->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    
    result = monitor1.Want(keyEvent1);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeyMonitorManagerTest_AddMonitor_02
 * @tc.desc: Verify the AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_AddMonitor_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor {
        .session_ = 100,
        .key_ = KeyEvent::KEYCODE_HOME,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    std::string name = "test.name";
    int32_t ret = keyMonitorManager->AddMonitor(monitor, name);
    EXPECT_EQ(ret, -PARAM_INPUT_INVALID);

    KeyMonitorManager::Monitor monitor1 {
        .session_ = 100,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = 999,
        .isRepeat_ = false,
    };
    ret = keyMonitorManager->AddMonitor(monitor1, name);
    EXPECT_EQ(ret, -PARAM_INPUT_INVALID);

    KeyMonitorManager::Monitor monitor2 {
        .session_ = 100,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    ret = keyMonitorManager->AddMonitor(monitor2, name);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: KeyMonitorManagerTest_AddMonitor_03
 * @tc.desc: Verify the AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_AddMonitor_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor {
        .session_ = 200,
        .key_ = KeyEvent::KEYCODE_VOLUME_UP,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_DOWN_AND_UP,
        .isRepeat_ = true,
    };
    std::string bundleName = "com.test.app";
    int32_t result1 = keyMonitorManager->AddMonitor(monitor, bundleName);
    EXPECT_EQ(result1, RET_OK);
    int32_t result2 = keyMonitorManager->AddMonitor(monitor, bundleName);
    EXPECT_EQ(result2, RET_OK);
    size_t count = keyMonitorManager->monitors_.count(monitor);
    EXPECT_EQ(count, 1);
}

/**
 * @tc.name: KeyMonitorManagerTest_AddMonitor_04
 * @tc.desc: Verify the AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_AddMonitor_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor {
        .session_ = 300,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    std::string bundleName = BUNDLE_NAME_PARSER.GetBundleName("MEETIME_DTOD_NAME");
    int32_t result = keyMonitorManager->AddMonitor(monitor, bundleName);
    EXPECT_EQ(result, RET_OK);

    auto it = keyMonitorManager->meeTimeMonitor_.find(bundleName);
    EXPECT_NE(it, keyMonitorManager->meeTimeMonitor_.end());
    EXPECT_EQ(it->second, monitor.session_);
}

/**
 * @tc.name: KeyMonitorManagerTest_RemoveMonitor_02
 * @tc.desc: Verify the AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_RemoveMonitor_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor {
        .session_ = 100,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    std::string bundleName = "com.test.app";
    keyMonitorManager->RemoveMonitor(monitor, bundleName);
    
    auto it = keyMonitorManager->meeTimeMonitor_.find(bundleName);
    EXPECT_EQ(it, keyMonitorManager->meeTimeMonitor_.end());
}

/**
 * @tc.name: KeyMonitorManagerTest_RemoveMonitor_03
 * @tc.desc: Verify the AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_RemoveMonitor_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor {
        .session_ = 200,
        .key_ = KeyEvent::KEYCODE_VOLUME_UP,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_DOWN_AND_UP,
        .isRepeat_ = true,
    };
    std::string bundleName = "com.test.app";
    int32_t addResult = keyMonitorManager->AddMonitor(monitor, bundleName);
    EXPECT_EQ(addResult, RET_OK);
    
    auto findIt = keyMonitorManager->monitors_.find(monitor);
    EXPECT_NE(findIt, keyMonitorManager->monitors_.end());

    keyMonitorManager->RemoveMonitor(monitor, bundleName);

    findIt = keyMonitorManager->monitors_.find(monitor);
    EXPECT_EQ(findIt, keyMonitorManager->monitors_.end());

    auto meeTimeIt = keyMonitorManager->meeTimeMonitor_.find(bundleName);
    EXPECT_EQ(meeTimeIt, keyMonitorManager->meeTimeMonitor_.end());
}

/**
 * @tc.name: KeyMonitorManagerTest_Intercept_03
 * @tc.desc: Verify the Intercept function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Intercept_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->AddFlag(InputEvent::EVENT_MEETIME);
    keyMonitorManager->SetMeeTimeSubcriber(true, "Test");
    keyMonitorManager->NotifyMeeTimeMonitor(keyEvent);

    bool result = keyMonitorManager->Intercept(keyEvent);
    EXPECT_TRUE(result);
}


/**
 * @tc.name: KeyMonitorManagerTest_Intercept_04
 * @tc.desc: Verify the Intercept function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Intercept_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyMonitorManager::Monitor monitor {
        .session_ = 100,
        .key_ = KeyEvent::KEYCODE_VOLUME_UP,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    keyMonitorManager->monitors_.emplace(monitor);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    
    bool result = keyMonitorManager->Intercept(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeyMonitorManagerTest_Intercept_05
 * @tc.desc: Verify the Intercept function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Intercept_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyMonitorManager::Monitor monitor1 {
        .session_ = 400,
        .key_ = KeyEvent::KEYCODE_MEDIA_NEXT,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_DOWN_AND_UP,
        .isRepeat_ = false,
    };

    KeyMonitorManager::Monitor monitor2 {
        .session_ = 400,
        .key_ = KeyEvent::KEYCODE_MEDIA_PREVIOUS,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_DOWN_AND_UP,
        .isRepeat_ = false,
    };
    keyMonitorManager->monitors_.emplace(monitor1);
    keyMonitorManager->monitors_.emplace(monitor2);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_MEDIA_NEXT);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    
    bool result = keyMonitorManager->Intercept(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeyMonitorManagerTest_Intercept_06
 * @tc.desc: Verify the Intercept function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Intercept_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    int32_t delay = -50;
    bool result = keyMonitorManager->Intercept(keyEvent, delay);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeyMonitorManagerTest_Intercept_07
 * @tc.desc: Verify the Intercept function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Intercept_07, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor {
        .session_ = 100,
        .key_ = KeyEvent::KEYCODE_VOLUME_UP,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    keyMonitorManager->monitors_.emplace(monitor);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    int32_t delay = 100;
    bool result = keyMonitorManager->Intercept(keyEvent, delay);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeyMonitorManagerTest_Intercept_08
 * @tc.desc: Verify the Intercept function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Intercept_08, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor {
        .session_ = 100,
        .key_ = KeyEvent::KEYCODE_VOLUME_UP,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    keyMonitorManager->monitors_.emplace(monitor);
    keyMonitorManager->SetMeeTimeSubcriber(true, "Test");

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddFlag(InputEvent::EVENT_MEETIME);
    int32_t delay = 100;
    
    bool result = keyMonitorManager->Intercept(keyEvent, delay);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: KeyMonitorManagerTest_Intercept_09
 * @tc.desc: Verify the Intercept function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Intercept_09, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor {
        .session_ = 300,
        .key_ = KeyEvent::KEYCODE_MEDIA_NEXT,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_DOWN_AND_UP,
        .isRepeat_ = false,
    };
    keyMonitorManager->monitors_.emplace(monitor);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_MEDIA_NEXT);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    int32_t delay = 100;
    
    bool result = keyMonitorManager->Intercept(keyEvent, delay);
    EXPECT_FALSE(result);
    EXPECT_GE(keyMonitorManager->pending_.size(), 0);
}

/**
 * @tc.name: KeyMonitorManagerTest_Intercept_010
 * @tc.desc: Verify the Intercept function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_Intercept_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    KeyMonitorManager::Monitor monitor1 {
        .session_ = 400,
        .key_ = KeyEvent::KEYCODE_MEDIA_NEXT,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_DOWN_AND_UP,
        .isRepeat_ = false,
    };

    KeyMonitorManager::Monitor monitor2 {
        .session_ = 400,
        .key_ = KeyEvent::KEYCODE_MEDIA_PREVIOUS,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_DOWN_AND_UP,
        .isRepeat_ = false,
    };
    keyMonitorManager->monitors_.emplace(monitor1);
    keyMonitorManager->monitors_.emplace(monitor2);

    std::shared_ptr<KeyEvent> keyEvent1 = KeyEvent::Create();
    keyEvent1->SetKeyCode(KeyEvent::KEYCODE_MEDIA_NEXT);
    keyEvent1->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    int32_t delay = 100;
    bool result1 = keyMonitorManager->Intercept(keyEvent1, delay);
    EXPECT_FALSE(result1);

    std::shared_ptr<KeyEvent> keyEvent2 = KeyEvent::Create();
    keyEvent2->SetKeyCode(KeyEvent::KEYCODE_MEDIA_PREVIOUS);
    keyEvent2->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    bool result2 = keyMonitorManager->Intercept(keyEvent2, delay);
    EXPECT_FALSE(result2);
}

/**
 * @tc.name: KeyMonitorManagerTest_OnSessionLost_02
 * @tc.desc: Verify the OnSessionLost function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_OnSessionLost_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    std::string name = BUNDLE_NAME_PARSER.GetBundleName("MEETIME_DTOD_NAME");
    keyMonitorManager->meeTimeMonitor_.clear();
    KeyMonitorManager::Monitor monitor1 {
        .session_ = 100,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    
    KeyMonitorManager::Monitor monitor2 {
        .session_ = 200,
        .key_ = KeyEvent::KEYCODE_VOLUME_UP,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_DOWN_AND_UP,
        .isRepeat_ = true,
    };
    keyMonitorManager->monitors_.emplace(monitor1);
    keyMonitorManager->monitors_.emplace(monitor2);
    
    int32_t session = 999;
    keyMonitorManager->OnSessionLost(session);
    EXPECT_EQ(keyMonitorManager->monitors_.size(), 2);
}

/**
 * @tc.name: KeyMonitorManagerTest_OnSessionLost_03
 * @tc.desc: Verify the OnSessionLost function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_OnSessionLost_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    std::string name = BUNDLE_NAME_PARSER.GetBundleName("MEETIME_DTOD_NAME");
    keyMonitorManager->meeTimeMonitor_.clear();
    keyMonitorManager->meeTimeMonitor_.emplace(name, 500); 
    KeyMonitorManager::Monitor monitor1 {
        .session_ = 100,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    keyMonitorManager->monitors_.emplace(monitor1);

    int32_t session = 100;
    keyMonitorManager->OnSessionLost(session);
    auto it = keyMonitorManager->meeTimeMonitor_.find(name);
    EXPECT_NE(it, keyMonitorManager->meeTimeMonitor_.cend());
    EXPECT_EQ(it->second, 500);
    EXPECT_EQ(keyMonitorManager->monitors_.size(), 0);
}

/**
 * @tc.name: KeyMonitorManagerTest_OnSessionLost_04
 * @tc.desc: Verify the OnSessionLost function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_OnSessionLost_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    std::string name = BUNDLE_NAME_PARSER.GetBundleName("MEETIME_DTOD_NAME");
    int32_t session = 300;
    keyMonitorManager->meeTimeMonitor_.clear();
    keyMonitorManager->meeTimeMonitor_.emplace(name, session);
    
    KeyMonitorManager::Monitor monitor1 {
        .session_ = session,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    
    KeyMonitorManager::Monitor monitor2 {
        .session_ = 400,
        .key_ = KeyEvent::KEYCODE_VOLUME_UP,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_DOWN_AND_UP,
        .isRepeat_ = true,
    };
    keyMonitorManager->monitors_.emplace(monitor1);
    keyMonitorManager->monitors_.emplace(monitor2);
    keyMonitorManager->OnSessionLost(session);
    auto it = keyMonitorManager->meeTimeMonitor_.find(name);
    EXPECT_EQ(it, keyMonitorManager->meeTimeMonitor_.cend());
    EXPECT_EQ(keyMonitorManager->monitors_.size(), 1);

    auto remainingMonitor = keyMonitorManager->monitors_.begin();
    EXPECT_EQ(remainingMonitor->session_, 400);
}

/**
 * @tc.name: KeyMonitorManagerTest_OnSessionLost_05
 * @tc.desc: Verify the OnSessionLost function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_OnSessionLost_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    keyMonitorManager->meeTimeMonitor_.clear();
    KeyMonitorManager::Monitor monitor1 {
        .session_ = 100,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    
    KeyMonitorManager::Monitor monitor2 {
        .session_ = 100,
        .key_ = KeyEvent::KEYCODE_VOLUME_UP,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_DOWN_AND_UP,
        .isRepeat_ = true,
    };

    KeyMonitorManager::Monitor monitor3 {
        .session_ = 200,
        .key_ = KeyEvent::KEYCODE_MEDIA_PLAY_PAUSE,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    keyMonitorManager->monitors_.emplace(monitor1);
    keyMonitorManager->monitors_.emplace(monitor2);
    keyMonitorManager->monitors_.emplace(monitor3);
    int32_t session = 100;
    keyMonitorManager->OnSessionLost(session);
    EXPECT_EQ(keyMonitorManager->monitors_.size(), 1);

    auto remainingMonitor = keyMonitorManager->monitors_.begin();
    EXPECT_EQ(remainingMonitor->session_, 200);
    EXPECT_EQ(remainingMonitor->key_, KeyEvent::KEYCODE_MEDIA_PLAY_PAUSE);
}

/**
 * @tc.name: KeyMonitorManagerTest_OnSessionLost_06
 * @tc.desc: Verify the OnSessionLost function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMonitorManagerTest, KeyMonitorManagerTest_OnSessionLost_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyMonitorManager> keyMonitorManager = std::make_shared<KeyMonitorManager>();
    std::string name = BUNDLE_NAME_PARSER.GetBundleName("MEETIME_DTOD_NAME");
    keyMonitorManager->meeTimeMonitor_.clear();
    keyMonitorManager->meeTimeMonitor_.emplace(name, 500);
    KeyMonitorManager::Monitor monitor1 {
        .session_ = 100,
        .key_ = KeyEvent::KEYCODE_VOLUME_DOWN,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_ONLY_DOWN,
        .isRepeat_ = false,
    };
    
    KeyMonitorManager::Monitor monitor2 {
        .session_ = 100,
        .key_ = KeyEvent::KEYCODE_VOLUME_UP,
        .action_ = KeyMonitorManager::MonitorType::MONITOR_ACTION_DOWN_AND_UP,
        .isRepeat_ = true,
    };

    keyMonitorManager->monitors_.emplace(monitor1);
    keyMonitorManager->monitors_.emplace(monitor2);
    int32_t session = 999;
    keyMonitorManager->OnSessionLost(session);
    EXPECT_EQ(keyMonitorManager->monitors_.size(), 2);

    auto it = keyMonitorManager->meeTimeMonitor_.find(name);
    EXPECT_NE(it, keyMonitorManager->meeTimeMonitor_.cend());
    EXPECT_EQ(it->second, 500);
}
} // namespace MMI
} // namespace OHOS
