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

#include "error_multimodal.h"
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
    KeyMonitorManager::Monitor monitor1{
        .session_ = 1, .key_ = KeyEvent::KEYCODE_VOLUME_UP, .action_ = KeyEvent::KEY_ACTION_UP, .isRepeat_ = true};
    int32_t ret = keyMonitorManager->AddMonitor(monitor1);
    EXPECT_EQ(ret, -PARAM_INPUT_INVALID);

    KeyMonitorManager::Monitor monitor2{
        .session_ = 1, .key_ = KeyEvent::KEYCODE_VOLUME_UP, .action_ = KeyEvent::KEY_ACTION_DOWN, .isRepeat_ = true};
    ret = keyMonitorManager->AddMonitor(monitor2);
    EXPECT_EQ(ret, RET_OK);

    ret = keyMonitorManager->AddMonitor(monitor2);
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

    KeyMonitorManager::Monitor monitor1{
        .session_ = 1, .key_ = KeyEvent::KEYCODE_VOLUME_UP, .action_ = KeyEvent::KEY_ACTION_DOWN, .isRepeat_ = true};
    int32_t ret = keyMonitorManager->AddMonitor(monitor1);
    EXPECT_EQ(ret, RET_OK);

    EXPECT_GT(keyMonitorManager->monitors_.size(), size);
    keyMonitorManager->RemoveMonitor(monitor1);

    EXPECT_EQ(keyMonitorManager->monitors_.size(), size);

    keyMonitorManager->RemoveMonitor(monitor1);
    EXPECT_EQ(keyMonitorManager->monitors_.size(), size);
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
    EXPECT_TRUE(ret);

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
} // namespace MMI
} // namespace OHOS
