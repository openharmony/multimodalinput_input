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

#include <fstream>
#include <list>
#include <gtest/gtest.h>

#include "ability_manager_client.h"
#include "display_event_monitor.h"
#include "key_option.h"
#include "key_gesture_manager.h"
#include "key_event.h"
#include "mmi_log.h"
#include "nap_process.h"
#include "switch_subscriber_handler.h"
#include "uds_server.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyGestureManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t INVALID_ENTITY_ID { -1 };
constexpr size_t SINGLE_KEY_PRESSED { 1 };
} // namespace

class KeyGestureManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: KeyGestureManagerTest_Intercept_01
 * @tc.desc: Test the funcation Intercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_Intercept_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    bool ret = keyGestureManager.Intercept(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_RemoveKeyGesture_01
 * @tc.desc: Test the funcation RemoveKeyGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RemoveKeyGesture_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    int32_t id = 1;
    ASSERT_NO_FATAL_FAILURE(keyGestureManager.RemoveKeyGesture(id));
}

/**
 * @tc.name: KeyGestureManagerTest_RemoveKeyGesture_02
 * @tc.desc: Test the funcation RemoveKeyGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RemoveKeyGesture_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    int32_t id = -2;
    ASSERT_NO_FATAL_FAILURE(keyGestureManager.RemoveKeyGesture(id));
}

/**
 * @tc.name: KeyGestureManagerTest_AddKeyGesture_01
 * @tc.desc: Test the funcation AddKeyGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_AddKeyGesture_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    int32_t pid = 1;
    std::shared_ptr<KeyOption> keyOption = nullptr;
    auto callback = [](std::shared_ptr<KeyEvent> event) {};
    int32_t result = keyGestureManager.AddKeyGesture(pid, keyOption, callback);
    EXPECT_EQ(result, INVALID_ENTITY_ID);
}

/**
 * @tc.name: KeyGestureManagerTest_ShouldIntercept_01
 * @tc.desc: Test the funcation ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_ShouldIntercept_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    std::shared_ptr<KeyOption> keyOption = nullptr;
    bool result = keyGestureManager.ShouldIntercept(keyOption);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeyGestureManagerTest_Intercept_02
 * @tc.desc: Test the funcation ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_Intercept_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = 2;
    longPressSingleKey.keyCode_ = 2;
    keyEvent->keyAction_ = KeyEvent::KEY_ACTION_DOWN;
    bool ret = longPressSingleKey.Intercept(keyEvent);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_Intercept_03
 * @tc.desc: Test the funcation ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_Intercept_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = 3;
    longPressSingleKey.keyCode_ = 2;
    keyEvent->keyAction_ = KeyEvent::KEY_ACTION_DOWN;
    bool ret = longPressSingleKey.Intercept(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_Intercept_04
 * @tc.desc: Test the funcation ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_Intercept_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = 2;
    longPressSingleKey.keyCode_ = 2;
    keyEvent->keyAction_ = KeyEvent::KEY_ACTION_UP;
    bool ret = longPressSingleKey.Intercept(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_Intercept_05
 * @tc.desc: Test the funcation ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_Intercept_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = 3;
    longPressSingleKey.keyCode_ = 2;
    keyEvent->keyAction_ = KeyEvent::KEY_ACTION_UP;
    bool ret = longPressSingleKey.Intercept(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_IsWorking_01
 * @tc.desc: Test the funcation ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_IsWorking_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::PullUpAccessibility pullUpAccessibility;
    DISPLAY_MONITOR->screenStatus_ = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF;
    bool ret = pullUpAccessibility.IsWorking();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_IsWorking_02
 * @tc.desc: Test the funcation ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_IsWorking_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::PullUpAccessibility pullUpAccessibility;
    DISPLAY_MONITOR->screenStatus_ = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON;
    DISPLAY_MONITOR->isScreenLocked_ = true;
    bool ret = pullUpAccessibility.IsWorking();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_IsWorking_03
 * @tc.desc: Test the funcation ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_IsWorking_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::PullUpAccessibility pullUpAccessibility;
    DISPLAY_MONITOR->screenStatus_ = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON;
    DISPLAY_MONITOR->isScreenLocked_ = false;
    bool ret = pullUpAccessibility.IsWorking();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_OnTriggerAll_01
 * @tc.desc: Test the funcation OnTriggerAll
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_OnTriggerAll_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::PullUpAccessibility pullUpAccessibility;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(pullUpAccessibility.OnTriggerAll(keyEvent));
}

/**
 * @tc.name: KeyGestureManagerTest_RecognizeGesture_01
 * @tc.desc: Test the funcation RecognizeGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RecognizeGesture_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {1, 2, 3};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    std::vector<int32_t> pressedKeys = {1};
    EXPECT_TRUE(pressedKeys.size() == SINGLE_KEY_PRESSED);
    bool ret = longPressCombinationKey.RecognizeGesture(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_RecognizeGesture_02
 * @tc.desc: Test the funcation RecognizeGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RecognizeGesture_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = { 1, 2, 3 };
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    std::vector<int32_t> pressedKeys = { 2, 3, 4 };
    EXPECT_FALSE(pressedKeys.size() == SINGLE_KEY_PRESSED);
    bool ret = longPressCombinationKey.RecognizeGesture(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_TriggerAll_01
 * @tc.desc: Test the funcation TriggerAll
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_TriggerAll_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = { 1, 2, 3 };
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(longPressCombinationKey.TriggerAll(keyEvent));
}
} // namespace MMI
} // namespace OHOS