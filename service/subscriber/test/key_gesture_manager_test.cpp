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

#include "key_option.h"
#include "key_gesture_manager.h"
#include "key_event.h"
#include "mmi_log.h"
#include "nap_process.h"
#include "switch_subscriber_handler.h"
#include "uds_server.h"
#include "want.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyGestureManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t INVALID_ENTITY_ID { -1 };
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
} // namespace MMI
} // namespace OHOS