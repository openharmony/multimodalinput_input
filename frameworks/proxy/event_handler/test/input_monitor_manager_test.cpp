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

#include <gtest/gtest.h>

#include "input_monitor_manager.h"
#include "input_handler_type.h"
#include "tablet_event_input_subscribe_manager.h"
#include "mmi_log.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputMonitorManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputMonitorManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: MarkConsumed_Test_001
 * @tc.desc: Test MarkConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMonitorManagerTest, MarkConsumed_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputMonitorManager manager;
    int32_t monitorId = 1;
    int32_t eventId = 2;
    ASSERT_NO_FATAL_FAILURE(manager.MarkConsumed(monitorId, eventId));
}

/**
 * @tc.name: CheckMonitorValid_ShouldReturnTrue_001
 * @tc.desc: Test CheckMonitorValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMonitorManagerTest, CheckMonitorValid_ShouldReturnTrue_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::MMI::InputMonitorManager inputMonitorManager;
    EXPECT_TRUE(inputMonitorManager.CheckMonitorValid(TOUCH_GESTURE_TYPE_SWIPE, ALL_FINGER_COUNT));
}

/**
 * @tc.name: CheckMonitorValid_ShouldReturnTrue_002
 * @tc.desc: Test CheckMonitorValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMonitorManagerTest, CheckMonitorValid_ShouldReturnTrue_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::MMI::InputMonitorManager inputMonitorManager;
    EXPECT_FALSE(inputMonitorManager.CheckMonitorValid(TOUCH_GESTURE_TYPE_SWIPE, INVALID_HANDLER_ID));
}

 /**
 * @tc.name: CheckMonitorValid_ShouldReturnTrue_003
 * @tc.desc: Test CheckMonitorValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMonitorManagerTest, CheckMonitorValid_ShouldReturnTrue_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::MMI::InputMonitorManager inputMonitorManager;
    EXPECT_TRUE(inputMonitorManager.CheckMonitorValid(TOUCH_GESTURE_TYPE_PINCH, MAX_FINGERS_COUNT));
}

 /**
 * @tc.name: CheckMonitorValid_ShouldReturnTrue_004
 * @tc.desc: Test CheckMonitorValid
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(InputMonitorManagerTest, CheckMonitorValid_ShouldReturnTrue_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::MMI::InputMonitorManager inputMonitorManager;
    EXPECT_FALSE(inputMonitorManager.CheckMonitorValid(TOUCH_GESTURE_TYPE_SWIPE, ERROR_EXCEED_MAX_COUNT));
}

 /**
 * @tc.name: CheckMonitorValid_ShouldReturnTrue_005
 * @tc.desc: Test CheckMonitorValid
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(InputMonitorManagerTest, CheckMonitorValid_ShouldReturnTrue_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::MMI::InputMonitorManager inputMonitorManager;
    EXPECT_FALSE(inputMonitorManager.CheckMonitorValid(TOUCH_GESTURE_TYPE_NONE, FOUR_FINGER_COUNT));
}

} // namespace MMI
} // namespace OHOS