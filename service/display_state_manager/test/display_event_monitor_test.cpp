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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "display_event_monitor.h"
#include "mmi_log.h"
#include "mock.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DisplayEventMonitorTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
} // namespace

class DisplayEventMonitorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void DisplayEventMonitorTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}
void DisplayEventMonitorTest::TearDownTestCase()
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}

/**
 * @tc.name: DisplayEventMonitorTest_UpdateShieldStatusOnScreenOn_001
 * @tc.desc: Test the function UpdateShieldStatusOnScreenOn
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayEventMonitorTest, DisplayEventMonitorTest_UpdateShieldStatusOnScreenOn_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DISPLAY_MONITOR->shieldModeBeforeSreenOff_ = 0;
    EXPECT_NO_FATAL_FAILURE(DISPLAY_MONITOR->UpdateShieldStatusOnScreenOn());
    DISPLAY_MONITOR->shieldModeBeforeSreenOff_ = 1;
    EXPECT_NO_FATAL_FAILURE(DISPLAY_MONITOR->UpdateShieldStatusOnScreenOn());
    DISPLAY_MONITOR->shieldModeBeforeSreenOff_ = -1;
    EXPECT_NO_FATAL_FAILURE(DISPLAY_MONITOR->UpdateShieldStatusOnScreenOn());
}

/**
 * @tc.name: DisplayEventMonitorTest_UpdateShieldStatusOnScreenOff_001
 * @tc.desc: Test the function UpdateShieldStatusOnScreenOff
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayEventMonitorTest, DisplayEventMonitorTest_UpdateShieldStatusOnScreenOff_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DISPLAY_MONITOR->shieldModeBeforeSreenOff_ = 10;
    EXPECT_NO_FATAL_FAILURE(DISPLAY_MONITOR->UpdateShieldStatusOnScreenOff());
    DISPLAY_MONITOR->shieldModeBeforeSreenOff_ = 5;
    EXPECT_NO_FATAL_FAILURE(DISPLAY_MONITOR->UpdateShieldStatusOnScreenOff());
    DISPLAY_MONITOR->shieldModeBeforeSreenOff_ = -1;
    EXPECT_NO_FATAL_FAILURE(DISPLAY_MONITOR->UpdateShieldStatusOnScreenOff());
}

/**
 * @tc.name: DisplayEventMonitorTest_InitCommonEventSubscriber_001
 * @tc.desc: Test the function InitCommonEventSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayEventMonitorTest, DisplayEventMonitorTest_InitCommonEventSubscriber_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DISPLAY_MONITOR->hasInit_ = true;
    EXPECT_NO_FATAL_FAILURE(DISPLAY_MONITOR->InitCommonEventSubscriber());
}

/**
 * @tc.name: DisplayEventMonitorTest_InitCommonEventSubscriber_002
 * @tc.desc: Test the function InitCommonEventSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayEventMonitorTest, DisplayEventMonitorTest_InitCommonEventSubscriber_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DISPLAY_MONITOR->hasInit_ = false;
    EXPECT_NO_FATAL_FAILURE(DISPLAY_MONITOR->InitCommonEventSubscriber());
    ASSERT_TRUE(DISPLAY_MONITOR->hasInit_);
}

/**
 * @tc.name: DisplayEventMonitorTest_IsCommonEventSubscriberInit_001
 * @tc.desc: Test the function IsCommonEventSubscriberInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayEventMonitorTest, DisplayEventMonitorTest_IsCommonEventSubscriberInit_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DISPLAY_MONITOR->hasInit_ = true;
    EXPECT_NO_FATAL_FAILURE(DISPLAY_MONITOR->IsCommonEventSubscriberInit());
    DISPLAY_MONITOR->hasInit_ = false;
    EXPECT_NO_FATAL_FAILURE(DISPLAY_MONITOR->IsCommonEventSubscriberInit());
}

/**
 * @tc.name: DisplayEventMonitorTest_SendCancelEventWhenLock_001
 * @tc.desc: Test the function InitCommonEventSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayEventMonitorTest, DisplayEventMonitorTest_SendCancelEventWhenLock_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(DISPLAY_MONITOR->SendCancelEventWhenLock());
}
} // namespace MMI
} // namespace OHOS