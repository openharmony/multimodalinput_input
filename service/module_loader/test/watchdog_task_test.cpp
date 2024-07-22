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

#include "mmi_log.h"
#include "watchdog_task.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "WatchdogTaskTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class WatchdogTaskTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: WatchdogTaskTest_GetFirstLine_001
 * @tc.desc: Test the function GetFirstLine
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetFirstLine_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string path;
    auto ret = watchdogtask.GetFirstLine(path);
    EXPECT_EQ(ret, path);
}

/**
 * @tc.name: WatchdogTaskTest_GetProcessNameFromProcCmdline_001
 * @tc.desc: Test the function GetProcessNameFromProcCmdline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetProcessNameFromProcCmdline_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string expectedDescription;
    int32_t pid = -1;
    auto ret = watchdogtask.GetProcessNameFromProcCmdline(pid);
    EXPECT_EQ(ret, expectedDescription);
}

/**
 * @tc.name: WatchdogTaskTest_IsNumberic_001
 * @tc.desc: Test the function IsNumberic
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsNumberic_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string testString = "12345";
    bool ret = watchdogtask.IsNumberic(testString);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_IsProcessDebug_001
 * @tc.desc: Test the function IsProcessDebug
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsProcessDebug_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    int32_t pid = 1;
    bool ret = watchdogtask.IsProcessDebug(pid);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_GetBlockDescription_001
 * @tc.desc: Test the function GetBlockDescription
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetBlockDescription_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string desc = "Watchdog: thread(mmi_service) blocked 5000s";
    uint64_t timeInterval = 5000;
    auto ret = watchdogtask.GetBlockDescription(timeInterval);
    EXPECT_EQ(ret, desc);
}

/**
 * @tc.name: WatchdogTaskTest_GetSelfProcName_001
 * @tc.desc: Test the function GetSelfProcName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetSelfProcName_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string desc = "ut-mmi-service-";
    auto ret = watchdogtask.GetSelfProcName();
    EXPECT_NE(ret, desc);
}

/**
 * @tc.name: WatchdogTaskTest_SendEvent_001
 * @tc.desc: Test the function SendEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_SendEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string message = "This is a test message";
    std::string event = "TestEvent";
    ASSERT_NO_FATAL_FAILURE(watchdogtask.SendEvent(message, event));
}
} // namespace MMI
} // namespace OHOS