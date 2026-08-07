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

#include <algorithm>
#include <climits>

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
 * @tc.desc: Test GetFirstLine with empty path
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
 * @tc.name: WatchdogTaskTest_GetFirstLine_002
 * @tc.desc: Test GetFirstLine with non-existent path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetFirstLine_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string path = "/nonexistent/path/to/file";
    auto ret = watchdogtask.GetFirstLine(path);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: WatchdogTaskTest_GetFirstLine_003
 * @tc.desc: Test GetFirstLine with a valid /proc/self/comm file
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetFirstLine_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string path = "/proc/self/comm";
    auto ret = watchdogtask.GetFirstLine(path);
    EXPECT_FALSE(ret.empty());
}

/**
 * @tc.name: WatchdogTaskTest_GetFirstLine_004
 * @tc.desc: Test GetFirstLine with a relative path containing special chars
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetFirstLine_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string path = "../nonexistent/../../file";
    auto ret = watchdogtask.GetFirstLine(path);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: WatchdogTaskTest_GetFirstLine_005
 * @tc.desc: Test GetFirstLine with a directory path instead of file
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetFirstLine_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string path = "/proc/self";
    auto ret = watchdogtask.GetFirstLine(path);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: WatchdogTaskTest_GetFirstLine_006
 * @tc.desc: Test GetFirstLine with root directory
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetFirstLine_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string path = "/";
    auto ret = watchdogtask.GetFirstLine(path);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: WatchdogTaskTest_GetFirstLine_007
 * @tc.desc: Test GetFirstLine with a long path exceeding PATH_MAX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetFirstLine_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string path(5000, 'a');
    auto ret = watchdogtask.GetFirstLine(path);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: WatchdogTaskTest_GetProcessNameFromProcCmdline_001
 * @tc.desc: Test GetProcessNameFromProcCmdline with invalid pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetProcessNameFromProcCmdline_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    int32_t pid = -1;
    auto ret = watchdogtask.GetProcessNameFromProcCmdline(pid);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: WatchdogTaskTest_GetProcessNameFromProcCmdline_003
 * @tc.desc: Test GetProcessNameFromProcCmdline with pid 1 (init process)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetProcessNameFromProcCmdline_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    int32_t pid = 1;
    auto ret = watchdogtask.GetProcessNameFromProcCmdline(pid);
    EXPECT_FALSE(ret.empty());
}

/**
 * @tc.name: WatchdogTaskTest_GetProcessNameFromProcCmdline_004
 * @tc.desc: Test GetProcessNameFromProcCmdline with current process pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetProcessNameFromProcCmdline_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    int32_t pid = static_cast<int32_t>(getpid());
    auto ret = watchdogtask.GetProcessNameFromProcCmdline(pid);
    EXPECT_FALSE(ret.empty());
}

/**
 * @tc.name: WatchdogTaskTest_GetProcessNameFromProcCmdline_005
 * @tc.desc: Test GetProcessNameFromProcCmdline with a very large pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetProcessNameFromProcCmdline_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    int32_t pid = 99999999;
    auto ret = watchdogtask.GetProcessNameFromProcCmdline(pid);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: WatchdogTaskTest_IsNumberic_001
 * @tc.desc: Test IsNumberic with a valid numeric string
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
 * @tc.name: WatchdogTaskTest_IsNumberic_002
 * @tc.desc: Test IsNumberic with an empty string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsNumberic_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string testString;
    bool ret = watchdogtask.IsNumberic(testString);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_IsNumberic_003
 * @tc.desc: Test IsNumberic with a string containing letters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsNumberic_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string testString = "123abc";
    bool ret = watchdogtask.IsNumberic(testString);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_IsNumberic_004
 * @tc.desc: Test IsNumberic with a negative number string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsNumberic_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string testString = "-123";
    bool ret = watchdogtask.IsNumberic(testString);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_IsNumberic_005
 * @tc.desc: Test IsNumberic with a decimal string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsNumberic_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string testString = "12.34";
    bool ret = watchdogtask.IsNumberic(testString);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_IsNumberic_006
 * @tc.desc: Test IsNumberic with a single digit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsNumberic_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string testString = "0";
    bool ret = watchdogtask.IsNumberic(testString);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_IsNumberic_007
 * @tc.desc: Test IsNumberic with spaces
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsNumberic_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string testString = " 123 ";
    bool ret = watchdogtask.IsNumberic(testString);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_IsNumberic_008
 * @tc.desc: Test IsNumberic with special characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsNumberic_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string testString = "123\n";
    bool ret = watchdogtask.IsNumberic(testString);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_IsNumberic_009
 * @tc.desc: Test IsNumberic with leading zeros
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsNumberic_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string testString = "00123";
    bool ret = watchdogtask.IsNumberic(testString);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_IsNumberic_010
 * @tc.desc: Test IsNumberic with very large number string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsNumberic_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string testString = "99999999999999999999";
    bool ret = watchdogtask.IsNumberic(testString);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_IsProcessDebug_001
 * @tc.desc: Test IsProcessDebug with pid 1
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
 * @tc.name: WatchdogTaskTest_IsProcessDebug_002
 * @tc.desc: Test IsProcessDebug with negative pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsProcessDebug_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    int32_t pid = -1;
    bool ret = watchdogtask.IsProcessDebug(pid);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_IsProcessDebug_003
 * @tc.desc: Test IsProcessDebug with current process pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsProcessDebug_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    int32_t pid = static_cast<int32_t>(getpid());
    bool ret = watchdogtask.IsProcessDebug(pid);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_IsProcessDebug_004
 * @tc.desc: Test IsProcessDebug with zero pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsProcessDebug_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    int32_t pid = 0;
    bool ret = watchdogtask.IsProcessDebug(pid);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_GetBlockDescription_001
 * @tc.desc: Test GetBlockDescription with a large interval
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
 * @tc.name: WatchdogTaskTest_GetBlockDescription_002
 * @tc.desc: Test GetBlockDescription with zero interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetBlockDescription_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string desc = "Watchdog: thread(mmi_service) blocked 0s";
    uint64_t timeInterval = 0;
    auto ret = watchdogtask.GetBlockDescription(timeInterval);
    EXPECT_EQ(ret, desc);
}

/**
 * @tc.name: WatchdogTaskTest_GetBlockDescription_003
 * @tc.desc: Test GetBlockDescription with a small interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetBlockDescription_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string desc = "Watchdog: thread(mmi_service) blocked 1s";
    uint64_t timeInterval = 1;
    auto ret = watchdogtask.GetBlockDescription(timeInterval);
    EXPECT_EQ(ret, desc);
}

/**
 * @tc.name: WatchdogTaskTest_GetBlockDescription_004
 * @tc.desc: Test GetBlockDescription with max uint64 interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetBlockDescription_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    uint64_t timeInterval = UINT64_MAX;
    auto ret = watchdogtask.GetBlockDescription(timeInterval);
    EXPECT_FALSE(ret.empty());
    EXPECT_NE(ret.find("Watchdog"), std::string::npos);
    EXPECT_NE(ret.find("mmi_service"), std::string::npos);
}

/**
 * @tc.name: WatchdogTaskTest_GetBlockDescription_005
 * @tc.desc: Test GetBlockDescription with a 10-second interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetBlockDescription_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string desc = "Watchdog: thread(mmi_service) blocked 10s";
    uint64_t timeInterval = 10;
    auto ret = watchdogtask.GetBlockDescription(timeInterval);
    EXPECT_EQ(ret, desc);
}

/**
 * @tc.name: WatchdogTaskTest_GetSelfProcName_001
 * @tc.desc: Test GetSelfProcName returns non-empty and valid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetSelfProcName_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    auto ret = watchdogtask.GetSelfProcName();
    EXPECT_FALSE(ret.empty());
    for (const auto &ch : ret) {
        EXPECT_TRUE((ch >= '0' && ch <= '9') ||
            (ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            ch == '.' || ch == '-' || ch == '_');
    }
}

/**
 * @tc.name: WatchdogTaskTest_SendEvent_001
 * @tc.desc: Test SendEvent with a normal message and event name
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

/**
 * @tc.name: WatchdogTaskTest_GetProcessNameFromProcCmdline_006
 * @tc.desc: Test GetProcessNameFromProcCmdline reads a valid proc entry with path separators
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetProcessNameFromProcCmdline_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    int32_t pid = static_cast<int32_t>(getpid());
    std::string name = watchdogtask.GetProcessNameFromProcCmdline(pid);
    EXPECT_FALSE(name.empty());
    EXPECT_EQ(name.find('/'), std::string::npos);
}

/**
 * @tc.name: WatchdogTaskTest_IsNumberic_011
 * @tc.desc: Test IsNumberic with only whitespace string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsNumberic_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string testString = "   ";
    bool ret = watchdogtask.IsNumberic(testString);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_IsNumberic_012
 * @tc.desc: Test IsNumberic with hex-like string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsNumberic_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string testString = "0xFF";
    bool ret = watchdogtask.IsNumberic(testString);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_GetBlockDescription_006
 * @tc.desc: Test GetBlockDescription with interval near boundary
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetBlockDescription_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    uint64_t timeInterval = 3600;
    auto ret = watchdogtask.GetBlockDescription(timeInterval);
    std::string expected = "Watchdog: thread(mmi_service) blocked 3600s";
    EXPECT_EQ(ret, expected);
}

/**
 * @tc.name: WatchdogTaskTest_GetBlockDescription_007
 * @tc.desc: Test GetBlockDescription with a small interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetBlockDescription_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    uint64_t timeInterval = 100;
    auto ret = watchdogtask.GetBlockDescription(timeInterval);
    std::string expected = "Watchdog: thread(mmi_service) blocked 100s";
    EXPECT_EQ(ret, expected);
}

/**
 * @tc.name: WatchdogTaskTest_IsProcessDebug_005
 * @tc.desc: Test IsProcessDebug with a very large pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsProcessDebug_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    int32_t pid = 2147483647;
    bool ret = watchdogtask.IsProcessDebug(pid);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_GetSelfProcName_003
 * @tc.desc: Test GetSelfProcName returns consistent results on multiple calls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetSelfProcName_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    auto ret1 = watchdogtask.GetSelfProcName();
    auto ret2 = watchdogtask.GetSelfProcName();
    EXPECT_EQ(ret1, ret2);
}

/**
 * @tc.name: WatchdogTaskTest_GetSelfProcName_004
 * @tc.desc: Test GetSelfProcName with /proc/self/comm readable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetSelfProcName_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string selfComm = watchdogtask.GetFirstLine("/proc/self/comm");
    auto procName = watchdogtask.GetSelfProcName();
    if (!selfComm.empty()) {
        std::string sanitized = selfComm;
        sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(),
            [](unsigned char c) {
                return !((c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') ||
                    c == '.' || c == '-' || c == '_');
            }), sanitized.end());
        EXPECT_EQ(procName, sanitized);
    }
}

/**
 * @tc.name: WatchdogTaskTest_IsNumberic_013
 * @tc.desc: Test IsNumberic with very long numeric string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_IsNumberic_013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    std::string testString(10000, '9');
    bool ret = watchdogtask.IsNumberic(testString);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: WatchdogTaskTest_GetBlockDescription_008
 * @tc.desc: Test GetBlockDescription thread name component
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatchdogTaskTest, WatchdogTaskTest_GetBlockDescription_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WatchdogTask watchdogtask;
    uint64_t timeInterval = 30;
    auto ret = watchdogtask.GetBlockDescription(timeInterval);
    EXPECT_NE(ret.find("mmi_service"), std::string::npos);
    EXPECT_NE(ret.find("30"), std::string::npos);
}
} // namespace MMI
} // namespace OHOS