/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <fcntl.h>
#include <gtest/gtest.h>

#include <cerrno>
#include <cstdio>

#include "event_dump.h"
#include "event_log_helper.h"
#include "i_input_windows_manager.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "input_manager.h"
#include "input_manager_util.h"
#include "mouse_event_normalize.h"
#include "multimodal_event_handler.h"
#include "system_info.h"
#include "event_statistic.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventDumpTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
const std::string TEST_FILE_NAME = "/data/log.log";
constexpr int32_t MAX_COMMAND_COUNT { 32 };
} // namespace

class EventDumpTest : public testing::Test {
public:
    void SetUp() override
    {
        fd_ = open(TEST_FILE_NAME.c_str(), O_WRONLY);
    }

    void TearDown() override
    {
        close(fd_);
        fd_ = -1;
    }

    int32_t fd_;
};

/**
 * @tc.name: EventDumpTest_CheckCount_001
 * @tc.desc: Event dump CheckCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args;
    int32_t count = 0;
    MMIEventDump->CheckCount(fd_, args, count);
    EXPECT_EQ(count, 0);
}

/**
 * @tc.name: EventDumpTest_CheckCount_002
 * @tc.desc: Event dump CheckCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"--help"};
    int32_t count = 0;
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    EXPECT_EQ(count, 1);
}

/**
 * @tc.name: EventDumpTest_CheckCount_003
 * @tc.desc: Event dump CheckCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-h"};
    int32_t count = 0;
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    EXPECT_EQ(count, 1);
}

/**
 * @tc.name: EventDumpTest_CheckCount_004
 * @tc.desc: Event dump CheckCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-abc"};
    int32_t count = 0;
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    EXPECT_EQ(count, 3);
}

/**
 * @tc.name: EventDumpTest_CheckCount_005
 * @tc.desc: Event dump CheckCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-a", "--help", "foo", "-bc", "bar"};
    int32_t count = 0;
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    MMIEventDump->DumpEventHelp(fd_, args);
    EXPECT_EQ(count, 4);
}

/**
 * @tc.name: EventDumpTest_006
 * @tc.desc: Event dump InputDeviceManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-d"};
    int32_t count = 0;
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->Dump(fd_, args));
}

/**
 * @tc.name: EventDumpTest_007
 * @tc.desc: Event dump DeviceList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-l"};
    int32_t count = 0;
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->DumpDeviceList(fd_, args));
}

/**
 * @tc.name: EventDumpTest_008
 * @tc.desc: Event dump WindowsManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-w"};
    int32_t count = 0;
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->Dump(fd_, args));
}

/**
 * @tc.name: EventDumpTest_009
 * @tc.desc: Event dump UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-u"};
    int32_t count = 0;
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    ASSERT_NO_FATAL_FAILURE(udsServer->Dump(fd_, args));
}

/**
 * @tc.name: EventDumpTest_010
 * @tc.desc: Event dump SubscriberHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-s"};
    int32_t count = 0;
    auto subscriberHandler = InputHandler->GetSubscriberHandler();
    CHKPV(subscriberHandler);
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    ASSERT_NO_FATAL_FAILURE(subscriberHandler->Dump(fd_, args));
}

/**
 * @tc.name: EventDumpTest_011
 * @tc.desc: Event dump MonitorHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-o"};
    int32_t count = 0;
    auto monitorHandler = InputHandler->GetMonitorHandler();
    CHKPV(monitorHandler);
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    ASSERT_NO_FATAL_FAILURE(monitorHandler->Dump(fd_, args));
}

/**
 * @tc.name: EventDumpTest_012
 * @tc.desc: Event dump InterceptorHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-i"};
    int32_t count = 0;
    auto interceptorHandler = InputHandler->GetInterceptorHandler();
    CHKPV(interceptorHandler);
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler->Dump(fd_, args));
}

/**
 * @tc.name: EventDumpTest_013
 * @tc.desc: Event dump FilterHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-f"};
    int32_t count = 0;
    auto filterHandler = InputHandler->GetFilterHandler();
    CHKPV(filterHandler);
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    ASSERT_NO_FATAL_FAILURE(filterHandler->Dump(fd_, args));
}

/**
 * @tc.name: EventDumpTest_014
 * @tc.desc: Event dump MouseEventHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-m"};
    int32_t count = 0;
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    ASSERT_NO_FATAL_FAILURE(MouseEventHdr->Dump(fd_, args));
}

/**
 * @tc.name: EventDumpTest_015
 * @tc.desc: Event dump event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-e"};
    int32_t count = 0;
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    ASSERT_NO_FATAL_FAILURE(EventStatistic::Dump(fd_, args));
}

/**
 * @tc.name: EventDumpTest_CheckCount_001
 * @tc.desc: Verify CheckCount with args containing options starting with "--"
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_CheckCount_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t count = 0;
    std::vector<std::string> args = {"--help", "--version"};
    MMIEventDump->CheckCount(fd_, args, count);
    EXPECT_EQ(count, 2);
}

/**
 * @tc.name: EventDumpTest_CheckCount_002
 * @tc.desc: Verify CheckCount with args containing options starting with "-"
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_CheckCount_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t count = 0;
    std::vector<std::string> args = {"-abc", "-d"};
    MMIEventDump->CheckCount(fd_, args, count);
    EXPECT_EQ(count, 4);
}

/**
 * @tc.name: EventDumpTest_CheckCount_003
 * @tc.desc: Verify CheckCount with mixed args, including normal strings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_CheckCount_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t count = 0;
    std::vector<std::string> args = {"--opt", "-xy", "normal", "-z"};
    MMIEventDump->CheckCount(fd_, args, count);
    EXPECT_EQ(count, 4);
}

/**
 * @tc.name: EventDumpTest_CheckCount_004
 * @tc.desc: Verify CheckCount with empty args
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_CheckCount_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t count = 0;
    std::vector<std::string> args = {};
    MMIEventDump->CheckCount(fd_, args, count);
    EXPECT_EQ(count, 0);
}

/**
 * @tc.name: EventDumpTest_ParseCommand_001
 * @tc.desc: Verify ParseCommand when args is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_ParseCommand_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args;
    EXPECT_NO_FATAL_FAILURE(MMIEventDump->ParseCommand(fd_, args));
}

/**
 * @tc.name: EventDumpTest_ParseCommand_002
 * @tc.desc: Verify ParseCommand when count > MAX_COMMAND_COUNT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_ParseCommand_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args(MAX_COMMAND_COUNT + 5, "--test");
    EXPECT_NO_FATAL_FAILURE(MMIEventDump->ParseCommand(fd_, args));
}

/**
 * @tc.name: EventDumpTest_ParseCommand_003
 * @tc.desc: Verify ParseCommand with valid '-h' option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_ParseCommand_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-h"};
    EXPECT_NO_FATAL_FAILURE(MMIEventDump->ParseCommand(fd_, args));
}

/**
 * @tc.name: EventDumpTest_ParseCommand_004
 * @tc.desc: Verify ParseCommand with valid '-d' option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_ParseCommand_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-d"};
    EXPECT_NO_FATAL_FAILURE(MMIEventDump->ParseCommand(fd_, args));
}

/**
 * @tc.name: EventDumpTest_ParseCommand_005
 * @tc.desc: Verify ParseCommand with valid '-l' option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_ParseCommand_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-l"};
    EXPECT_NO_FATAL_FAILURE(MMIEventDump->ParseCommand(fd_, args));
}

/**
 * @tc.name: EventDumpTest_ParseCommand_006
 * @tc.desc: Verify ParseCommand with valid '-w' option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_ParseCommand_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-w"};
    EXPECT_NO_FATAL_FAILURE(MMIEventDump->ParseCommand(fd_, args));
}

/**
 * @tc.name: EventDumpTest_ParseCommand_007
 * @tc.desc: Verify ParseCommand with valid '-e' option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_ParseCommand_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-e"};
    EXPECT_NO_FATAL_FAILURE(MMIEventDump->ParseCommand(fd_, args));
}

/**
 * @tc.name: EventDumpTest_ParseCommand_008
 * @tc.desc: Verify ParseCommand with invalid option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_ParseCommand_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-z"};
    EXPECT_NO_FATAL_FAILURE(MMIEventDump->ParseCommand(fd_, args));
}

/**
 * @tc.name: EventDumpTest_ParseCommand_009
 * @tc.desc: Verify ParseCommand with mixed valid and invalid options
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_ParseCommand_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"-h", "-z", "-d"};
    EXPECT_NO_FATAL_FAILURE(MMIEventDump->ParseCommand(fd_, args));
}

/**
 * @tc.name: EventDumpTest_DumpHelp_001
 * @tc.desc: Verify DumpHelp prints all expected help messages.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_DumpHelp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *tmpFile = "/data/tmp_dumphelp.log";
    int fd = open(tmpFile, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);
    MMIEventDump->DumpHelp(fd);
    close(fd);
    std::string content;
    {
        int fdRead = open(tmpFile, O_RDONLY);
        ASSERT_GE(fdRead, 0);
        char buf[1024];
        ssize_t bytes = read(fdRead, buf, sizeof(buf) - 1);
        ASSERT_GT(bytes, 0);
        buf[bytes] = '\0';
        content = buf;
        close(fdRead);
    }
    EXPECT_NE(content.find("-h, --help"), std::string::npos);
    EXPECT_NE(content.find("-d, --device"), std::string::npos);
    EXPECT_NE(content.find("-l, --devicelist"), std::string::npos);
    EXPECT_NE(content.find("-w, --windows"), std::string::npos);
    EXPECT_NE(content.find("-e, --event"), std::string::npos);
    unlink(tmpFile);
}

/**
 * @tc.name: EventDumpTest_DumpEventHelp_001
 * @tc.desc: Verify DumpEventHelp calls DumpHelp correctly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDumpTest, EventDumpTest_DumpEventHelp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *tmpFile = "/data/tmp_dumpeventhelp.log";
    int fd = open(tmpFile, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);
    std::vector<std::string> args = {"-h"};
    MMIEventDump->DumpEventHelp(fd, args);
    close(fd);
    std::string content;
    {
        int fdRead = open(tmpFile, O_RDONLY);
        ASSERT_GE(fdRead, 0);
        char buf[1024];
        ssize_t bytes = read(fdRead, buf, sizeof(buf) - 1);
        ASSERT_GT(bytes, 0);
        buf[bytes] = '\0';
        content = buf;
        close(fdRead);
    }
    EXPECT_NE(content.find("Usage:"), std::string::npos);
    unlink(tmpFile);
}
} // namespace MMI
} // namespace OHOS