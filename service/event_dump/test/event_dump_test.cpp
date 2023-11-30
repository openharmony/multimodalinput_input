/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <event_dump.h>

#include "event_log_helper.h"

#include "input_manager_util.h"
#include "multimodal_event_handler.h"
#include "system_info.h"
#include "input_manager.h"
#include <fcntl.h>
#include <cstdio>
#include <cerrno>

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
const char *testFileName = "/data/log.log";
}  // namespace

class EventDumpTest : public testing::Test {
public:
void SetUp() override
{
    fd_ = open(testFileName, O_WRONLY);
}

void TearDown() override
{
    close(fd_);
}

int32_t fd_;
};

/**
 * @tc.name: EventDumpTest_CheckCount_001
 * @tc.desc: Event dump CheckCount
 * @tc.type: FUNC
 * @tc.require:AR000GJG6G
 */
HWTEST_F(EventDumpTest, EventDumpTest001, TestSize.Level1)
{
    std::vector<std::string> args;
    size_t count = 0;
    MMIEventDump->CheckCount(fd_, args, count);
    EXPECT_EQ(count, 0);
}

HWTEST_F(EventDumpTest, EventDumpTest002, TestSize.Level1)
{
    std::vector<std::string> args = {"--help"};
    size_t count = 0;
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    EXPECT_EQ(count, 1);
}

HWTEST_F(EventDumpTest, EventDumpTest003, TestSize.Level1)
{
    std::vector<std::string> args = {"-h"};
    size_t count = 0;
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    EXPECT_EQ(count, 1);
}

HWTEST_F(EventDumpTest, EventDumpTest004, TestSize.Level1) {
    std::vector<std::string> args = {"-abc"};
    size_t count = 0;
    MMIEventDump->CheckCount(fd_, args, count);
    MMIEventDump->ParseCommand(fd_, args);
    EXPECT_EQ(count, 3);
}

// 定义一个测试用例，名为MixedOptions，用于测试混合的选项和非选项的参数列表
HWTEST_F(EventDumpTest, EventDumpTest005, TestSize.Level1) {
    // 定义一个包含混合的选项和非选项的参数列表
    std::vector<std::string> args = {"-a", "--help", "foo", "-bc", "bar"};
    // 定义一个选项个数的变量，初始值为0
    size_t count = 0;
    // 调用CheckCount方法，传入文件描述符，参数列表和选项个数
    MMIEventDump->CheckCount(fd_, args, count);
    // 调用Dump方法，传入文件描述符，参数列表
    MMIEventDump->ParseCommand(fd_, args);
    // 调用Dump方法，传入文件描述符，参数列表
    MMIEventDump->DumpEventHelp(fd_, args);
    // 使用Gtest提供的断言函数，判断选项个数是否为4
    EXPECT_EQ(count, 4);
}
}
}