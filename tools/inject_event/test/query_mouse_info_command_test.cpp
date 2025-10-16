/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include <fcntl.h>
 
#include "input_manager.h"
#include "input_manager_command.h"
#include "pixel_map.h"
 
#include "mock.h"
 
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class QueryMouseInfoCommandTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};
 
/**
 * @tc.name: Test_QueryMouseInfo_001
 * @tc.desc: test query mouse info
 * @tc.type: FUNC
 */
HWTEST_F(QueryMouseInfoCommandTest, Test_QueryMouseInfo_001, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"uinput"};
    char command2[] = {"-M"};
    char command3[] = {"-q"};
 
    char *argv[] = {command1, command2, command3};
 
    int32_t result = inputManagerCommand->ParseCommand(8, argv);
    EXPECT_EQ(RET_ERR, result);
    MOCKHANDLER->mockIsPointerInitRet = false;
    result = inputManagerCommand->ParseCommand(3, argv);
    EXPECT_EQ(RET_ERR, result);
    MOCKHANDLER->mockIsPointerInitRet = true;
    MOCKHANDLER->mockGetCurrentCursorInfoRet = RET_ERR;
    result = inputManagerCommand->ParseCommand(3, argv);
    EXPECT_EQ(RET_ERR, result);
    MOCKHANDLER->mockGetCurrentCursorInfoRet = RET_OK;
    MOCKHANDLER->mockVisible = false;
    result = inputManagerCommand->ParseCommand(3, argv);
    EXPECT_EQ(RET_ERR, result);
    MOCKHANDLER->mockVisible = true;
    MOCKHANDLER->mockPointerStyleId = 0;
    result = inputManagerCommand->ParseCommand(3, argv);
    EXPECT_EQ(RET_OK, result);
}
 
/**
 * @tc.name: Test_QueryMouseInfo_002
 * @tc.desc: test query mouse info
 * @tc.type: FUNC
 */
HWTEST_F(QueryMouseInfoCommandTest, Test_QueryMouseInfo_002, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"uinput"};
    char command2[] = {"-M"};
    char command3[] = {"-q"};
    char command4[] = {"/data/testFile"};
 
    char *argv[] = {command1, command2, command3, command4};
 
    MOCKHANDLER->mockIsPointerInitRet = true;
    MOCKHANDLER->mockGetCurrentCursorInfoRet = RET_OK;
    MOCKHANDLER->mockVisible = true;
    MOCKHANDLER->mockPointerStyleId = 0;
    int32_t result = inputManagerCommand->ParseCommand(4, argv);
    EXPECT_EQ(RET_ERR, result);
    MOCKHANDLER->mockPointerStyleId = -100;
    result = inputManagerCommand->ParseCommand(4, argv);
    EXPECT_EQ(RET_ERR, result);
    EXPECT_GE(open(command4, O_RDWR | O_CREAT), 0);
    char realPath[PATH_MAX] = {};
    EXPECT_NE(realpath(command4, realPath), nullptr);
    MOCKHANDLER->mockGetUserDefinedCursorPixelMapRet = RET_ERR;
    result = inputManagerCommand->ParseCommand(4, argv);
    EXPECT_EQ(RET_ERR, result);
    MOCKHANDLER->mockGetUserDefinedCursorPixelMapRet = RET_OK;
    MOCKHANDLER->mockPixelMapPtr = nullptr;
    result = inputManagerCommand->ParseCommand(4, argv);
    EXPECT_EQ(RET_ERR, result);
    auto g_pixelMap = std::make_shared<Media::PixelMap>();
    MOCKHANDLER->mockPixelMapPtr = g_pixelMap;
    EXPECT_NE(MOCKHANDLER->mockPixelMapPtr, nullptr);
    result = inputManagerCommand->ParseCommand(4, argv);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: Test_QueryMouseInfo_003
 * @tc.desc: test query mouse info with different parameter combinations
 * @tc.type: FUNC
 */
HWTEST_F(QueryMouseInfoCommandTest, Test_QueryMouseInfo_003, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"uinput"};
    char command2[] = {"-M"};
    char command3[] = {"-q"};
    char command4[] = {"--query"};

    char *argv1[] = {command1, command2, command4};

    MOCKHANDLER->mockIsPointerInitRet = true;
    MOCKHANDLER->mockGetCurrentCursorInfoRet = RET_OK;
    MOCKHANDLER->mockVisible = true;
    MOCKHANDLER->mockPointerStyleId = 1;

    int32_t result = inputManagerCommand->ParseCommand(3, argv1);
    EXPECT_EQ(RET_OK, result);

    char *argv2[] = {command1, command3};
    result = inputManagerCommand->ParseCommand(2, argv2);
    EXPECT_EQ(RET_ERR, result);

    char *argv3[] = {command1, command2};
    result = inputManagerCommand->ParseCommand(2, argv3);
    EXPECT_EQ(RET_ERR, result);
}

/**
 * @tc.name: Test_QueryMouseInfo_004
 * @tc.desc: test query mouse info with various pointer styles
 * @tc.type: FUNC
 */
HWTEST_F(QueryMouseInfoCommandTest, Test_QueryMouseInfo_004, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"uinput"};
    char command2[] = {"-M"};
    char command3[] = {"-q"};

    char *argv[] = {command1, command2, command3};

    MOCKHANDLER->mockIsPointerInitRet = true;
    MOCKHANDLER->mockGetCurrentCursorInfoRet = RET_OK;
    MOCKHANDLER->mockVisible = true;

    MOCKHANDLER->mockPointerStyleId = 5;
    int32_t result = inputManagerCommand->ParseCommand(3, argv);
    EXPECT_EQ(RET_OK, result);

    MOCKHANDLER->mockPointerStyleId = 100;
    result = inputManagerCommand->ParseCommand(3, argv);
    EXPECT_EQ(RET_OK, result);

    MOCKHANDLER->mockPointerStyleId = INT32_MAX;
    result = inputManagerCommand->ParseCommand(3, argv);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: Test_QueryMouseInfo_005
 * @tc.desc: test query mouse info error handling
 * @tc.type: FUNC
 */
HWTEST_F(QueryMouseInfoCommandTest, Test_QueryMouseInfo_005, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"uinput"};
    char command2[] = {"-M"};
    char command3[] = {"-q"};
    
    char *argv[] = {command1, command2, command3};

    MOCKHANDLER->mockIsPointerInitRet = false;
    int32_t result = inputManagerCommand->ParseCommand(3, argv);
    EXPECT_EQ(RET_ERR, result);
    
    MOCKHANDLER->mockIsPointerInitRet = true;
    MOCKHANDLER->mockGetCurrentCursorInfoRet = RET_OK;
    MOCKHANDLER->mockVisible = true;
    MOCKHANDLER->mockPointerStyleId = 0;
    result = inputManagerCommand->ParseCommand(3, argv);
    EXPECT_EQ(RET_OK, result);

    MOCKHANDLER->mockGetCurrentCursorInfoRet = RET_ERR;
    result = inputManagerCommand->ParseCommand(3, argv);
    EXPECT_EQ(RET_ERR, result);

    MOCKHANDLER->mockGetCurrentCursorInfoRet = RET_OK;
    MOCKHANDLER->mockVisible = false;
    result = inputManagerCommand->ParseCommand(3, argv);
    EXPECT_EQ(RET_ERR, result);

    MOCKHANDLER->mockVisible = true;
    result = inputManagerCommand->ParseCommand(3, argv);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: Test_QueryMouseInfo_006
 * @tc.desc: test query mouse info memory boundary conditions
 * @tc.type: FUNC
 */
HWTEST_F(QueryMouseInfoCommandTest, Test_QueryMouseInfo_006, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"uinput"};
    char command2[] = {"-M"};
    char command3[] = {"-q"};

    char* argv[100];
    argv[0] = command1;
    argv[1] = command2;
    argv[2] = command3;

    for (int i = 3; i < 100; i++) {
        argv[i] = new char[10];
        sprintf(argv[i], "-p%d", i);
    }

    MOCKHANDLER->mockIsPointerInitRet = true;
    MOCKHANDLER->mockGetCurrentCursorInfoRet = RET_OK;
    MOCKHANDLER->mockVisible = true;
    MOCKHANDLER->mockPointerStyleId = 0;

    int32_t result = inputManagerCommand->ParseCommand(3, argv);
    EXPECT_EQ(RET_OK, result);

    for (int i = 3; i < 100; i++) {
        delete[] argv[i];
    }
}
} // namespace MMI
} // namespace OHOS