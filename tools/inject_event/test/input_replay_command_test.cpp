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

#include "mmi_log.h"
#include "input_replay_command.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputReplayCommandTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: InputReplayCommandTest_Constructor
 * @tc.desc: Test constructor of InputReplayCommand
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputReplayCommandTest, InputReplayCommandTest_Constructor, TestSize.Level1)
{
    char programName[] = {"program_name"};
    char* argv[] = {programName, nullptr};
    InputReplayCommand command(1, argv);
    SUCCEED();
}

/**
 * @tc.name: InputReplayCommandTest_ParseDeviceMapping_Valid
 * @tc.desc: Test parsing valid device mapping
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputReplayCommandTest, InputReplayCommandTest_ParseDeviceMapping_Valid, TestSize.Level1)
{
    char programName[] = {"program_name"};
    char mapArg[] = {"--map"};
    char mapValue[] = {"0:1,2:3,4:5"};
    char recordArg[] = {"record"};
    char outputPath[] = {"output.bin"};
    char devicePath[] = {"/dev/input/event0"};

    char* mappingArgv[] = {
        programName,
        mapArg, mapValue,
        recordArg, outputPath,
        devicePath
    };
    InputReplayCommand mappingCommand(6, mappingArgv);
    EXPECT_TRUE(mappingCommand.Parse());
}

/**
 * @tc.name: InputReplayCommandTest_ParseDeviceMapping_Invalid
 * @tc.desc: Test parsing invalid device mapping
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputReplayCommandTest, InputReplayCommandTest_ParseDeviceMapping_Invalid, TestSize.Level1)
{
    char programName[] = {"program_name"};
    char mapArg[] = {"--map"};
    char invalidMapValue[] = {"0:1,invalid,4:5"};
    char invalidFormatValue[] = {"0:1:2"};
    char emptyMapValue[] = {""};
    char recordArg[] = {"record"};
    char outputPath[] = {"output.bin"};
    char devicePath[] = {"/dev/input/event0"};

    // Invalid mapping value
    char* invalidMappingArgv[] = {
        programName,
        mapArg, invalidMapValue,
        recordArg, outputPath,
        devicePath
    };
    InputReplayCommand invalidCommand(6, invalidMappingArgv);
    EXPECT_FALSE(invalidCommand.Parse());

    // Invalid format
    char* invalidFormatArgv[] = {
        programName,
        mapArg, invalidFormatValue,
        recordArg, outputPath,
        devicePath
    };
    InputReplayCommand invalidFormatCommand(6, invalidFormatArgv);
    EXPECT_FALSE(invalidFormatCommand.Parse());

    // Empty mapping
    char* emptyMappingArgv[] = {
        programName,
        mapArg, emptyMapValue,
        recordArg, outputPath,
        devicePath
    };
    InputReplayCommand emptyMappingCommand(6, emptyMappingArgv);
    EXPECT_FALSE(emptyMappingCommand.Parse());
}

/**
 * @tc.name: InputReplayCommandTest_ParseRecord_WithDevices
 * @tc.desc: Test parsing record command with specific devices
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputReplayCommandTest, InputReplayCommandTest_ParseRecord_WithDevices, TestSize.Level1)
{
    char programName[] = {"program_name"};
    char recordArg[] = {"record"};
    char outputPath[] = {"output.bin"};
    char device1[] = {"/dev/input/event0"};
    char device2[] = {"/dev/input/event1"};

    char* argv[] = {
        programName,
        recordArg, outputPath,
        device1, device2
    };
    InputReplayCommand command(5, argv);
    EXPECT_TRUE(command.Parse());
}

/**
 * @tc.name: InputReplayCommandTest_ParseRecord_AllDevices
 * @tc.desc: Test parsing record command with all devices flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputReplayCommandTest, InputReplayCommandTest_ParseRecord_AllDevices, TestSize.Level1)
{
    char programName[] = {"program_name"};
    char allArg[] = {"--all"};
    char recordArg[] = {"record"};
    char outputPath[] = {"output.bin"};

    char* argv[] = {
        programName,
        allArg,
        recordArg, outputPath
    };
    InputReplayCommand command(4, argv);
    EXPECT_TRUE(command.Parse());
}

/**
 * @tc.name: InputReplayCommandTest_ParseRecord_NoDevices
 * @tc.desc: Test parsing record command with no devices specified
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputReplayCommandTest, InputReplayCommandTest_ParseRecord_NoDevices, TestSize.Level1)
{
    char programName[] = {"program_name"};
    char recordArg[] = {"record"};
    char outputPath[] = {"output.bin"};

    char* argv[] = {
        programName,
        recordArg, outputPath
    };
    InputReplayCommand command(3, argv);
    EXPECT_FALSE(command.Parse());
}

/**
 * @tc.name: InputReplayCommandTest_ParseReplay_Valid
 * @tc.desc: Test parsing replay command with valid arguments
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputReplayCommandTest, InputReplayCommandTest_ParseReplay_Valid, TestSize.Level1)
{
    char programName[] = {"program_name"};
    char replayArg[] = {"replay"};
    char inputPath[] = {"input.bin"};

    char* argv[] = {
        programName,
        replayArg, inputPath
    };
    InputReplayCommand command(3, argv);
    EXPECT_TRUE(command.Parse());
}

/**
 * @tc.name: InputReplayCommandTest_ParseReplay_Invalid
 * @tc.desc: Test parsing replay command with extra arguments
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputReplayCommandTest, InputReplayCommandTest_ParseReplay_Invalid, TestSize.Level1)
{
    char programName[] = {"program_name"};
    char replayArg[] = {"replay"};
    char inputPath[] = {"input.bin"};
    char extraArg[] = {"extra"};

    char* argv[] = {
        programName,
        replayArg, inputPath, extraArg
    };
    InputReplayCommand command(4, argv);
    EXPECT_FALSE(command.Parse());
}

/**
 * @tc.name: InputReplayCommandTest_Parse_MissingCommand
 * @tc.desc: Test parsing with missing command
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputReplayCommandTest, InputReplayCommandTest_Parse_MissingCommand, TestSize.Level1)
{
    char programName[] = {"program_name"};
    char* argv[] = {programName, nullptr};
    InputReplayCommand command(1, argv);
    EXPECT_FALSE(command.Parse());
}

/**
 * @tc.name: InputReplayCommandTest_Parse_MissingFilePath
 * @tc.desc: Test parsing with missing file path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputReplayCommandTest, InputReplayCommandTest_Parse_MissingFilePath, TestSize.Level1)
{
    char programName[] = {"program_name"};
    char recordArg[] = {"record"};
    char* argv[] = {programName, recordArg, nullptr};
    InputReplayCommand command(2, argv);
    EXPECT_FALSE(command.Parse());
}

/**
 * @tc.name: InputReplayCommandTest_Parse_InvalidCommand
 * @tc.desc: Test parsing with invalid command
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputReplayCommandTest, InputReplayCommandTest_Parse_InvalidCommand, TestSize.Level1)
{
    char programName[] = {"program_name"};
    char invalidArg[] = {"invalid"};
    char filePath[] = {"file.bin"};

    char* argv[] = {
        programName,
        invalidArg, filePath
    };
    InputReplayCommand command(3, argv);
    EXPECT_FALSE(command.Parse());
}

/**
 * @tc.name: InputReplayCommandTest_HandleCommand
 * @tc.desc: Test the static HandleRecordReplayCommand function with error cases
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputReplayCommandTest, InputReplayCommandTest_HandleCommand, TestSize.Level1)
{
    // Invalid command
    char programName1[] = {"program_name"};
    char invalidArg[] = {"invalid"};
    char* invalidArgv[] = {
        programName1,
        invalidArg
    };
    EXPECT_EQ(RET_ERR, InputReplayCommand::HandleRecordReplayCommand(2, invalidArgv));

    // Incomplete arguments
    char programName2[] = {"program_name"};
    char* incompleteArgv[] = {
        programName2
    };
    EXPECT_EQ(RET_ERR, InputReplayCommand::HandleRecordReplayCommand(1, incompleteArgv));
}
} // namespace MMI
} // namespace OHOS