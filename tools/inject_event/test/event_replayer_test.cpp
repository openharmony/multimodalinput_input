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
#include <fstream>
#include <string>
#include <map>

#include "event_replayer.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;

const std::string SANDBOX_PATH = "/data/service/el1/public/multimodalinput/";
const std::string TEST_FILE_PATH = SANDBOX_PATH + "mmi_test_events.rec";
const std::string INVALID_FILE_PATH = SANDBOX_PATH + "mmi_invalid_events.rec";
const std::string EMPTY_FILE_PATH = SANDBOX_PATH + "mmi_empty_events.rec";
const std::string PARTIAL_FILE_PATH = SANDBOX_PATH + "mmi_partial_events.rec";

bool CreateTestEventFile(const std::string& path)
{
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    file << "EVENTS_BEGIN" << std::endl;
    file << "[1, 1, 30, 1, 1682345678, 123456] # EV_KEY / KEY_A 1" << std::endl;
    file << "[1, 0, 0, 0, 1682345678, 123456] # EV_SYN / SYN_REPORT 0" << std::endl;
    file << "[1, 1, 30, 0, 1682345678, 223456] # EV_KEY / KEY_A 0" << std::endl;
    file << "[1, 0, 0, 0, 1682345678, 223456] # EV_SYN / SYN_REPORT 0" << std::endl;
    file << "EVENTS_END" << std::endl;
    file << std::endl;
    file << "DEVICES: 1" << std::endl;
    file << "DEVICE: 1|/dev/input/event2|Test Keyboard" << std::endl;
    file.close();
    return true;
}

bool CreateTestDeviceFile(const std::string& path)
{
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    file << "EVENTS_BEGIN" << std::endl;
    file << "[1, 1, 30, 1, 1682345678, 123456] # EV_KEY / KEY_A 1" << std::endl;
    file << "[1, 0, 0, 0, 1682345678, 123456] # EV_SYN / SYN_REPORT 0" << std::endl;
    file << "[1, 1, 30, 0, 1682345678, 223456] # EV_KEY / KEY_A 0" << std::endl;
    file << "[1, 0, 0, 0, 1682345678, 223456] # EV_SYN / SYN_REPORT 0" << std::endl;
    file << "EVENTS_END" << std::endl;
    file << std::endl;
    file << "DEVICES: 1" << std::endl;
    file << "DEVICE: 1|/dev/input/event2|Test Keyboard|123124a" << std::endl;
    file.close();
    return true;
}

bool CreateInvalidEventFile(const std::string& path)
{
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    file << "INVALID CONTENT" << std::endl;
    file.close();
    return true;
}

bool CreateEmptyEventFile(const std::string& path)
{
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    file.close();
    return true;
}

bool CreatePartialEventFile(const std::string& path, bool includeDevices, bool includeEvents)
{
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    file << "HEADER INFORMATION" << std::endl;
    if (includeEvents) {
        file << "EVENTS_BEGIN" << std::endl;
        file << "[4, 2, 0, -2, 1501837700, 841124] # EV_REL / REL_X -2" << std::endl;
        file << "[4, 0, 0, 0, 1501837700, 841124] # EV_SYN / SYN_REPORT 0" << std::endl;
        file << "EVENTS_END" << std::endl;
    }
    if (includeDevices) {
        file << "DEVICES: 2" << std::endl;
        file << "DEVICE: 4|/dev/input/event4|Compx 2.4G Receiver Mouse" << std::endl;
        file << "DEVICE: 10|/dev/input/event10|VSoC touchscreen" << std::endl;
    }
    file.close();
    return true;
}

void CleanupTestFiles()
{
    std::remove(TEST_FILE_PATH.c_str());
    std::remove(INVALID_FILE_PATH.c_str());
    std::remove(EMPTY_FILE_PATH.c_str());
    std::remove(PARTIAL_FILE_PATH.c_str());
}
} // namespace

class EventReplayerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void)
    {
        CleanupTestFiles();
    }
    void SetUp() {}
    void TearDown()
    {
        CleanupTestFiles();
    }
};

/**
 * @tc.name: EventReplayerTest_Constructor
 * @tc.desc: Test constructor of EventReplayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_Constructor, TestSize.Level1)
{
    EventReplayer replayer1(TEST_FILE_PATH);
    SUCCEED();

    std::map<uint16_t, uint16_t> deviceMapping = {{1, 3}, {2, 4}};
    EventReplayer replayer2(TEST_FILE_PATH, deviceMapping);
    SUCCEED();
}

/**
 * @tc.name: EventReplayerTest_ParseInputLine_Valid
 * @tc.desc: Test parsing valid input lines
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_ParseInputLine_Valid, TestSize.Level1)
{
    uint32_t deviceId;
    input_event event;

    EXPECT_TRUE(EventReplayer::ParseInputLine("[1, 1, 30, 1, 1682345678, 123456] # EV_KEY / KEY_A 1",
        deviceId, event));
    EXPECT_EQ(deviceId, 1);
    EXPECT_EQ(event.type, 1);
    EXPECT_EQ(event.code, 30);
    EXPECT_EQ(event.value, 1);
    EXPECT_EQ(event.input_event_sec, 1682345678);
    EXPECT_EQ(event.input_event_usec, 123456);

    EXPECT_TRUE(EventReplayer::ParseInputLine("[  2,  3,  40,  0,  1682345679,  234567  ] # Comment",
        deviceId, event));
    EXPECT_EQ(deviceId, 2);
    EXPECT_EQ(event.type, 3);
    EXPECT_EQ(event.code, 40);
    EXPECT_EQ(event.value, 0);
    EXPECT_EQ(event.input_event_sec, 1682345679);
    EXPECT_EQ(event.input_event_usec, 234567);

    EXPECT_TRUE(EventReplayer::ParseInputLine("[3, 0, 0, 0, 1682345680, 345678]",
        deviceId, event));
    EXPECT_EQ(deviceId, 3);
    EXPECT_EQ(event.type, 0);
    EXPECT_EQ(event.code, 0);
    EXPECT_EQ(event.value, 0);
    EXPECT_EQ(event.input_event_sec, 1682345680);
    EXPECT_EQ(event.input_event_usec, 345678);
}

/**
 * @tc.name: EventReplayerTest_ParseInputLine_Invalid
 * @tc.desc: Test parsing invalid input lines
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_ParseInputLine_Invalid, TestSize.Level1)
{
    uint32_t deviceId;
    input_event event;

    EXPECT_FALSE(EventReplayer::ParseInputLine("", deviceId, event));
    EXPECT_FALSE(EventReplayer::ParseInputLine("1, 1, 30, 1, 1682345678, 123456", deviceId, event));
    EXPECT_FALSE(EventReplayer::ParseInputLine("[1, 1, 30]", deviceId, event));
    EXPECT_FALSE(EventReplayer::ParseInputLine("[a, 1, 30, 1, 1682345678, 123456]", deviceId, event));
    EXPECT_FALSE(EventReplayer::ParseInputLine("[ 1, 1, 30, 1, 1682345678, 123456", deviceId, event));
    EXPECT_FALSE(EventReplayer::ParseInputLine("1, 1, 30, 1, 1682345678, 123456 ]", deviceId, event));
    EXPECT_FALSE(EventReplayer::ParseInputLine("[1 1, 30, 1, 1682345678, 123456]", deviceId, event));
}

/**
 * @tc.name: EventReplayerTest_FileOpenError
 * @tc.desc: Test file opening error cases
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_FileOpenError, TestSize.Level1)
{
    std::string nonExistentPath = SANDBOX_PATH + "non_existent_file.rec";
    EventReplayer replayer(nonExistentPath);
    EXPECT_FALSE(replayer.Replay());
}

/**
 * @tc.name: EventReplayerTest_EmptyFileError
 * @tc.desc: Test with empty file error cases
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_EmptyFileError, TestSize.Level1)
{
    if (!CreateEmptyEventFile(EMPTY_FILE_PATH)) {
        GTEST_SKIP() << "Failed to create test file, skipping test";
    }
    EventReplayer replayer(EMPTY_FILE_PATH);
    EXPECT_FALSE(replayer.Replay());
}

/**
 * @tc.name: EventReplayerTest_InvalidFileFormat
 * @tc.desc: Test with invalid file format
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_InvalidFileFormat, TestSize.Level1)
{
    if (!CreateInvalidEventFile(INVALID_FILE_PATH)) {
        GTEST_SKIP() << "Failed to create test file, skipping test";
    }
    EventReplayer replayer(INVALID_FILE_PATH);
    EXPECT_FALSE(replayer.Replay());
}

/**
 * @tc.name: EventReplayerTest_InvaildFilePath
 * @tc.desc: Test with invalid file path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_InvaildFilePath, TestSize.Level1)
{
    EventReplayer replayer("/invaild/path");
    EXPECT_FALSE(replayer.Replay());
}

/**
 * @tc.name: EventReplayerTest_VaildFilePath
 * @tc.desc: Test with valid file path but no available device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_VaildFilePath, TestSize.Level1)
{
    if (!CreateTestDeviceFile(TEST_FILE_PATH)) {
    GTEST_SKIP() << "Failed to create test file, skipping test";
    }
    EventReplayer replayer(TEST_FILE_PATH);
    EXPECT_FALSE(replayer.Replay());
}

/**
 * @tc.name: EventReplayerTest_DeviceMapping
 * @tc.desc: Test device mapping functionality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_DeviceMapping, TestSize.Level1)
{
    std::map<uint16_t, uint16_t> deviceMapping = {{1, 3}, {2, 4}};
    EventReplayer replayer(TEST_FILE_PATH, deviceMapping);
    SUCCEED();
}

/**
 * @tc.name: EventReplayerTest_InvalidDeviceError
 * @tc.desc: Test error handling when device is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_InvalidDeviceError, TestSize.Level1)
{
    if (!CreateTestEventFile(TEST_FILE_PATH)) {
        GTEST_SKIP() << "Failed to create test file, skipping test";
    }
    std::map<uint16_t, uint16_t> deviceMapping = {{2, 3}, {3, 4}};
    EventReplayer replayer(TEST_FILE_PATH, deviceMapping);
    ASSERT_NO_FATAL_FAILURE({
        replayer.Replay();
    });
}

/**
 * @tc.name: EventReplayerTest_SeekToDevicesSection_Found
 * @tc.desc: Test seeking to DEVICES section when it exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_SeekToDevicesSection_Found, TestSize.Level1)
{
    if (!CreatePartialEventFile(PARTIAL_FILE_PATH, true, false)) {
        GTEST_SKIP() << "Failed to create test file, skipping test";
    }
    EventReplayer replayer(PARTIAL_FILE_PATH);
    std::ifstream inputFile(PARTIAL_FILE_PATH);
    EXPECT_TRUE(inputFile.is_open()) << "Failed to open test file";
    EXPECT_TRUE(replayer.SeekToDevicesSection(inputFile));
    // Verify we're at the right position
    std::string line;
    std::getline(inputFile, line);
    EXPECT_EQ(line, "DEVICES: 2") << "File position should be at DEVICES line";

    inputFile.close();
}

/**
 * @tc.name: EventReplayerTest_SeekToDevicesSection_NotFound
 * @tc.desc: Test seeking to DEVICES section when it doesn't exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_SeekToDevicesSection_NotFound, TestSize.Level1)
{
    if (!CreatePartialEventFile(PARTIAL_FILE_PATH, false, true)) {
        GTEST_SKIP() << "Failed to create test file, skipping test";
    }
    EventReplayer replayer(PARTIAL_FILE_PATH);
    std::ifstream inputFile(PARTIAL_FILE_PATH);
    EXPECT_TRUE(inputFile.is_open()) << "Failed to open test file";
    EXPECT_FALSE(replayer.SeekToDevicesSection(inputFile));
    inputFile.close();
}

/**
 * @tc.name: EventReplayerTest_SeekToEventsSection_Found
 * @tc.desc: Test seeking to EVENTS_BEGIN section when it exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_SeekToEventsSection_Found, TestSize.Level1)
{
    if (!CreatePartialEventFile(PARTIAL_FILE_PATH, false, true)) {
        GTEST_SKIP() << "Failed to create test file, skipping test";
    }
    EventReplayer replayer(PARTIAL_FILE_PATH);
    std::ifstream inputFile(PARTIAL_FILE_PATH);
    EXPECT_TRUE(inputFile.is_open()) << "Failed to open test file";
    EXPECT_TRUE(replayer.SeekToEventsSection(inputFile));
    // Verify we're at the right position (after EVENTS_BEGIN)
    std::string line;
    std::getline(inputFile, line);
    EXPECT_EQ(line, "[4, 2, 0, -2, 1501837700, 841124] # EV_REL / REL_X -2") <<
        "File position should be after EVENTS_BEGIN line";
    inputFile.close();
}

/**
 * @tc.name: EventReplayerTest_SeekToEventsSection_NotFound
 * @tc.desc: Test seeking to EVENTS_BEGIN section when it doesn't exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_SeekToEventsSection_NotFound, TestSize.Level1)
{
    if (!CreatePartialEventFile(PARTIAL_FILE_PATH, true, false)) {
        GTEST_SKIP() << "Failed to create test file, skipping test";
    }
    EventReplayer replayer(PARTIAL_FILE_PATH);
    std::ifstream inputFile(PARTIAL_FILE_PATH);
    EXPECT_TRUE(inputFile.is_open()) << "Failed to open test file";
    EXPECT_FALSE(replayer.SeekToEventsSection(inputFile));
    inputFile.close();
}

/**
 * @tc.name: EventReplayerTest_SeekToDevicesSection_BadStream
 * @tc.desc: Test seeking to DEVICES section with a bad file stream
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_SeekToDevicesSection_BadStream, TestSize.Level1)
{
    EventReplayer replayer(INVALID_FILE_PATH);
    std::ifstream inputFile(INVALID_FILE_PATH);
    inputFile.close(); // Deliberately close to make it bad
    EXPECT_FALSE(replayer.SeekToDevicesSection(inputFile));
}

/**
 * @tc.name: EventReplayerTest_SeekToEventsSection_BadStream
 * @tc.desc: Test seeking to EVENTS_BEGIN section with a bad file stream
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_SeekToEventsSection_BadStream, TestSize.Level1)
{
    EventReplayer replayer(INVALID_FILE_PATH);
    std::ifstream inputFile(INVALID_FILE_PATH);
    inputFile.close(); // Deliberately close to make it bad
    EXPECT_FALSE(replayer.SeekToEventsSection(inputFile));
}

/**
 * @tc.name: EventReplayerTest_SeekToDevicesSection_CompleteFile
 * @tc.desc: Test seeking to DEVICES section in a complete file with both sections
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_SeekToDevicesSection_CompleteFile, TestSize.Level1)
{
    if (!CreateTestEventFile(TEST_FILE_PATH)) {
        GTEST_SKIP() << "Failed to create test file, skipping test";
    }
    EventReplayer replayer(TEST_FILE_PATH);
    std::ifstream inputFile(TEST_FILE_PATH);
    EXPECT_TRUE(inputFile.is_open()) << "Failed to open test file";
    EXPECT_TRUE(replayer.SeekToDevicesSection(inputFile));
    // Verify we're at the right position
    std::string line;
    std::getline(inputFile, line);
    EXPECT_EQ(line, "DEVICES: 1") << "File position should be at DEVICES line";
    inputFile.close();
}

/**
 * @tc.name: EventReplayerTest_SeekToEventsSection_CompleteFile
 * @tc.desc: Test seeking to EVENTS_BEGIN section in a complete file with both sections
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_SeekToEventsSection_CompleteFile, TestSize.Level1)
{
    if (!CreateTestEventFile(TEST_FILE_PATH)) {
        GTEST_SKIP() << "Failed to create test file, skipping test";
    }
    EventReplayer replayer(TEST_FILE_PATH);
    std::ifstream inputFile(TEST_FILE_PATH);
    EXPECT_TRUE(inputFile.is_open()) << "Failed to open test file";
    EXPECT_TRUE(replayer.SeekToEventsSection(inputFile));
    // Verify we're at the right position (after EVENTS_BEGIN)
    std::string line;
    std::getline(inputFile, line);
    EXPECT_EQ(line, "[1, 1, 30, 1, 1682345678, 123456] # EV_KEY / KEY_A 1") <<
        "File position should be after EVENTS_BEGIN line";
    inputFile.close();
}

/**
 * @tc.name: EventReplayerTest_SeekToDevicesSection_EmptyFile
 * @tc.desc: Test seeking to DEVICES section in an empty file
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_SeekToDevicesSection_EmptyFile, TestSize.Level1)
{
    if (!CreateEmptyEventFile(EMPTY_FILE_PATH)) {
        GTEST_SKIP() << "Failed to create test file, skipping test";
    }
    EventReplayer replayer(EMPTY_FILE_PATH);
    std::ifstream inputFile(EMPTY_FILE_PATH);
    EXPECT_TRUE(inputFile.is_open()) << "Failed to open test file";
    EXPECT_FALSE(replayer.SeekToDevicesSection(inputFile));
    inputFile.close();
}

/**
 * @tc.name: EventReplayerTest_SeekToEventsSection_EmptyFile
 * @tc.desc: Test seeking to EVENTS_BEGIN section in an empty file
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventReplayerTest, EventReplayerTest_SeekToEventsSection_EmptyFile, TestSize.Level1)
{
    if (!CreateEmptyEventFile(EMPTY_FILE_PATH)) {
        GTEST_SKIP() << "Failed to create test file, skipping test";
    }
    EventReplayer replayer(EMPTY_FILE_PATH);
    std::ifstream inputFile(EMPTY_FILE_PATH);
    EXPECT_TRUE(inputFile.is_open()) << "Failed to open test file";
    EXPECT_FALSE(replayer.SeekToEventsSection(inputFile));
    inputFile.close();
}
} // namespace MMI
} // namespace OHOS