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

#include "event_recorder.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;

const std::string SANDBOX_PATH = "/data/service/el1/public/multimodalinput/";
const std::string TEST_FILE_PATH = SANDBOX_PATH + "test_events.bin";

void CleanupTestFiles()
{
    std::remove(TEST_FILE_PATH.c_str());
}
} // namespace

class EventRecorderTest : public testing::Test {
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
 * @tc.name: EventRecorderTest_Constructor
 * @tc.desc: Test constructor of EventRecorder
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventRecorderTest, EventRecorderTest_Constructor, TestSize.Level1)
{
    EventRecorder recorder(TEST_FILE_PATH);
    SUCCEED();
}

/**
 * @tc.name: EventRecorderTest_GetEventTypeString
 * @tc.desc: Test getting event type string representation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventRecorderTest, EventRecorderTest_GetEventTypeString, TestSize.Level1)
{
    EXPECT_EQ(EventRecorder::GetEventTypeString(EV_SYN), "EV_SYN");
    EXPECT_EQ(EventRecorder::GetEventTypeString(EV_KEY), "EV_KEY");
    EXPECT_EQ(EventRecorder::GetEventTypeString(EV_REL), "EV_REL");
    EXPECT_EQ(EventRecorder::GetEventTypeString(EV_ABS), "EV_ABS");
    EXPECT_EQ(EventRecorder::GetEventTypeString(0xFF), "UNKNOWN_TYPE(255)");
}

/**
 * @tc.name: EventRecorderTest_GetEventCodeString_EVKey
 * @tc.desc: Test getting event code string representation for EV_KEY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventRecorderTest, EventRecorderTest_GetEventCodeString_EVKey, TestSize.Level1)
{
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_KEY, KEY_ENTER), "KEY_ENTER");
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_KEY, KEY_ESC), "KEY_ESC");
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_KEY, KEY_SPACE), "KEY_SPACE");
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_KEY, KEY_A), "KEY_A");
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_KEY, KEY_Z), "KEY_Z");
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_KEY, 0xFFFF), "CODE(65535)");
}

/**
 * @tc.name: EventRecorderTest_GetEventCodeString_EVSyn
 * @tc.desc: Test getting event code string representation for EV_SYN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventRecorderTest, EventRecorderTest_GetEventCodeString_EVSyn, TestSize.Level1)
{
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_SYN, SYN_REPORT), "SYN_REPORT");
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_SYN, SYN_CONFIG), "SYN_CONFIG");
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_SYN, 0xFF), "CODE(255)");
}

/**
 * @tc.name: EventRecorderTest_GetEventCodeString_EVRel
 * @tc.desc: Test getting event code string representation for EV_REL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventRecorderTest, EventRecorderTest_GetEventCodeString_EVRel, TestSize.Level1)
{
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_REL, REL_X), "REL_X");
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_REL, REL_Y), "REL_Y");
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_REL, REL_WHEEL), "REL_WHEEL");
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_REL, 0xFF), "CODE(255)");
}

/**
 * @tc.name: EventRecorderTest_GetEventCodeString_EVAbs
 * @tc.desc: Test getting event code string representation for EV_ABS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventRecorderTest, EventRecorderTest_GetEventCodeString_EVAbs, TestSize.Level1)
{
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_ABS, ABS_X), "ABS_X");
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_ABS, ABS_Y), "ABS_Y");
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_ABS, ABS_MT_POSITION_X), "ABS_MT_POSITION_X");
    EXPECT_EQ(EventRecorder::GetEventCodeString(EV_ABS, 0xFF), "CODE(255)");
}

/**
 * @tc.name: EventRecorderTest_GetSecondaryEventCodeString
 * @tc.desc: Test getting secondary event code string representation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventRecorderTest, EventRecorderTest_GetSecondaryEventCodeString, TestSize.Level1)
{
    EXPECT_EQ(EventRecorder::GetSecondaryEventCodeString(EV_LED, LED_NUML), "LED_NUML");
    EXPECT_EQ(EventRecorder::GetSecondaryEventCodeString(EV_LED, LED_CAPSL), "LED_CAPSL");
    EXPECT_EQ(EventRecorder::GetSecondaryEventCodeString(EV_REP, REP_DELAY), "REP_DELAY");
    EXPECT_EQ(EventRecorder::GetSecondaryEventCodeString(EV_REP, REP_PERIOD), "REP_PERIOD");
    EXPECT_EQ(EventRecorder::GetSecondaryEventCodeString(EV_MSC, MSC_SERIAL), "MSC_SERIAL");
    EXPECT_EQ(EventRecorder::GetSecondaryEventCodeString(EV_LED, 0xFF), "");
    EXPECT_EQ(EventRecorder::GetSecondaryEventCodeString(0xFF, 0), "");
}

/**
 * @tc.name: EventRecorderTest_Start_EmptyDevices
 * @tc.desc: Test start with empty device list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventRecorderTest, EventRecorderTest_Start_EmptyDevices, TestSize.Level1)
{
    EventRecorder recorder(TEST_FILE_PATH);
    std::vector<InputDevice> devices;
    EXPECT_FALSE(recorder.Start(devices));
}

/**
 * @tc.name: EventRecorderTest_Start_emptyPath
 * @tc.desc: Test start with realpath outputpath failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventRecorderTest, EventRecorderTest_Start_emptyPath, TestSize.Level1)
{
    EventRecorder recorder(TEST_FILE_PATH);
    recorder.outputPath_ = "";
    std::vector<InputDevice> devices;
    EXPECT_FALSE(recorder.Start(devices));
}
 
/**
 * @tc.name: EventRecorderTest_Start_InvalidPath
 * @tc.desc: Test start with invalid output path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventRecorderTest, EventRecorderTest_Start_InvalidPath, TestSize.Level1)
{
    EventRecorder recorder(TEST_FILE_PATH);
    recorder.outputPath_ = "/invalid/path";
 
    std::vector<InputDevice> devices;
    bool result = recorder.Start(devices);
 
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventRecorderTest_Stop_NotRunning
 * @tc.desc: Test stop when not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventRecorderTest, EventRecorderTest_Stop_NotRunning, TestSize.Level1)
{
    EventRecorder recorder(TEST_FILE_PATH);
    ASSERT_NO_FATAL_FAILURE({
        recorder.Stop();
    });
}
} // namespace MMI
} // namespace OHOS