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

#include "input_scene_board_judgement.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SceneBoardJudgementTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class SceneBoardJudgementTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: SceneBoardJudgementTest_IsSceneBoardEnabled_001
 * @tc.desc: Verify IsSceneBoardEnabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SceneBoardJudgementTest, SceneBoardJudgementTest_IsSceneBoardEnabled_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMISceneBoardJudgement judgement;
    bool ret = judgement.IsSceneBoardEnabled();
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SceneBoardJudgementTest_IsResampleEnabled_001
 * @tc.desc: Verify IsResampleEnabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SceneBoardJudgementTest, SceneBoardJudgementTest_IsResampleEnabled_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    MMISceneBoardJudgement judgement;
    bool ret = judgement.IsResampleEnabled();
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SceneBoardJudgementTest_SafeGetLine_001
 * @tc.desc: Verify SafeGetLine
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SceneBoardJudgementTest, SceneBoardJudgementTest_SafeGetLine_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMISceneBoardJudgement judgement;
    std::string input = "test.txt";
    std::ofstream testFile(input);
    testFile << "Hello\r" << std::endl;
    testFile << "\r" << std::endl;
    testFile << "World\r" << std::endl;
    testFile.close();
    std::ifstream configFile(input);
    std::string line;
    configFile >> std::ws;
    judgement.SafeGetLine(configFile, line);
    ASSERT_EQ(line, "Hello");
    configFile >> std::ws;
    judgement.SafeGetLine(configFile, line);
    assert(line == "");
    configFile >> std::ws;
    judgement.SafeGetLine(configFile, line);
    assert(line == "World");
    configFile.close();
    std::remove(input.c_str());
}

/**
 * @tc.name: SceneBoardJudgementTest_InitWithConfigFile_001
 * @tc.desc: Verify InitWithConfigFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SceneBoardJudgementTest, SceneBoardJudgementTest_InitWithConfigFile_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMISceneBoardJudgement judgement;
    bool enabled = false;
    std::string configContent = "ENABLED";
    std::ofstream configFile("test_config.txt");
    configFile << configContent;
    configFile.close();
    judgement.InitWithConfigFile("test_config.txt", enabled);
    ASSERT_TRUE(enabled);
    std::remove("test_config.txt");
}

/**
 * @tc.name: SceneBoardJudgementTest_InitWithConfigFile_002
 * @tc.desc: Verify InitWithConfigFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SceneBoardJudgementTest, SceneBoardJudgementTest_InitWithConfigFile_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMISceneBoardJudgement judgement;
    bool enabled = false;
    std::string configContent = "DISABLED";
    std::ofstream configFile("test_config.txt");
    configFile << configContent;
    configFile.close();
    judgement.InitWithConfigFile("test_config.txt", enabled);
    ASSERT_FALSE(enabled);
    std::remove("test_config.txt");
}
} // namespace MMI
} // namespace OHOS