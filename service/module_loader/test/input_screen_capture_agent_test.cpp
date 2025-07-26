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

#include "proto.h"
#include "input_event_handler.h"
#include "input_screen_capture_agent.h"
#include "mmi_log.h"
#include "mmi_service.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputScreenCaptureAgentTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;

#ifdef __aarch64__
const std::string REFERENCE_LIB_PATH = "/system/lib64/platformsdk";
#else
const std::string REFERENCE_LIB_PATH = "/system/lib/platformsdk";
#endif
const std::string FILESEPARATOR = "/";
const std::string REFERENCE_LIB_NAME = "libmmi-screen_capture.z.so";
std::string REFENCE_LIB_ABSOLUTE_PATH = REFERENCE_LIB_PATH + FILESEPARATOR + REFERENCE_LIB_NAME;
} // namespace

class InputScreenCaptureAgentTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    InputScreenCaptureAgent inputScreenCaptureAgent;
private:
    std::mutex agentMutex_;
};
void InputScreenCaptureAgentTest::SetUpTestCase(void)
{}

void InputScreenCaptureAgentTest::TearDownTestCase(void)
{}

void InputScreenCaptureAgentTest::SetUp()
{
    inputScreenCaptureAgent.handle_.handle = nullptr;
    inputScreenCaptureAgent.handle_.isWorking = nullptr;
    inputScreenCaptureAgent.handle_.registerListener = nullptr;
    inputScreenCaptureAgent.handle_.isMusicActivate = nullptr;
}

void InputScreenCaptureAgentTest::TearDown()
{
    std::lock_guard<std::mutex> guard(agentMutex_);
    if (inputScreenCaptureAgent.handle_.handle != nullptr) {
        inputScreenCaptureAgent.handle_.Free(agentMutex_);
    }
}

/**
 * @tc.name: IsScreenCaptureWorking_001
 * @tc.desc: Test IsScreenCaptureWorking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputScreenCaptureAgentTest, IsScreenCaptureWorking_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t capturePid = 1;
    EXPECT_FALSE(inputScreenCaptureAgent.IsScreenCaptureWorking(capturePid));
}

/**
 * @tc.name: LoadLibrary_001
 * @tc.desc: Test LoadLibrary
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputScreenCaptureAgentTest, LoadLibrary_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(inputScreenCaptureAgent.handle_.handle, nullptr);
    EXPECT_EQ(inputScreenCaptureAgent.handle_.isWorking, nullptr);
    EXPECT_EQ(inputScreenCaptureAgent.handle_.registerListener, nullptr);
    char libRealPath[PATH_MAX] = {};
    realpath(REFENCE_LIB_ABSOLUTE_PATH.c_str(), libRealPath);
    inputScreenCaptureAgent.handle_.handle = dlopen(libRealPath, RTLD_LAZY);
    EXPECT_NE(inputScreenCaptureAgent.handle_.handle, nullptr);
    int32_t ret = inputScreenCaptureAgent.LoadLibrary();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: LoadAudioLibrary_001
 * @tc.desc: Test LoadAudioLibrary
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputScreenCaptureAgentTest, LoadAudioLibrary_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(inputScreenCaptureAgent.handle_.handle, nullptr);
    EXPECT_EQ(inputScreenCaptureAgent.handle_.isWorking, nullptr);
    EXPECT_EQ(inputScreenCaptureAgent.handle_.registerListener, nullptr);
    char libRealPath[PATH_MAX] = {};
    realpath(REFENCE_LIB_ABSOLUTE_PATH.c_str(), libRealPath);
    inputScreenCaptureAgent.handle_.handle = dlopen(libRealPath, RTLD_LAZY);
    EXPECT_NE(inputScreenCaptureAgent.handle_.handle, nullptr);
    int32_t ret = inputScreenCaptureAgent.LoadAudioLibrary();
    EXPECT_EQ(ret, RET_OK);
}

} // namespace MMI
} // namespace OHOS
