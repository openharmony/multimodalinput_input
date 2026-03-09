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
const std::string INVALID_LIB_PATH = "/system/lib64/invalid_lib_mmi_test.so";
const std::string EMPTY_LIB_PATH = "";
std::string REFENCE_LIB_ABSOLUTE_PATH = REFERENCE_LIB_PATH + FILESEPARATOR + REFERENCE_LIB_NAME;
} // namespace

class InputScreenCaptureAgentTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    InputScreenCaptureAgent inputScreenCaptureAgent;
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
    if (inputScreenCaptureAgent.handle_.handle != nullptr) {
        inputScreenCaptureAgent.handle_.Free();
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

/**
 * @tc.name: IsScreenCaptureWorking_003
 * @tc.desc: Test IsScreenCaptureWorking when isWorking function pointer is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputScreenCaptureAgentTest, IsScreenCaptureWorking_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char libRealPath[PATH_MAX] = {};
    if (realpath(REFENCE_LIB_ABSOLUTE_PATH.c_str(), libRealPath) != nullptr) {
        inputScreenCaptureAgent.handle_.handle = dlopen(libRealPath, RTLD_LAZY);
    }
    inputScreenCaptureAgent.handle_.isWorking = nullptr;
    
    int32_t capturePid = 200;
    EXPECT_FALSE(inputScreenCaptureAgent.IsScreenCaptureWorking(capturePid));
}

/**
 * @tc.name: LoadLibrary_003
 * @tc.desc: Test LoadLibrary failed (dlsym isWorking null)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputScreenCaptureAgentTest, LoadLibrary_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char libRealPath[PATH_MAX] = {};
    if (realpath(REFENCE_LIB_ABSOLUTE_PATH.c_str(), libRealPath) != nullptr) {
        inputScreenCaptureAgent.handle_.handle = dlopen(libRealPath, RTLD_LAZY);
    }
    if (inputScreenCaptureAgent.handle_.handle != nullptr) {
        inputScreenCaptureAgent.handle_.Free();
    }
    
    int32_t ret = inputScreenCaptureAgent.LoadLibrary();
    if (inputScreenCaptureAgent.handle_.isWorking == nullptr) {
        EXPECT_EQ(ret, RET_ERR);
    } else {
        EXPECT_EQ(ret, RET_OK);
    }
}

/**
 * @tc.name: LoadLibrary_004
 * @tc.desc: Test LoadLibrary failed (dlsym registerListener null)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputScreenCaptureAgentTest, LoadLibrary_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char libRealPath[PATH_MAX] = {};
    if (realpath(REFENCE_LIB_ABSOLUTE_PATH.c_str(), libRealPath) != nullptr) {
        inputScreenCaptureAgent.LoadLibrary();
        inputScreenCaptureAgent.handle_.registerListener = nullptr;
    }
    
    int32_t ret = inputScreenCaptureAgent.LoadLibrary();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: LoadAudioLibrary_003
 * @tc.desc: Test LoadAudioLibrary failed (dlsym isMusicActivate null)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputScreenCaptureAgentTest, LoadAudioLibrary_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char libRealPath[PATH_MAX] = {};
    if (realpath(REFENCE_LIB_ABSOLUTE_PATH.c_str(), libRealPath) != nullptr) {
        inputScreenCaptureAgent.handle_.handle = dlopen(libRealPath, RTLD_LAZY);
    }
    if (inputScreenCaptureAgent.handle_.handle != nullptr) {
        inputScreenCaptureAgent.handle_.Free();
    }
    
    int32_t ret = inputScreenCaptureAgent.LoadAudioLibrary();
    if (inputScreenCaptureAgent.handle_.isMusicActivate == nullptr) {
        EXPECT_EQ(ret, RET_ERR);
    } else {
        EXPECT_EQ(ret, RET_OK);
    }
}

/**
 * @tc.name: IsMusicActivate_001
 * @tc.desc: Test IsMusicActivate normal case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputScreenCaptureAgentTest, IsMusicActivate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(inputScreenCaptureAgent.IsMusicActivate());
}

/**
 * @tc.name: IsMusicActivate_002
 * @tc.desc: Test IsMusicActivate when LoadAudioLibrary failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputScreenCaptureAgentTest, IsMusicActivate_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string oldLibPath = REFENCE_LIB_ABSOLUTE_PATH;
    REFENCE_LIB_ABSOLUTE_PATH = INVALID_LIB_PATH;
    
    EXPECT_FALSE(inputScreenCaptureAgent.IsMusicActivate());
    
    REFENCE_LIB_ABSOLUTE_PATH = oldLibPath;
}

/**
 * @tc.name: IsMusicActivate_003
 * @tc.desc: Test IsMusicActivate when isMusicActivate function pointer is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputScreenCaptureAgentTest, IsMusicActivate_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char libRealPath[PATH_MAX] = {};
    if (realpath(REFENCE_LIB_ABSOLUTE_PATH.c_str(), libRealPath) != nullptr) {
        inputScreenCaptureAgent.handle_.handle = dlopen(libRealPath, RTLD_LAZY);
    }
    inputScreenCaptureAgent.handle_.isMusicActivate = nullptr;
    
    EXPECT_FALSE(inputScreenCaptureAgent.IsMusicActivate());
}

/**
 * @tc.name: Destructor_001
 * @tc.desc: Test destructor with valid handle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputScreenCaptureAgentTest, Destructor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    {
        InputScreenCaptureAgent localAgent;
        char libRealPath[PATH_MAX] = {};
        realpath(REFENCE_LIB_ABSOLUTE_PATH.c_str(), libRealPath);
        localAgent.handle_.handle = dlopen(libRealPath, RTLD_LAZY);
        EXPECT_NE(localAgent.handle_.handle, nullptr);
    }
}

/**
 * @tc.name: FreeHandle_001
 * @tc.desc: Test Free method with valid handle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputScreenCaptureAgentTest, FreeHandle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char libRealPath[PATH_MAX] = {};
    realpath(REFENCE_LIB_ABSOLUTE_PATH.c_str(), libRealPath);
    inputScreenCaptureAgent.handle_.handle = dlopen(libRealPath, RTLD_LAZY);
    EXPECT_NE(inputScreenCaptureAgent.handle_.handle, nullptr);
    
    inputScreenCaptureAgent.handle_.Free();
    EXPECT_EQ(inputScreenCaptureAgent.handle_.handle, nullptr);
    EXPECT_EQ(inputScreenCaptureAgent.handle_.isWorking, nullptr);
    EXPECT_EQ(inputScreenCaptureAgent.handle_.registerListener, nullptr);
    EXPECT_EQ(inputScreenCaptureAgent.handle_.isMusicActivate, nullptr);
}

/**
 * @tc.name: FreeHandle_002
 * @tc.desc: Test Free method with null handle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputScreenCaptureAgentTest, FreeHandle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    inputScreenCaptureAgent.handle_.handle = nullptr;

    inputScreenCaptureAgent.handle_.isWorking = reinterpret_cast<int32_t(*)(int32_t)>(0x1234);
    inputScreenCaptureAgent.handle_.registerListener = reinterpret_cast<void(*)(ScreenCaptureCallback)>(0x5678);
    inputScreenCaptureAgent.handle_.isMusicActivate = reinterpret_cast<bool(*)()>(0x9abc);
    
    inputScreenCaptureAgent.handle_.Free();
    EXPECT_EQ(inputScreenCaptureAgent.handle_.handle, nullptr);
    EXPECT_EQ(inputScreenCaptureAgent.handle_.isWorking, nullptr);
    EXPECT_EQ(inputScreenCaptureAgent.handle_.registerListener, nullptr);
    EXPECT_EQ(inputScreenCaptureAgent.handle_.isMusicActivate, nullptr);
}

/**
 * @tc.name: IsScreenCaptureWorking_002
 * @tc.desc: Test IsScreenCaptureWorking when handle is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputScreenCaptureAgentTest, IsScreenCaptureWorking_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    inputScreenCaptureAgent.handle_.handle = nullptr;
    
    int32_t capturePid = 1;
    EXPECT_FALSE(inputScreenCaptureAgent.IsScreenCaptureWorking(capturePid));
}

} // namespace MMI
} // namespace OHOS
