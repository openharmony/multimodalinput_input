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

#include "error_multimodal.h"
#include "mmi_log.h"
#include "mmi_service.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MmiServiceControllerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}

class MmiServiceControllerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: MmiServiceControllerTest_CreateMouseController_001
 * @tc.desc: Test CreateMouseController when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MmiServiceControllerTest, MmiServiceControllerTest_CreateMouseController_001, TestSize.Level1)
{
    MMIService mmiService;
    ErrCode ret = mmiService.CreateMouseController();
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MmiServiceControllerTest_CreateKeyboardController_001
 * @tc.desc: Test CreateKeyboardController when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MmiServiceControllerTest, MmiServiceControllerTest_CreateKeyboardController_001, TestSize.Level1)
{
    MMIService mmiService;
    ErrCode ret = mmiService.CreateKeyboardController();
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

#ifdef OHOS_BUILD_ENABLE_CONTROLLER_INJECT
/**
 * @tc.name: MmiServiceControllerTest_CreateTouchController_001
 * @tc.desc: Test CreateTouchController when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MmiServiceControllerTest, MmiServiceControllerTest_CreateTouchController_001, TestSize.Level1)
{
    MMIService mmiService;
    ErrCode ret = mmiService.CreateTouchController();
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}
#endif // OHOS_BUILD_ENABLE_CONTROLLER_INJECT

/**
 * @tc.name: MmiServiceControllerTest_CheckControllerPermission_001
 * @tc.desc: Test CheckControllerPermission on non-PC device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MmiServiceControllerTest, MmiServiceControllerTest_CheckControllerPermission_001, TestSize.Level1)
{
    MMIService mmiService;
    ErrCode ret = mmiService.CheckControllerPermission();
    EXPECT_EQ(ret, CAPABILITY_NOT_SUPPORTED);
}

/**
 * @tc.name: MmiServiceControllerTest_CreateMouseController_002
 * @tc.desc: Test CreateMouseController when service is running but not on PC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MmiServiceControllerTest, MmiServiceControllerTest_CreateMouseController_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.CreateMouseController();
    EXPECT_EQ(ret, CAPABILITY_NOT_SUPPORTED);
}

/**
 * @tc.name: MmiServiceControllerTest_CreateKeyboardController_002
 * @tc.desc: Test CreateKeyboardController when service is running but not on PC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MmiServiceControllerTest, MmiServiceControllerTest_CreateKeyboardController_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.CreateKeyboardController();
    EXPECT_EQ(ret, CAPABILITY_NOT_SUPPORTED);
}

#ifdef OHOS_BUILD_ENABLE_CONTROLLER_INJECT
/**
 * @tc.name: MmiServiceControllerTest_CreateTouchController_002
 * @tc.desc: Test CreateTouchController when service is running but not on PC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MmiServiceControllerTest, MmiServiceControllerTest_CreateTouchController_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.CreateTouchController();
    EXPECT_EQ(ret, CAPABILITY_NOT_SUPPORTED);
}
#endif // OHOS_BUILD_ENABLE_CONTROLLER_INJECT

/**
 * @tc.name: MmiServiceControllerTest_IsRunning_001
 * @tc.desc: Test IsRunning returns false when service is not started
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MmiServiceControllerTest, MmiServiceControllerTest_IsRunning_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    EXPECT_FALSE(mmiService.IsRunning());
}

/**
 * @tc.name: MmiServiceControllerTest_IsRunning_002
 * @tc.desc: Test IsRunning returns true when service state is running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MmiServiceControllerTest, MmiServiceControllerTest_IsRunning_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    EXPECT_TRUE(mmiService.IsRunning());
}
} // namespace MMI
} // namespace OHOS
