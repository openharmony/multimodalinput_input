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

#include <fstream>

#include <dlfcn.h>
#include <gtest/gtest.h>

#include "infrared_emitter_controller.h"
#include "mmi_log.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
#ifndef OHOS_BUILD_PC_UNIT_TEST
namespace {
using namespace testing::ext;
const std::string IR_WRAPPER_PATH = "libinfrared_emitter_adapter.z.so";
} // namespace

class InfraredEmitterControllerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: InfraredEmitterControllerTest_GetInstance_001
 * @tc.desc: Test the funcation GetInstance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_GetInstance_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InfraredEmitterController controller;
    InfraredEmitterController* instance1 = controller.GetInstance();
    ASSERT_NE(instance1, nullptr);
    InfraredEmitterController* instance2 = controller.GetInstance();
    ASSERT_EQ(instance1, instance2);
}

/**
 * @tc.name: InfraredEmitterControllerTest_InitInfraredEmitter_001
 * @tc.desc: Test the funcation InitInfraredEmitter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_InitInfraredEmitter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InfraredEmitterController controller;
    controller.irInterface_ = nullptr;
    controller.soIrHandle_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(controller.InitInfraredEmitter());
    controller.soIrHandle_ = dlopen(IR_WRAPPER_PATH.c_str(), RTLD_NOW);
    ASSERT_NO_FATAL_FAILURE(controller.InitInfraredEmitter());
}

/**
 * @tc.name: InfraredEmitterControllerTest_Transmit_001
 * @tc.desc: Test the funcation Transmit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_Transmit_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InfraredEmitterController controller;
    int64_t carrierFreq = 12;
    std::vector<int64_t> pattern = {10, 20, 30};
    ASSERT_NO_FATAL_FAILURE(controller.Transmit(carrierFreq, pattern));
}

/**
 * @tc.name: InfraredEmitterControllerTest_GetFrequencies_001
 * @tc.desc: Test the funcation GetFrequencies
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_GetFrequencies_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InfraredEmitterController controller;
    controller.irInterface_ = nullptr;
    std::vector<InfraredFrequencyInfo> frequencyInfo;
    frequencyInfo.push_back(InfraredFrequencyInfo({1, 1000}));
    ASSERT_NO_FATAL_FAILURE(controller.GetFrequencies(frequencyInfo));
}

/**
 * @tc.name: InfraredEmitterControllerTest_InfraredEmitterController_001
 * @tc.desc: Test the funcation GetFrequencies
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_InfraredEmitterController_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InfraredEmitterController controller;
    const std::string irWrapperPath = "libconsumer_ir_service_1.0.z.so";
    controller.soIrHandle_ = dlopen(irWrapperPath.c_str(), RTLD_NOW);
    ASSERT_EQ(controller.irInterface_, nullptr);
}
#endif // OHOS_BUILD_PC_UNIT_TEST
} // namespace MMI
} // namespace OHOS