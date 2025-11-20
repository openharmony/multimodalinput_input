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
 * @tc.desc: Test the function GetInstance
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
 * @tc.desc: Test the function InitInfraredEmitter
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
 * @tc.desc: Test the function Transmit
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
 * @tc.desc: Test the function GetFrequencies
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
 * @tc.desc: Test the function GetFrequencies
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

/**
 * @tc.name: InfraredEmitterControllerTest_InitInfraredEmitter_002
 * @tc.desc: soIrHandle_ already loaded, should not dlopen again
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_InitInfraredEmitter_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InfraredEmitterController controller;
    controller.soIrHandle_ = dlopen(IR_WRAPPER_PATH.c_str(), RTLD_NOW);
    controller.irInterface_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(controller.InitInfraredEmitter());
    if (controller.soIrHandle_ != nullptr) {
        dlclose(controller.soIrHandle_);
    }
}

/**
 * @tc.name: InfraredEmitterControllerTest_InitInfraredEmitter_003
 * @tc.desc: dlopen fails, should return early
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_InitInfraredEmitter_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InfraredEmitterController controller;
    controller.irInterface_ = nullptr;
    controller.soIrHandle_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(controller.InitInfraredEmitter());
}

/**
 * @tc.name: InfraredEmitterControllerTest_InitInfraredEmitter_004
 * @tc.desc: dlsym returns nullptr, should cleanup so handle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_InitInfraredEmitter_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InfraredEmitterController controller;
    controller.irInterface_ = nullptr;
    controller.soIrHandle_ = dlopen(IR_WRAPPER_PATH.c_str(), RTLD_NOW);
    if (controller.soIrHandle_ != nullptr) {
        dlsym(controller.soIrHandle_, "NonExistFunction");
    }
    ASSERT_NO_FATAL_FAILURE(controller.InitInfraredEmitter());
    if (controller.soIrHandle_ != nullptr) {
        dlclose(controller.soIrHandle_);
    }
}

/**
 * @tc.name: InfraredEmitterControllerTest_InitInfraredEmitter_005
 * @tc.desc: fnCreate is nullptr even if dlsym success, should cleanup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_InitInfraredEmitter_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InfraredEmitterController controller;
    controller.irInterface_ = nullptr;
    controller.soIrHandle_ = dlopen(IR_WRAPPER_PATH.c_str(), RTLD_NOW);
    ASSERT_NO_FATAL_FAILURE(controller.InitInfraredEmitter());
    if (controller.soIrHandle_ != nullptr) {
        dlclose(controller.soIrHandle_);
    }
}

/**
 * @tc.name: InfraredEmitterControllerTest_Transmit_002
 * @tc.desc: irInterface_ is nullptr，Transmit return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_Transmit_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InfraredEmitterController controller;
    controller.irInterface_ = nullptr;
    int64_t carrierFreq = 38000;
    std::vector<int64_t> pattern = {100, 200, 300};
    bool ret = controller.Transmit(carrierFreq, pattern);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InfraredEmitterControllerTest_Transmit_003
 * @tc.desc: irInterface_->Transmit return -1，expected return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_Transmit_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct FakeAdapter : public IInfraredEmitterAdapter {
        int32_t Transmit(int32_t, const std::vector<int32_t>&, bool& outRet) override
        {
            outRet = true;
            return -1;
        }
        int32_t GetCarrierFreqs(bool&, std::vector<OHOS::HDI::Consumerir::V1_0::ConsumerIrFreqRange>&) override
        {
            return 0;
        }
        int32_t HasIrEmitter(bool &hasIrEmitter) override
        {
            return 0;
        }
    };

    InfraredEmitterController controller;
    controller.irInterface_ = new FakeAdapter();
    int64_t carrierFreq = 36000;
    std::vector<int64_t> pattern = {500, 600};
    bool ret = controller.Transmit(carrierFreq, pattern);
    ASSERT_FALSE(ret);
    delete controller.irInterface_;
}

/**
 * @tc.name: InfraredEmitterControllerTest_Transmit_004
 * @tc.desc: irInterface_->Transmit success but outRet return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_Transmit_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct FakeAdapter : public IInfraredEmitterAdapter {
        int32_t Transmit(int32_t, const std::vector<int32_t>&, bool& outRet) override
        {
            outRet = false;
            return 0;
        }
        int32_t GetCarrierFreqs(bool&, std::vector<OHOS::HDI::Consumerir::V1_0::ConsumerIrFreqRange>&) override
        {
            return 0;
        }
        int32_t HasIrEmitter(bool &hasIrEmitter) override
        {
            return 0;
        }
    };

    InfraredEmitterController controller;
    controller.irInterface_ = new FakeAdapter();
    int64_t carrierFreq = 40000;
    std::vector<int64_t> pattern = {150, 250};
    bool ret = controller.Transmit(carrierFreq, pattern);
    ASSERT_FALSE(ret);
    delete controller.irInterface_;
}

/**
 * @tc.name: InfraredEmitterControllerTest_Transmit_005
 * @tc.desc: irInterface_->Transmit success and return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_Transmit_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct FakeAdapter : public IInfraredEmitterAdapter {
        int32_t Transmit(int32_t, const std::vector<int32_t>&, bool& outRet) override
        {
            outRet = true;
            return 0;
        }
        int32_t GetCarrierFreqs(bool&, std::vector<OHOS::HDI::Consumerir::V1_0::ConsumerIrFreqRange>&) override
        {
            return 0;
        }
        int32_t HasIrEmitter(bool &hasIrEmitter) override
        {
            return 0;
        }
    };

    InfraredEmitterController controller;
    controller.irInterface_ = new FakeAdapter();
    int64_t carrierFreq = 39000;
    std::vector<int64_t> pattern = {100, 100, 100, 100};
    bool ret = controller.Transmit(carrierFreq, pattern);
    ASSERT_TRUE(ret);
    delete controller.irInterface_;
}

/**
 * @tc.name: InfraredEmitterControllerTest_GetFrequencies_002
 * @tc.desc: Test GetFrequencies when interface returns ret < 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_GetFrequencies_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct FakeAdapter : public IInfraredEmitterAdapter {
        int32_t Transmit(int32_t, const std::vector<int32_t>&, bool&) override { return 0; }
        int32_t GetCarrierFreqs(bool& ret, std::vector<HDI::Consumerir::V1_0::ConsumerIrFreqRange>&) override
        {
            ret = true;
            return -1;
        }
        int32_t HasIrEmitter(bool &hasIrEmitter) override
        {
            return 0;
        }
    };
    InfraredEmitterController controller;
    controller.irInterface_ = new (std::nothrow) FakeAdapter();
    std::vector<InfraredFrequencyInfo> frequencyInfo;
    int32_t result = controller.GetFrequencies(frequencyInfo);
    ASSERT_TRUE(result != RET_OK);
}

/**
 * @tc.name: InfraredEmitterControllerTest_GetFrequencies_003
 * @tc.desc: Test GetFrequencies when interface returns outRet = false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_GetFrequencies_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct FakeAdapter : public IInfraredEmitterAdapter {
        int32_t Transmit(int32_t, const std::vector<int32_t>&, bool&) override { return 0; }
        int32_t GetCarrierFreqs(bool& ret, std::vector<HDI::Consumerir::V1_0::ConsumerIrFreqRange>&) override
        {
            ret = false;
            return 0;
        }
        int32_t HasIrEmitter(bool &hasIrEmitter) override
        {
            return 0;
        }
    };
    InfraredEmitterController controller;
    controller.irInterface_ = new (std::nothrow) FakeAdapter();
    std::vector<InfraredFrequencyInfo> frequencyInfo;
    int32_t result = controller.GetFrequencies(frequencyInfo);
    ASSERT_TRUE(result != RET_OK);
}

/**
 * @tc.name: InfraredEmitterControllerTest_GetFrequencies_004
 * @tc.desc: Test GetFrequencies with valid data returned
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_GetFrequencies_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct FakeAdapter : public IInfraredEmitterAdapter {
        int32_t Transmit(int32_t, const std::vector<int32_t>&, bool&) override { return 0; }
        int32_t GetCarrierFreqs(bool& ret, std::vector<HDI::Consumerir::V1_0::ConsumerIrFreqRange>& range) override
        {
            ret = true;
            range = {
                { .min = 36000, .max = 40000 },
                { .min = 38000, .max = 42000 }
            };
            return 0;
        }
        int32_t HasIrEmitter(bool &hasIrEmitter) override
        {
            return 0;
        }
    };
    InfraredEmitterController controller;
    controller.irInterface_ = new (std::nothrow) FakeAdapter();
    std::vector<InfraredFrequencyInfo> frequencyInfo;
    int32_t result = controller.GetFrequencies(frequencyInfo);
    ASSERT_TRUE(result == RET_OK);
    ASSERT_EQ(frequencyInfo.size(), 2);
    ASSERT_EQ(frequencyInfo[0].min_, 36000);
    ASSERT_EQ(frequencyInfo[0].max_, 40000);
    ASSERT_EQ(frequencyInfo[1].min_, 38000);
    ASSERT_EQ(frequencyInfo[1].max_, 42000);
}

/**
 * @tc.name: InfraredEmitterControllerTest_HasIrEmitter_001
 * @tc.desc: Test GetFrequencies with valid data returned
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_HasIrEmitter_001, TestSize.Level1)
{
    InfraredEmitterController controller;
    const std::string irWrapperPath = "libmistouch_prevention.z.so";
    controller.soIrHandle_ = dlopen(irWrapperPath.c_str(), RTLD_NOW);
    bool hasIrEmitter = false;
    controller.HasIrEmitter(hasIrEmitter);
    ASSERT_TRUE(controller.soIrHandle_ == nullptr);
}
 
/**
 * @tc.name: InfraredEmitterControllerTest_HasIrEmitter_002
 * @tc.desc: Test GetFrequencies with valid data returned
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_HasIrEmitter_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct FakeAdapter : public IInfraredEmitterAdapter {
        int32_t Transmit(int32_t, const std::vector<int32_t>&, bool&) override { return 0; }
        int32_t GetCarrierFreqs(bool& ret, std::vector<HDI::Consumerir::V1_0::ConsumerIrFreqRange>& range) override
        {
            return 0;
        }
        int32_t HasIrEmitter(bool &hasIrEmitter) override
        {
            return 0;
        }
    };
    InfraredEmitterController controller;
    controller.irInterface_ = new (std::nothrow) FakeAdapter();
    ASSERT_NE(controller.irInterface_, nullptr);
    bool hasIrEmitter = false;
    int32_t result = controller.HasIrEmitter(hasIrEmitter);
    ASSERT_TRUE(result == RET_OK);
}
#endif // OHOS_BUILD_PC_UNIT_TEST
} // namespace MMI
} // namespace OHOS