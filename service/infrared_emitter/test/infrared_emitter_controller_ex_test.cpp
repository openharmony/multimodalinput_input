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
#include "mock.h"
 
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InfraredEmitterControllerTest"
 
namespace OHOS {
namespace MMI {
#ifndef OHOS_BUILD_PC_UNIT_TEST
namespace {
using namespace testing::ext;
using namespace testing;
class ConsumerIrTest : public OHOS::HDI::Consumerir::V1_0::ConsumerIr {
public:
    ConsumerIrTest() = default;
    ~ConsumerIrTest() {}
 
    int32_t Transmit(int32_t carrierFreq, const std::vector<int32_t>& pattern, bool& ret) { return 0; }
    int32_t GetCarrierFreqs(bool& ret, std::vector<OHOS::HDI::Consumerir::V1_0::ConsumerIrFreqRange>& range)
    {
        return 0;
    }
};
class IDeviceManagerTest : public OHOS::HDI::DeviceManager::V1_0::IDeviceManager {
public:
    IDeviceManagerTest() = default;
    virtual ~IDeviceManagerTest() = default;
 
    int32_t LoadDevice(const std::string &serviceName) { return 0; }
    int32_t UnloadDevice(const std::string &serviceName) { return 0; }
    int32_t ListAllDevice(std::vector<HDI::DeviceManager::V1_0::HdiDevHostInfo> &deviceInfos) { return 0; }
    int32_t ListAllHost(std::vector<int> &pidList) { return 0; }
};
} // namespace
 
class InfraredEmitterControllerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
 
    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};
 
void InfraredEmitterControllerTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}
 
void InfraredEmitterControllerTest::TearDownTestCase(void)
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}
 
void InfraredEmitterControllerTest::SetUp() {}
 
void InfraredEmitterControllerTest::TearDown() {}
 
/**
 * @tc.name: InfraredEmitterControllerTest_InitInfraredEmitter_001
 * @tc.desc: Test the funcation InitInfraredEmitter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_InitInfraredEmitter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<OHOS::HDI::Consumerir::V1_0::ConsumerIr> consumerIr = new ConsumerIrTest();
    EXPECT_CALL(*messageParcelMock_, Get(_, _)).WillOnce(Return(consumerIr));
    InfraredEmitterController controller;
    ASSERT_NO_FATAL_FAILURE(controller.InitInfraredEmitter());
}
 
/**
 * @tc.name: InfraredEmitterControllerTest_InitInfraredEmitter_002
 * @tc.desc: Test the funcation InitInfraredEmitter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_InitInfraredEmitter_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, Get(_, _)).WillOnce(Return(nullptr));
    EXPECT_CALL(*messageParcelMock_, Get()).WillOnce(Return(nullptr));
    InfraredEmitterController controller;
    ASSERT_NO_FATAL_FAILURE(controller.InitInfraredEmitter());
}
 
/**
 * @tc.name: InfraredEmitterControllerTest_InitInfraredEmitter_003
 * @tc.desc: Test the funcation InitInfraredEmitter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_InitInfraredEmitter_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, Get(_, _))
        .WillOnce(Return(nullptr))
        .WillOnce(Return(nullptr));
    sptr<OHOS::HDI::DeviceManager::V1_0::IDeviceManager> iDeviceManager = new IDeviceManagerTest();
    EXPECT_CALL(*messageParcelMock_, Get()).WillOnce(Return(iDeviceManager));
    InfraredEmitterController controller;
    ASSERT_NO_FATAL_FAILURE(controller.InitInfraredEmitter());
}
 
/**
 * @tc.name: InfraredEmitterControllerTest_InitInfraredEmitter_004
 * @tc.desc: Test the funcation InitInfraredEmitter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InfraredEmitterControllerTest, InfraredEmitterControllerTest_InitInfraredEmitter_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<OHOS::HDI::Consumerir::V1_0::ConsumerIr> consumerIr = new ConsumerIrTest();
    EXPECT_CALL(*messageParcelMock_, Get(_, _))
        .WillOnce(Return(nullptr))
        .WillOnce(Return(consumerIr));
    sptr<OHOS::HDI::DeviceManager::V1_0::IDeviceManager> iDeviceManager = new IDeviceManagerTest();
    EXPECT_CALL(*messageParcelMock_, Get()).WillOnce(Return(iDeviceManager));
    InfraredEmitterController controller;
    ASSERT_NO_FATAL_FAILURE(controller.InitInfraredEmitter());
}
#endif // OHOS_BUILD_PC_UNIT_TEST
} // namespace MMI
} // namespace OHOS