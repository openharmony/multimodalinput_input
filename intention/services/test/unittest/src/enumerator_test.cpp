/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vector>
#include <memory>

#include <unistd.h>

#include "device_manager.h"
#include <gtest/gtest.h>
#include "enumerator.h"

#include "devicestatus_define.h"
#include "devicestatus_errors.h"

#undef LOG_TAG
#define LOG_TAG "EnumeratorTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
const std::string TEST_DEV_NODE {"TestDeviceNode"};
} // namespace

class EnumeratorTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase(void);
};
void EnumeratorTest::SetUpTestCase() {}

void EnumeratorTest::TearDownTestCase() {}

void EnumeratorTest::SetUp() {}

void EnumeratorTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

class TestDeviceMgr : public IDeviceMgr {
public:
    TestDeviceMgr() = default;
    ~TestDeviceMgr() = default;
    void AddDevice(const std::string &devNode) override
    {
        devMgr_.DeviceManager::AddDevice(devNode);
    }
    void RemoveDevice(const std::string &devNode) override
    {
        devMgr_.DeviceManager::RemoveDevice(devNode);
    }
private:
    DeviceManager devMgr_;
};

/**
 * @tc.name: EnumeratorTest01
 * @tc.desc: test SetDeviceMgr and AddDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EnumeratorTest, EnumeratorTest01, TestSize.Level1)
{
    Enumerator enumerator;
    std::shared_ptr<TestDeviceMgr> testDevMgr = std::make_shared<TestDeviceMgr>();
    IDeviceMgr *deviceMgr = testDevMgr.get();
    ASSERT_NO_FATAL_FAILURE(enumerator.SetDeviceMgr(deviceMgr));
    ASSERT_NO_FATAL_FAILURE(enumerator.AddDevice(TEST_DEV_NODE));
}

/**
 * @tc.name: EnumeratorTest02
 * @tc.desc: test ScanDevices and ScanAndAddDevices
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EnumeratorTest, EnumeratorTest02, TestSize.Level1)
{
    Enumerator enumerator;
    ASSERT_NO_FATAL_FAILURE(enumerator.ScanDevices());
    ASSERT_NO_FATAL_FAILURE(enumerator.ScanAndAddDevices());
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS