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
#include "monitor.h"

#include "devicestatus_define.h"
#include "devicestatus_errors.h"

#undef LOG_TAG
#define LOG_TAG "MonitorTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
const std::string TEST_DEV_NODE {"TestDeviceNode"};
} // namespace

class MonitorTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase(void);
};
void MonitorTest::SetUpTestCase() {}

void MonitorTest::TearDownTestCase() {}

void MonitorTest::SetUp() {}

void MonitorTest::TearDown()
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
 * @tc.name: MonitorTest01
 * @tc.desc: test Dispatch event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MonitorTest, MonitorTest01, TestSize.Level1)
{
    Monitor monitor;
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ASSERT_NO_FATAL_FAILURE(monitor.Dispatch(ev));
    ev.events = EPOLLHUP;
    ASSERT_NO_FATAL_FAILURE(monitor.Dispatch(ev));
    ev.events = EPOLLERR;
    ASSERT_NO_FATAL_FAILURE(monitor.Dispatch(ev));
}

/**
 * @tc.name: MonitorTest02
 * @tc.desc: test Enable and Disable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MonitorTest, MonitorTest02, TestSize.Level1)
{
    Monitor monitor;
    int32_t ret = monitor.Enable();
    EXPECT_EQ(ret, RET_OK);
    ASSERT_NO_FATAL_FAILURE(monitor.Disable());
}

/**
 * @tc.name: MonitorTest03
 * @tc.desc: test OpenConnection and EnableReceiving
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MonitorTest, MonitorTest03, TestSize.Level1)
{
    Monitor monitor;
    int32_t ret = monitor.OpenConnection();
    EXPECT_EQ(ret, RET_OK);
    ret = monitor.EnableReceiving();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MonitorTest04
 * @tc.desc: test AddDevice and RemoveDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MonitorTest, MonitorTest04, TestSize.Level1)
{
    Monitor monitor;
    ASSERT_NO_FATAL_FAILURE(monitor.AddDevice(TEST_DEV_NODE));
    ASSERT_NO_FATAL_FAILURE(monitor.RemoveDevice(TEST_DEV_NODE));
}

/**
 * @tc.name: MonitorTest05
 * @tc.desc: test SetDeviceMgr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MonitorTest, MonitorTest05, TestSize.Level1)
{
    Monitor monitor;
    std::shared_ptr<TestDeviceMgr> testDevMgr = std::make_shared<TestDeviceMgr>();
    IDeviceMgr *deviceMgr = testDevMgr.get();
    ASSERT_NO_FATAL_FAILURE(monitor.SetDeviceMgr(deviceMgr));
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS