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

#include "device_manager.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class DeviceManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: DeviceManagerTest_ExtractEventNumber_Valid
 * @tc.desc: Test extracting event number from valid file names
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceManagerTest, DeviceManagerTest_ExtractEventNumber_Valid, TestSize.Level1)
{
    DeviceManager deviceManager;
    EXPECT_EQ(deviceManager.ExtractEventNumber("event0"), 0);
    EXPECT_EQ(deviceManager.ExtractEventNumber("event1"), 1);
    EXPECT_EQ(deviceManager.ExtractEventNumber("event10"), 10);
    EXPECT_EQ(deviceManager.ExtractEventNumber("event999"), 999);
}

/**
 * @tc.name: DeviceManagerTest_ExtractEventNumber_Invalid
 * @tc.desc: Test extracting event number from invalid file names
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceManagerTest, DeviceManagerTest_ExtractEventNumber_Invalid, TestSize.Level1)
{
    DeviceManager deviceManager;
    EXPECT_EQ(deviceManager.ExtractEventNumber(""), -1);
    EXPECT_EQ(deviceManager.ExtractEventNumber("event"), -1);
    EXPECT_EQ(deviceManager.ExtractEventNumber("eventX"), -1);
    EXPECT_EQ(deviceManager.ExtractEventNumber("event-1"), -1);
    EXPECT_EQ(deviceManager.ExtractEventNumber("EVENT0"), -1);
    EXPECT_EQ(deviceManager.ExtractEventNumber("myevent0"), -1);
    EXPECT_EQ(deviceManager.ExtractEventNumber("event0suffix"), -1);
}

/**
 * @tc.name: DeviceManagerTest_BuildDevicePath
 * @tc.desc: Test building device path from file name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceManagerTest, DeviceManagerTest_BuildDevicePath, TestSize.Level1)
{
    DeviceManager deviceManager;
    EXPECT_EQ(deviceManager.BuildDevicePath("event0"), "/dev/input/event0");
    EXPECT_EQ(deviceManager.BuildDevicePath("test"), "/dev/input/test");
    EXPECT_EQ(deviceManager.BuildDevicePath(""), "/dev/input/");
}

/**
 * @tc.name: DeviceManagerTest_DiscoverDevices_NoException
 * @tc.desc: Test that DiscoverDevices doesn't throw exceptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceManagerTest, DeviceManagerTest_DiscoverDevices_NoException, TestSize.Level1)
{
    DeviceManager deviceManager;
    ASSERT_NO_FATAL_FAILURE({
        auto devices = deviceManager.DiscoverDevices();
    });
}

/**
 * @tc.name: DeviceManagerTest_PrintDeviceList_NoException
 * @tc.desc: Test that PrintDeviceList doesn't throw exceptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceManagerTest, DeviceManagerTest_PrintDeviceList_NoException, TestSize.Level1)
{
    DeviceManager deviceManager;
    ASSERT_NO_FATAL_FAILURE({
        deviceManager.PrintDeviceList();
    });
}
} // namespace MMI
} // namespace OHOS