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
#include "input_device.h"

#include <gtest/gtest.h>

#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputDeviceTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
};

void InputDeviceTest::SetUpTestCase()
{
}

void InputDeviceTest::SetUp()
{
}

void InputDeviceTest::TearDown()
{
}

/**
 * @tc.name: InputDeviceTest_SetVirtualDevice_01
 * @tc.desc: Test SetVirtualDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceTest, InputDeviceTest_SetVirtualDevice_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDevice device;
    device.SetVirtualDevice(true);
    EXPECT_TRUE(device.IsVirtualDevice());

    device.SetVirtualDevice(false);
    EXPECT_FALSE(device.IsVirtualDevice());
}

/**
 * @tc.name: InputDeviceTest_SetRemoteDevice_01
 * @tc.desc: Test SetRemoteDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceTest, InputDeviceTest_SetRemoteDevice_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDevice device;
    device.SetRemoteDevice(true);
    EXPECT_TRUE(device.IsRemoteDevice());

    device.SetRemoteDevice(false);
    EXPECT_FALSE(device.IsRemoteDevice());
}
} // namespace MMI
} // namespace OHOS
