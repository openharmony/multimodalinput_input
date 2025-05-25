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

#include "input_device.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: InputDeviceTest_DefaultConstructor
 * @tc.desc: Test default constructor of InputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceTest, InputDeviceTest_DefaultConstructor, TestSize.Level1)
{
    InputDevice device;
    EXPECT_EQ(device.GetId(), 0);
    EXPECT_EQ(device.GetFd(), -1);
    EXPECT_TRUE(device.GetPath().empty());
    EXPECT_TRUE(device.GetName().empty());
    EXPECT_FALSE(device.IsOpen());
}

/**
 * @tc.name: InputDeviceTest_ParamConstructor
 * @tc.desc: Test parameterized constructor of InputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceTest, InputDeviceTest_ParamConstructor, TestSize.Level1)
{
    InputDevice device("/non/existent/path", 123);
    EXPECT_EQ(device.GetId(), 123);
    EXPECT_EQ(device.GetPath(), "/non/existent/path");
    EXPECT_FALSE(device.IsOpen());
}

/**
 * @tc.name: InputDeviceTest_MoveConstructor
 * @tc.desc: Test move constructor of InputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceTest, InputDeviceTest_MoveConstructor, TestSize.Level1)
{
    InputDevice device1;
    device1.SetId(42);
    device1.SetPath("/test/path");
    device1.SetName("TestDevice");

    InputDevice device2(std::move(device1));
    EXPECT_EQ(device2.GetId(), 42);
    EXPECT_EQ(device2.GetPath(), "/test/path");
    EXPECT_EQ(device2.GetName(), "TestDevice");

    EXPECT_TRUE(device1.GetPath().empty());
    EXPECT_TRUE(device1.GetName().empty());
}

/**
 * @tc.name: InputDeviceTest_MoveAssignment
 * @tc.desc: Test move assignment operator of InputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceTest, InputDeviceTest_MoveAssignment, TestSize.Level1)
{
    InputDevice device1;
    device1.SetId(42);
    device1.SetPath("/test/path");
    device1.SetName("TestDevice");

    InputDevice device2;
    device2 = std::move(device1);
    EXPECT_EQ(device2.GetId(), 42);
    EXPECT_EQ(device2.GetPath(), "/test/path");
    EXPECT_EQ(device2.GetName(), "TestDevice");

    EXPECT_TRUE(device1.GetPath().empty());
    EXPECT_TRUE(device1.GetName().empty());
}

/**
 * @tc.name: InputDeviceTest_SettersGetters
 * @tc.desc: Test setters and getters of InputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceTest, InputDeviceTest_SettersGetters, TestSize.Level1)
{
    InputDevice device;

    device.SetId(123);
    EXPECT_EQ(device.GetId(), 123);

    device.SetPath("/some/path");
    EXPECT_EQ(device.GetPath(), "/some/path");

    device.SetName("Device Name");
    EXPECT_EQ(device.GetName(), "Device Name");
}

/**
 * @tc.name: InputDeviceTest_TrimString
 * @tc.desc: Test TrimString method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceTest, InputDeviceTest_TrimString, TestSize.Level1)
{
    std::string str1 = "  test string  ";
    TrimString(str1);
    EXPECT_EQ(str1, "test string");

    std::string str2 = "test";
    TrimString(str2);
    EXPECT_EQ(str2, "test");

    std::string str3 = "  ";
    TrimString(str3);
    EXPECT_TRUE(str3.empty());

    std::string str4 = "";
    TrimString(str4);
    EXPECT_TRUE(str4.empty());
}

/**
 * @tc.name: InputDeviceTest_RemovePrefix
 * @tc.desc: Test RemovePrefix method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceTest, InputDeviceTest_RemovePrefix, TestSize.Level1)
{
    std::string str1 = "PREFIX:value";
    EXPECT_TRUE(RemovePrefix(str1, "PREFIX:"));
    EXPECT_EQ(str1, "value");

    std::string str2 = "NON_PREFIX:value";
    EXPECT_FALSE(RemovePrefix(str2, "PREFIX:"));
    EXPECT_EQ(str2, "NON_PREFIX:value");

    std::string str3 = "PREFIX:  value  ";
    EXPECT_TRUE(RemovePrefix(str3, "PREFIX:"));
    EXPECT_NE(str3, "value");
}

/**
 * @tc.name: InputDeviceTest_InitFromTextLine_Valid
 * @tc.desc: Test initializing device from valid text line
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceTest, InputDeviceTest_InitFromTextLine_Valid, TestSize.Level1)
{
    InputDevice device;
    EXPECT_TRUE(device.InitFromTextLine("DEVICE: 42 | /dev/input/event0 | Keyboard|adfa9924"));
    EXPECT_EQ(device.GetId(), 42);
    EXPECT_EQ(device.GetPath(), "/dev/input/event0");
    EXPECT_EQ(device.GetName(), "Keyboard");
}

/**
 * @tc.name: InputDeviceTest_InitFromTextLine_Invalid
 * @tc.desc: Test initializing device from invalid text lines
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceTest, InputDeviceTest_InitFromTextLine_Invalid, TestSize.Level1)
{
    InputDevice device;
    EXPECT_FALSE(device.InitFromTextLine("42 | /dev/input/event0 | Keyboard|adfa9921"));
    EXPECT_FALSE(device.InitFromTextLine("DEVICE: 42 /dev/input/event0 | Keyboard|adfa9922"));
    EXPECT_FALSE(device.InitFromTextLine("DEVICE: 42 | /dev/input/event0 Keyboard|adfa9923"));
    EXPECT_FALSE(device.InitFromTextLine("DEVICE: abc | /dev/input/event0 | Keyboard|adfa9924"));
}

/**
 * @tc.name: InputDeviceTest_WriteEvents_EmptyVector
 * @tc.desc: Test writing empty vector of events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceTest, InputDeviceTest_WriteEvents_EmptyVector, TestSize.Level1)
{
    InputDevice device;
    std::vector<input_event> events;
    EXPECT_FALSE(device.WriteEvents(events));
}
} // namespace MMI
} // namespace OHOS