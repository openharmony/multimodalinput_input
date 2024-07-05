/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <libudev.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "test_device.h"

using ::testing::ext::TestSize;

class UdevTestDevice : public TestDevice {
public:
    UdevTestDevice()
    {
        udev_ = udev_new();
    }

    ~UdevTestDevice()
    {
        if (udevDevice_ != nullptr) {
            udevDevice_ = udev_device_unref(udevDevice_);
        }
        udev_unref(udev_);
    }

    void Init(bool def = true)
    {
        ASSERT_NE(udev_, nullptr);
        ASSERT_NO_FATAL_FAILURE(TestDevice::Init(def));
        udevDevice_ = udev_device_new_from_devnum(udev_, 'c', GetDevNum());
        ASSERT_NE(udevDevice_, nullptr);
    }

    auto GetUdev() const
    {
        return udev_;
    }

    auto GetDevice() const
    {
        return udevDevice_;
    }

private:
    struct udev* udev_{};
    struct udev_device* udevDevice_{};
};

class CustomUdevTest : public ::testing::Test {
public:
    UdevTestDevice testDevice_;
};

/*
 * Tests:
 * udev_device_new_from_devnum (uses udev_device_new_from_syspath)
 * udev_device_get_udev
 * udev_device_ref
 * udev_device_unref
 */
HWTEST_F(CustomUdevTest, TestBasics, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    EXPECT_EQ(udev_device_get_udev(device), testDevice_.GetUdev());

    auto* res = udev_device_ref(device);
    EXPECT_NE(res, nullptr);
    EXPECT_EQ(res, device);

    res = udev_device_unref(device);
    EXPECT_EQ(res, nullptr);
}

/*
 * Tests negative cases for:
 * udev_device_new_from_devnum (uses udev_device_new_from_syspath)
 * udev_device_get_udev
 * udev_device_ref
 * udev_device_unref
 */
HWTEST_F(CustomUdevTest, TestBasicsFail, TestSize.Level1)
{
    errno = 0;
    EXPECT_EQ(udev_device_get_udev(nullptr), nullptr);
    EXPECT_NE(errno, 0);

    errno = 0;
    EXPECT_EQ(udev_device_ref(nullptr), nullptr);
    EXPECT_EQ(errno, 0);

    errno = 0;
    EXPECT_EQ(udev_device_unref(nullptr), nullptr);
    EXPECT_EQ(errno, 0);
}

/*
 * Tests negative cases for:
 * udev_device_new_from_devnum
 */
HWTEST_F(CustomUdevTest, TestNewFail1, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto devnum = testDevice_.GetDevNum();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);

    errno = 0;
    EXPECT_EQ(udev_device_new_from_devnum(nullptr, 'c', devnum), nullptr);
    EXPECT_EQ(errno, EINVAL);

    errno = 0;
    // Invalid device type
    EXPECT_EQ(udev_device_new_from_devnum(udev, 'a', devnum), nullptr);
    EXPECT_EQ(errno, EINVAL);

    errno = 0;
    // Wrong devnum
    EXPECT_EQ(udev_device_new_from_devnum(udev, 'b', devnum), nullptr);
    EXPECT_EQ(errno, ENOENT);

    errno = 0;
    // Invalid devnum
    EXPECT_EQ(udev_device_new_from_devnum(udev, 'c', 0), nullptr);
    EXPECT_EQ(errno, ENOENT);
}

/*
 * Tests negative cases for:
 * udev_device_new_from_syspath
 */
HWTEST_F(CustomUdevTest, TestNewFail2, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    errno = 0;
    EXPECT_EQ(udev_device_new_from_syspath(nullptr, testDevice_.GetSysPath()), nullptr);
    EXPECT_EQ(errno, EINVAL);

    errno = 0;
    EXPECT_EQ(udev_device_new_from_syspath(udev, nullptr), nullptr);
    EXPECT_EQ(errno, EINVAL);

    errno = 0;
    EXPECT_EQ(udev_device_new_from_syspath(udev, "/system"), nullptr);
    EXPECT_EQ(errno, EINVAL);

    errno = 0;
    EXPECT_EQ(udev_device_new_from_syspath(udev, "/sys/unknown"), nullptr);
    EXPECT_EQ(errno, ENOENT);

    errno = 0;
    EXPECT_EQ(udev_device_new_from_syspath(udev, "/sys/char/0:0"), nullptr);
    EXPECT_EQ(errno, ENOENT);
}

/*
 * Tests:
 * udev_device_get_is_initialized()
 */
HWTEST_F(CustomUdevTest, TestIsInitialized, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    EXPECT_EQ(udev_device_get_is_initialized(device), 1);

    errno = 0;
    EXPECT_LT(udev_device_get_is_initialized(nullptr), 0);
    EXPECT_EQ(errno, 0);
}

/*
 * Tests:
 * udev_device_get_devnode()
 */
HWTEST_F(CustomUdevTest, TestGetDevnode, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    EXPECT_STREQ(udev_device_get_devnode(device), testDevice_.GetDevNode());

    errno = 0;
    EXPECT_EQ(udev_device_get_devnode(nullptr), nullptr);
    EXPECT_EQ(errno, 0);
}

/*
 * Test for:
 * udev_device_get_sysname()
 */
HWTEST_F(CustomUdevTest, TestGetSysname, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    EXPECT_EQ(std::string("/dev/input/") + udev_device_get_sysname(device), testDevice_.GetDevNode());

    errno = 0;
    EXPECT_EQ(udev_device_get_sysname(nullptr), nullptr);
    EXPECT_EQ(errno, 0);
}

/*
 * Test for:
 * udev_device_get_syspath()
 */
HWTEST_F(CustomUdevTest, TestGetSyspath, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    EXPECT_EQ(udev_device_get_syspath(device),
        testDevice_.GetSysPath() + std::string("/") + udev_device_get_sysname(device));

    errno = 0;
    EXPECT_EQ(udev_device_get_syspath(nullptr), nullptr);
    EXPECT_EQ(errno, 0);
}

/*
 * Test for:
 * udev_device_get_property_value()
 * Properties:
 * - DEVNAME
 * - MAJOR
 * - MINOR
 */
HWTEST_F(CustomUdevTest, TestGetProperty, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    EXPECT_STREQ(udev_device_get_property_value(device, "DEVNAME"), testDevice_.GetDevNode());

    auto devnum = testDevice_.GetDevNum();
    EXPECT_EQ(udev_device_get_property_value(device, "MINOR"), std::to_string(minor(devnum)));
    EXPECT_EQ(udev_device_get_property_value(device, "MAJOR"), std::to_string(major(devnum)));

    errno = 0;
    EXPECT_EQ(udev_device_get_property_value(nullptr, "DEVNAME"), nullptr);
    EXPECT_EQ(errno, 0);

    errno = 0;
    EXPECT_EQ(udev_device_get_property_value(device, nullptr), nullptr);
    EXPECT_EQ(errno, 0);

    errno = 0;
    EXPECT_EQ(udev_device_get_property_value(device, "UNKNOWN"), nullptr);
    EXPECT_EQ(errno, 0);
}

/*
 * Test for:
 * udev_device_get_parent()
 */
HWTEST_F(CustomUdevTest, TestGetParent1, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);
    EXPECT_STREQ(udev_device_get_syspath(parent), testDevice_.GetSysPath());

    errno = 0;
    EXPECT_EQ(udev_device_get_parent(nullptr), nullptr);
    EXPECT_EQ(errno, EINVAL);
}

/*
 * Test for:
 * udev_device_get_parent_with_subsystem_devtype()
 */
HWTEST_F(CustomUdevTest, TestGetParent2, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent_with_subsystem_devtype(device, "input", nullptr);
    ASSERT_EQ(parent, nullptr);
    EXPECT_NE(udev_device_get_syspath(parent), testDevice_.GetSysPath());

    errno = 0;
    EXPECT_EQ(udev_device_get_parent_with_subsystem_devtype(nullptr, "input", nullptr), nullptr);
    EXPECT_EQ(errno, 0);

    errno = 0;
    EXPECT_NE(udev_device_get_parent_with_subsystem_devtype(device, "input", ""), nullptr);
    EXPECT_EQ(errno, 0);

    errno = 0;
    EXPECT_EQ(udev_device_get_parent_with_subsystem_devtype(device, nullptr, nullptr), nullptr);
    EXPECT_EQ(errno, EINVAL);

    errno = 0;
    EXPECT_EQ(udev_device_get_parent_with_subsystem_devtype(device, "unknown", nullptr), nullptr);
    EXPECT_EQ(errno, ENOENT);
}

HWTEST_F(CustomUdevTest, TestUdevPropsDefault, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    std::string expectedName = std::string{"\""} + TestDevice::TEST_NAME + "\"";
    EXPECT_STREQ(udev_device_get_property_value(parent, "NAME"), expectedName.c_str());
    std::stringstream expectedProduct;
    expectedProduct << std::hex << TestDevice::TEST_BUS << '/' << TestDevice::TEST_VENDOR << '/' <<
        TestDevice::TEST_PRODUCT << '/' << TestDevice::TEST_VERSION;
    EXPECT_STREQ(udev_device_get_property_value(parent, "PRODUCT"), expectedProduct.str().c_str());
    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT_MOUSE"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevWheel, TestSize.Level1)
{
    testDevice_.WheelSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT_KEY"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevAbsMouse, TestSize.Level1)
{
    testDevice_.AbsMouseSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT_MOUSE"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsKey, TestSize.Level1)
{
    testDevice_.KeyboardSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT_KEY"), "1");
    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT_KEYBOARD"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsSwitch, TestSize.Level1)
{
    testDevice_.SwitchSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT_SWITCH"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsAccel, TestSize.Level1)
{
    testDevice_.AccelerometerSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT_ACCELEROMETER"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsStick, TestSize.Level1)
{
    testDevice_.StickSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT_POINTINGSTICK"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsTouchpad, TestSize.Level1)
{
    testDevice_.TouchpadSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT_TOUCHPAD"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsTouchscreen, TestSize.Level1)
{
    testDevice_.TouchscreenSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT_TOUCHSCREEN"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsJoystick, TestSize.Level1)
{
    testDevice_.JoystickSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT_JOYSTICK"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsJoystick1, TestSize.Level1)
{
    testDevice_.JoystickSetup1();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT_JOYSTICK"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsTablet, TestSize.Level1)
{
    testDevice_.TabletSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STREQ(udev_device_get_property_value(parent, "ID_INPUT_TABLET"), "1");
}
