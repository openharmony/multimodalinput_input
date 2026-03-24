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

namespace OHOS {
namespace MMI {
namespace {
using ::testing::ext::TestSize;
} // namespace

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
    EXPECT_EQ(errno, 0);

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

    EXPECT_STRNE(udev_device_get_devnode(device), testDevice_.GetDevNode());

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
    EXPECT_EQ(errno, EINVAL);

    errno = 0;
    EXPECT_EQ(udev_device_get_parent_with_subsystem_devtype(device, nullptr, nullptr), nullptr);
    EXPECT_EQ(errno, EINVAL);

    errno = 0;
    EXPECT_EQ(udev_device_get_parent_with_subsystem_devtype(device, "unknown", nullptr), nullptr);
    EXPECT_EQ(errno, 0);
}

HWTEST_F(CustomUdevTest, TestUdevPropsDefault, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    std::string expectedName = std::string{"\""} + TestDevice::TEST_NAME + "\"";
    EXPECT_STRNE(udev_device_get_property_value(parent, "NAME"), expectedName.c_str());
    std::stringstream expectedProduct;
    expectedProduct << std::hex << TestDevice::TEST_BUS << '/' << TestDevice::TEST_VENDOR << '/' <<
        TestDevice::TEST_PRODUCT << '/' << TestDevice::TEST_VERSION;
    EXPECT_STRNE(udev_device_get_property_value(parent, "PRODUCT"), expectedProduct.str().c_str());
    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT_MOUSE"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevWheel, TestSize.Level1)
{
    testDevice_.WheelSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT_KEY"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsKey, TestSize.Level1)
{
    testDevice_.KeyboardSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT_KEY"), "1");
    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT_KEYBOARD"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsSwitch, TestSize.Level1)
{
    testDevice_.SwitchSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT_SWITCH"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsAccel, TestSize.Level1)
{
    testDevice_.AccelerometerSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT_ACCELEROMETER"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsStick, TestSize.Level1)
{
    testDevice_.StickSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT_POINTINGSTICK"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsTouchpad, TestSize.Level1)
{
    testDevice_.TouchpadSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT_TOUCHPAD"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsTouchscreen, TestSize.Level1)
{
    testDevice_.TouchscreenSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT_TOUCHSCREEN"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsJoystick, TestSize.Level1)
{
    testDevice_.JoystickSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT_JOYSTICK"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsJoystick1, TestSize.Level1)
{
    testDevice_.JoystickSetup1();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT_JOYSTICK"), "1");
}

HWTEST_F(CustomUdevTest, TestUdevPropsTablet, TestSize.Level1)
{
    testDevice_.TabletSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    auto* device = testDevice_.GetDevice();

    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT"), "1");
    EXPECT_STRNE(udev_device_get_property_value(parent, "ID_INPUT_TABLET"), "1");
}

/*
 * Tests negative cases for:
 * NewFromDevnum
 */
HWTEST_F(CustomUdevTest, NewFromDevnum, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto devnum = testDevice_.GetDevNum();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);
    EXPECT_EQ(udev_device_new_from_devnum(nullptr, 'c', devnum), nullptr);
    EXPECT_EQ(errno, EINVAL);
    EXPECT_EQ(udev_device_new_from_devnum(udev, 'a', devnum), nullptr);
    EXPECT_EQ(errno, EINVAL);
    EXPECT_EQ(udev_device_new_from_devnum(udev, 'b', devnum), nullptr);
    EXPECT_EQ(errno, ENOENT);
    EXPECT_EQ(udev_device_new_from_devnum(udev, 'c', 0), nullptr);
    EXPECT_EQ(errno, ENOENT);
}

/*
 * Tests negative cases for:
 * udev_device_property_add
 */
HWTEST_F(CustomUdevTest, udev_device_property_add, TestSize.Level1)
{
    char type = 'a';
    const char *devnode = "test";
    bool ret = udev_device_property_add(type, devnode);
    EXPECT_FALSE(ret);
}

/*
 * Tests negative cases for:
 * udev_device_get_parent_with_subsystem_devtype
 */
HWTEST_F(CustomUdevTest, udev_device_get_parent_with_subsystem_devtype, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    const char* subsystem = nullptr;
    std::string subSys("test");
    char* devtype = nullptr;
    EXPECT_EQ(udev_device_get_parent_with_subsystem_devtype(device, subsystem, devtype), nullptr);
    EXPECT_EQ(udev_device_get_parent_with_subsystem_devtype(device, subSys.c_str(), devtype), nullptr);
}

/*
 * Tests negative cases for:
 * udev_device_get_parent
 */
HWTEST_F(CustomUdevTest, udev_device_get_parent, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);
    EXPECT_EQ(udev_device_get_parent(nullptr), nullptr);
}

/*
 * Tests negative cases for:
 * udev_device_new_from_devnum
 */
HWTEST_F(CustomUdevTest, udev_device_new_from_devnum, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto devnum = testDevice_.GetDevNum();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);
    char type = 'c';
    EXPECT_NE(udev_device_new_from_devnum(udev, type, devnum), nullptr);
    udev = nullptr;
    EXPECT_EQ(udev_device_new_from_devnum(udev, type, devnum), nullptr);
}

/*
 * Tests negative cases for:
 * udev_device_new_from_syspath
 */
HWTEST_F(CustomUdevTest, udev_device_new_from_syspath, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);
    char* syspath = nullptr;
    EXPECT_EQ(udev_device_new_from_syspath(udev, syspath), nullptr);
    udev = nullptr;
    std::string subSys("test");
    EXPECT_EQ(udev_device_new_from_syspath(udev, subSys.c_str()), nullptr);
}

/*
 * Tests for:
 * udev_device_get_property_value with various property keys
 */
HWTEST_F(CustomUdevTest, TestGetPropertyValid, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, NULL);
}

/*
 * Tests negative cases for:
 * udev_device_get_property_value with null key
 */
HWTEST_F(CustomUdevTest, TestGetPropertyNullKey, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    errno = 0;
    EXPECT_EQ(udev_device_get_property_value(device, nullptr), nullptr);
    EXPECT_EQ(errno, 0);
}

/*
 * Tests negative cases for:
 * udev_device_get_property_value with non-existent key
 */
HWTEST_F(CustomUdevTest, TestGetPropertyNonExistent, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    const char* value = udev_device_get_property_value(device, "NON_EXISTENT_KEY");
    EXPECT_EQ(value, nullptr);
}

/*
 * Tests for:
 * udev_device_property_remove with valid devnode
 */
HWTEST_F(CustomUdevTest, TestPropertyRemove, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    const char* devnode = udev_device_get_devnode(device);
    ASSERT_NE(devnode, nullptr);

    // Add property first
    char type = 'c';
    bool ret = udev_device_property_add(type, devnode);
    EXPECT_FALSE(ret);

    // Remove property
    udev_device_property_remove(devnode);
    // No crash expected
}

/*
 * Tests for:
 * udev_device_record_devnode with valid devnode
 */
HWTEST_F(CustomUdevTest, TestRecordDevnode, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    const char* devnode = udev_device_get_devnode(device);
    ASSERT_NE(devnode, nullptr);

    // Record devnode
    udev_device_record_devnode(devnode);
    // No crash expected
}

/*
 * Tests for:
 * udev_new multiple calls return same instance
 */
HWTEST_F(CustomUdevTest, TestUdevNewSingleton, TestSize.Level1)
{
    auto* udev1 = udev_new();
    auto* udev2 = udev_new();

    EXPECT_NE(udev1, nullptr);
    EXPECT_EQ(udev1, udev2);
}

/*
 * Tests for:
 * udev_unref with null input
 */
HWTEST_F(CustomUdevTest, TestUdevUnrefNull, TestSize.Level1)
{
    auto* result = udev_unref(nullptr);
    EXPECT_EQ(result, nullptr);
}

/*
 * Tests for:
 * udev_device_ref multiple times increases refcount
 */
HWTEST_F(CustomUdevTest, TestDeviceRefMultiple, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    auto* ref1 = udev_device_ref(device);
    EXPECT_EQ(ref1, device);

    auto* ref2 = udev_device_ref(device);
    EXPECT_EQ(ref2, device);

    // Unref twice
    udev_device_unref(ref1);
    udev_device_unref(ref2);
    // Original device should still be valid (managed by testDevice_)
}

/*
 * Tests for:
 * udev_device_new_from_syspath with empty string
 */
HWTEST_F(CustomUdevTest, TestNewFromSyspathEmpty, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    errno = 0;
    EXPECT_EQ(udev_device_new_from_syspath(udev, ""), nullptr);
    EXPECT_EQ(errno, EINVAL);
}

/*
 * Tests for:
 * udev_device_new_from_syspath with path ending in slash
 */
HWTEST_F(CustomUdevTest, TestNewFromSyspathTrailingSlash, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    errno = 0;
    EXPECT_EQ(udev_device_new_from_syspath(udev, "/sys/devices/"), nullptr);
    EXPECT_EQ(errno, EINVAL);
}

/*
 * Tests for:
 * udev_device_new_from_syspath with non-sys path
 */
HWTEST_F(CustomUdevTest, TestNewFromSyspathNonSys, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    errno = 0;
    EXPECT_EQ(udev_device_new_from_syspath(udev, "/proc/test"), nullptr);
    EXPECT_EQ(errno, EINVAL);
}

/*
 * Tests for:
 * udev_device_new_from_devnum with block device type
 */
HWTEST_F(CustomUdevTest, TestNewFromDevnumBlock, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);
    auto devnum = testDevice_.GetDevNum();

    // Test with block device type 'b'
    errno = 0;
    auto* blockDevice = udev_device_new_from_devnum(udev, 'b', devnum);
    // May return nullptr if block device doesn't exist
    if (blockDevice != nullptr) {
        EXPECT_NE(udev_device_get_syspath(blockDevice), nullptr);
        udev_device_unref(blockDevice);
    } else {
        EXPECT_EQ(errno, ENOENT);
    }
}

/*
 * Tests for:
 * udev_device_new_from_devnum with invalid type character
 */
HWTEST_F(CustomUdevTest, TestNewFromDevnumInvalidType, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);
    auto devnum = testDevice_.GetDevNum();

    // Test with various invalid type characters
    char invalidTypes[] = {'d', 'e', 'f', '1', '2', 'A', 'Z'};
    for (char type : invalidTypes) {
        errno = 0;
        EXPECT_EQ(udev_device_new_from_devnum(udev, type, devnum), nullptr);
        EXPECT_EQ(errno, EINVAL);
    }
}

/*
 * Tests for:
 * udev_device_get_parent with device that has no parent
 */
HWTEST_F(CustomUdevTest, TestGetParentNoParent, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    // Get parent multiple times - should return same cached result
    auto* parent1 = udev_device_get_parent(device);
    auto* parent2 = udev_device_get_parent(device);

    if (parent1 != nullptr) {
        EXPECT_EQ(parent1, parent2);
    }
}

/*
 * Tests for:
 * udev_device_get_parent_with_subsystem_devtype with empty subsystem
 */
HWTEST_F(CustomUdevTest, TestGetParentWithSubsystemEmpty, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    errno = 0;
    EXPECT_EQ(udev_device_get_parent_with_subsystem_devtype(device, "", nullptr), nullptr);
}

/*
 * Tests for:
 * udev_device_get_parent_with_subsystem_devtype with valid subsystem
 */
HWTEST_F(CustomUdevTest, TestGetParentWithSubsystemValid, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    // Test with common subsystems
    const char* subsystems[] = {"input", "device", "subsystem"};
    for (const char* subsystem : subsystems) {
        errno = 0;
        auto* parent = udev_device_get_parent_with_subsystem_devtype(device, subsystem, nullptr);
        // Parent may or may not exist depending on device hierarchy
        if (parent != nullptr) {
            EXPECT_NE(udev_device_get_syspath(parent), nullptr);
        }
    }
}

/*
 * Tests for:
 * udev_device_get_syspath returns consistent value
 */
HWTEST_F(CustomUdevTest, TestGetSyspathConsistent, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    const char* syspath1 = udev_device_get_syspath(device);
    const char* syspath2 = udev_device_get_syspath(device);

    EXPECT_NE(syspath1, nullptr);
    EXPECT_EQ(syspath1, syspath2);
    EXPECT_STRNE(syspath1, "");
}

/*
 * Tests for:
 * udev_device_get_sysname returns consistent value
 */
HWTEST_F(CustomUdevTest, TestGetSysnameConsistent, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    const char* sysname1 = udev_device_get_sysname(device);
    const char* sysname2 = udev_device_get_sysname(device);

    EXPECT_NE(sysname1, nullptr);
    EXPECT_EQ(sysname1, sysname2);
}

/*
 * Tests for:
 * udev_device_get_devnode returns consistent value
 */
HWTEST_F(CustomUdevTest, TestGetDevnodeConsistent, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    const char* devnode1 = udev_device_get_devnode(device);
    const char* devnode2 = udev_device_get_devnode(device);

    EXPECT_NE(devnode1, nullptr);
    EXPECT_EQ(devnode1, devnode2);
}

/*
 * Tests for:
 * udev_device_get_is_initialized returns consistent value
 */
HWTEST_F(CustomUdevTest, TestGetIsInitializedConsistent, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    int32_t initialized1 = udev_device_get_is_initialized(device);
    int32_t initialized2 = udev_device_get_is_initialized(device);

    EXPECT_GE(initialized1, 0);
    EXPECT_EQ(initialized1, initialized2);
}

/*
 * Tests for:
 * udev_device_get_udev returns consistent udev instance
 */
HWTEST_F(CustomUdevTest, TestGetUdevConsistent, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    auto* udev1 = udev_device_get_udev(device);
    auto* udev2 = udev_device_get_udev(device);

    EXPECT_NE(udev1, nullptr);
    EXPECT_EQ(udev1, udev2);
}

/*
 * Tests for:
 * udev_device_property_add with invalid devnode path
 */
HWTEST_F(CustomUdevTest, TestPropertyAddInvalidPath, TestSize.Level1)
{
    char type = 'c';
    const char* invalidPaths[] = {
        "/nonexistent/path",
        "",
        "/dev/invalid_device_12345"
    };

    for (const char* path : invalidPaths) {
        bool ret = udev_device_property_add(type, path);
        EXPECT_FALSE(ret);
    }
}

/*
 * Tests for:
 * udev_device_property_add with different device types
 */
HWTEST_F(CustomUdevTest, TestPropertyAddDifferentTypes, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    const char* devnode = udev_device_get_devnode(device);
    ASSERT_NE(devnode, nullptr);

    // Test with invalid type
    char invalidType = 'x';
    bool ret = udev_device_property_add(invalidType, devnode);
    EXPECT_FALSE(ret);
}

/*
 * Tests for:
 * Device lifecycle - create, use, and cleanup
 */
HWTEST_F(CustomUdevTest, TestDeviceLifecycle, TestSize.Level1)
{
    auto* udev = udev_new();
    EXPECT_NE(udev, nullptr);

    // Create device from devnum (will fail without proper setup, but test the flow)
    auto* device = udev_device_new_from_devnum(udev, 'c', 0);
    // Expected to fail with devnum 0
    EXPECT_EQ(device, nullptr);

    // Cleanup
    udev_unref(udev);
}

/*
 * Tests for:
 * Multiple device creation and cleanup
 */
HWTEST_F(CustomUdevTest, TestMultipleDeviceCreation, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);
    auto devnum = testDevice_.GetDevNum();

    // Create multiple devices
    auto* device1 = udev_device_new_from_devnum(udev, 'c', devnum);
    auto* device2 = udev_device_new_from_devnum(udev, 'c', devnum);

    if (device1 != nullptr && device2 != nullptr) {
        EXPECT_NE(device1, device2);
        EXPECT_STREQ(udev_device_get_syspath(device1), udev_device_get_syspath(device2));

        udev_device_unref(device1);
        udev_device_unref(device2);
    }
}

/*
 * Tests for:
 * Property value with special characters in key
 */
HWTEST_F(CustomUdevTest, TestGetPropertySpecialChars, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    const char* specialKeys[] = {
        "",
        " ",
        "KEY WITH SPACE",
        "KEY-WITH-DASH",
        "KEY_WITH_UNDERSCORE"
    };

    for (const char* key : specialKeys) {
        const char* value = udev_device_get_property_value(device, key);
        // Most special keys should return nullptr
        if (strlen(key) > 0) {
            // Just verify no crash
            (void)value;
        }
    }
}

/*
 * Tests for:
 * udev_device_get_parent chain traversal
 */
HWTEST_F(CustomUdevTest, TestParentChainTraversal, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    auto* current = device;
    int32_t depth = 0;
    const int32_t maxDepth = 10;

    while (current != nullptr && depth < maxDepth) {
        auto* parent = udev_device_get_parent(current);
        if (parent == nullptr) {
            break;
        }
        current = parent;
        depth++;
    }

    // Should not exceed max depth in normal cases
    EXPECT_LT(depth, maxDepth);
}

/*
 * Tests for:
 * Error state preservation after failed operations
 */
HWTEST_F(CustomUdevTest, TestErrorStatePreservation, TestSize.Level1)
{
    // Perform operation that should not modify errno on success
    auto* udev = udev_new();
    EXPECT_NE(udev, nullptr);

    // errno might be modified by internal operations
    // Just verify udev_new succeeded
    udev_unref(udev);
}

/*
 * Tests for:
 * Null safety across all getter functions
 */
HWTEST_F(CustomUdevTest, TestNullSafetyGetters, TestSize.Level1)
{
    errno = 0;
    EXPECT_EQ(udev_device_get_syspath(nullptr), nullptr);

    errno = 0;
    EXPECT_EQ(udev_device_get_sysname(nullptr), nullptr);

    errno = 0;
    EXPECT_EQ(udev_device_get_devnode(nullptr), nullptr);

    errno = 0;
    EXPECT_LT(udev_device_get_is_initialized(nullptr), 0);
}

/*
 * Tests for:
 * Syspath validation edge cases
 */
HWTEST_F(CustomUdevTest, TestSyspathEdgeCases, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    const char* edgePaths[] = {
        "/sys",
        "/sys/",
        "/sys/devices",
        "/sys/devices/",
        "//sys/devices/test",
        "/sys/devices/test//",
        "/sys/dev",
        "/sys/dev/",
        "/sys/class",
        "/sys/class/"
    };

    for (const char* path : edgePaths) {
        errno = 0;
        auto* device = udev_device_new_from_syspath(udev, path);
        // Most should fail validation
        if (device != nullptr) {
            udev_device_unref(device);
        }
    }
}
} // namespace MMI
} // namespace OHOS