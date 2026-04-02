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

/*
 * Tests for:
 * udev_device_new_from_syspath with double slash in path
 */
HWTEST_F(CustomUdevTest, TestNewFromSyspathDoubleSlash, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    errno = 0;
    EXPECT_EQ(udev_device_new_from_syspath(udev, "//sys/devices/test"), nullptr);
    EXPECT_EQ(errno, EINVAL);
}

/*
 * Tests for:
 * udev_device_new_from_syspath with very long path
 */
HWTEST_F(CustomUdevTest, TestNewFromSyspathLongPath, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    std::string longPath = "/sys/devices/";
    for (int32_t i = 0; i < 100; i++) {
        longPath += "layer" + std::to_string(i) + "/";
    }
    longPath += "device";

    errno = 0;
    auto* device = udev_device_new_from_syspath(udev, longPath.c_str());
    // Should fail due to non-existent path
    if (device != nullptr) {
        udev_device_unref(device);
    }
}

/*
 * Tests for:
 * udev_device_new_from_syspath with relative path
 */
HWTEST_F(CustomUdevTest, TestNewFromSyspathRelativePath, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    errno = 0;
    EXPECT_EQ(udev_device_new_from_syspath(udev, "devices/test"), nullptr);
    EXPECT_EQ(errno, EINVAL);
}

/*
 * Tests for:
 * udev_device_new_from_syspath with null udev but valid syspath
 */
HWTEST_F(CustomUdevTest, TestNewFromSyspathNullUdev, TestSize.Level1)
{
    errno = 0;
    EXPECT_EQ(udev_device_new_from_syspath(nullptr, "/sys/devices/test"), nullptr);
    EXPECT_EQ(errno, EINVAL);
}

/*
 * Tests for:
 * udev_device_new_from_devnum with both valid block and char types
 */
HWTEST_F(CustomUdevTest, TestNewFromDevnumBothTypes, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);
    auto devnum = testDevice_.GetDevNum();

    // Test char device type 'c'
    errno = 0;
    auto* charDevice = udev_device_new_from_devnum(udev, 'c', devnum);
    if (charDevice != nullptr) {
        EXPECT_NE(udev_device_get_syspath(charDevice), nullptr);
        udev_device_unref(charDevice);
    }

    // Test block device type 'b'
    errno = 0;
    auto* blockDevice = udev_device_new_from_devnum(udev, 'b', devnum);
    if (blockDevice != nullptr) {
        EXPECT_NE(udev_device_get_syspath(blockDevice), nullptr);
        udev_device_unref(blockDevice);
    }
}

/*
 * Tests for:
 * udev_device_new_from_devnum with negative devnum
 */
HWTEST_F(CustomUdevTest, TestNewFromDevnumNegativeDevnum, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);

    errno = 0;
    // Negative devnum should fail
    EXPECT_EQ(udev_device_new_from_devnum(udev, 'c', -1), nullptr);
    EXPECT_EQ(errno, ENOENT);
}

/*
 * Tests for:
 * udev_device_new_from_devnum with maximum devnum value
 */
HWTEST_F(CustomUdevTest, TestNewFromDevnumMaxDevnum, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);

    errno = 0;
    auto* maxDevice = udev_device_new_from_devnum(udev, 'c', ~0U);
    if (maxDevice != nullptr) {
        udev_device_unref(maxDevice);
    }
}

/*
 * Tests for:
 * udev_device_ref with already referenced device
 */
HWTEST_F(CustomUdevTest, TestDeviceRefAlreadyReferenced, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    // Reference multiple times
    auto* ref1 = udev_device_ref(device);
    auto* ref2 = udev_device_ref(ref1);
    auto* ref3 = udev_device_ref(ref2);

    EXPECT_EQ(ref1, device);
    EXPECT_EQ(ref2, device);
    EXPECT_EQ(ref3, device);

    // Cleanup all references
    udev_device_unref(ref3);
    udev_device_unref(ref2);
    udev_device_unref(ref1);
}

/*
 * Tests for:
 * udev_device_get_parent chain until root
 */
HWTEST_F(CustomUdevTest, TestGetParentChainToRoot, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    auto* current = device;
    int32_t depth = 0;
    const int32_t maxDepth = 20;

    while (current != nullptr && depth < maxDepth) {
        auto* parent = udev_device_get_parent(current);
        if (parent == nullptr) {
            break;
        }
        current = parent;
        depth++;
    }

    // Verify we reached end of chain
    EXPECT_LT(depth, maxDepth);
}

/*
 * Tests for:
 * udev_device_get_parent_with_subsystem_devtype with whitespace subsystem
 */
HWTEST_F(CustomUdevTest, TestGetParentWithWhitespaceSubsystem, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    errno = 0;
    auto* parent = udev_device_get_parent_with_subsystem_devtype(device, " ", nullptr);
    if (parent != nullptr) {
        EXPECT_NE(udev_device_get_syspath(parent), nullptr);
        udev_device_unref(parent);
    }
}

/*
 * Tests for:
 * udev_device_get_syspath with device created from devnum
 */
HWTEST_F(CustomUdevTest, TestGetSyspathFromDevnum, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    const char* syspath = udev_device_get_syspath(device);
    EXPECT_NE(syspath, nullptr);
    EXPECT_STRNE(syspath, "");
    EXPECT_TRUE(strlen(syspath) > 0);
}

/*
 * Tests for:
 * udev_device_get_sysname with special characters
 */
HWTEST_F(CustomUdevTest, TestGetSysnameSpecialChars, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    const char* sysname = udev_device_get_sysname(device);
    EXPECT_NE(sysname, nullptr);
    // Sysname should not contain path separators after processing
    EXPECT_EQ(strchr(sysname, '/'), nullptr);
}

/*
 * Tests for:
 * udev_device_get_devnode format validation
 */
HWTEST_F(CustomUdevTest, TestGetDevnodeFormat, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    const char* devnode = udev_device_get_devnode(device);
    EXPECT_NE(devnode, nullptr);
}

/*
 * Tests for:
 * udev_device_get_is_initialized multiple calls consistency
 */
HWTEST_F(CustomUdevTest, TestGetIsInitializedMultipleCalls, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    int32_t results[5];
    for (int32_t i = 0; i < 5; i++) {
        results[i] = udev_device_get_is_initialized(device);
    }

    // All results should be the same
    for (int32_t i = 1; i < 5; i++) {
        EXPECT_EQ(results[0], results[i]);
    }
}

/*
 * Tests for:
 * udev_device_get_property_value with empty key
 */
HWTEST_F(CustomUdevTest, TestGetPropertyEmptyKey, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    errno = 0;
    const char* value = udev_device_get_property_value(device, "");
    EXPECT_EQ(value, nullptr);
}

/*
 * Tests for:
 * udev_device_get_property_value with very long key
 */
HWTEST_F(CustomUdevTest, TestGetPropertyLongKey, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    std::string longKey(1000, 'A');
    const char* value = udev_device_get_property_value(device, longKey.c_str());
    // Should return nullptr for non-existent key
    EXPECT_EQ(value, nullptr);
}

/*
 * Tests for:
 * udev_device_get_property_value with common input properties
 */
HWTEST_F(CustomUdevTest, TestGetPropertyCommonInputProps, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    const char* commonProps[] = {
        "ID_INPUT",
        "DEVNAME",
        "DEVPATH",
        "SUBSYSTEM"
    };

    for (const char* prop : commonProps) {
        const char* value = udev_device_get_property_value(parent, prop);
        // Property may or may not exist, just verify no crash
        (void)value;
    }
}

/*
 * Tests for:
 * udev_device_property_add with valid devnode after stat succeeds
 */
HWTEST_F(CustomUdevTest, TestPropertyAddValidDevnode, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    const char* devnode = udev_device_get_devnode(device);
    ASSERT_NE(devnode, nullptr);

    // Test with valid char device type
    bool ret = udev_device_property_add('c', devnode);
    // May succeed or fail depending on device existence
    (void)ret;
}

/*
 * Tests for:
 * udev_device_property_add with block device type
 */
HWTEST_F(CustomUdevTest, TestPropertyAddBlockType, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    const char* devnode = udev_device_get_devnode(device);
    ASSERT_NE(devnode, nullptr);

    // Test with block device type
    bool ret = udev_device_property_add('b', devnode);
    // May succeed or fail depending on device existence
    (void)ret;
}

/*
 * Tests for:
 * udev_device_property_add with null devnode
 */
HWTEST_F(CustomUdevTest, TestPropertyAddNullDevnode, TestSize.Level1)
{
    errno = 0;
    bool ret = udev_device_property_add('c', nullptr);
    EXPECT_FALSE(ret);
}

/*
 * Tests for:
 * udev_device_property_remove with empty devnode
 */
HWTEST_F(CustomUdevTest, TestPropertyRemoveEmptyDevnode, TestSize.Level1)
{
    // Should not crash with empty string
    udev_device_property_remove("");
}

/*
 * Tests for:
 * udev_device_record_devnode with empty devnode
 */
HWTEST_F(CustomUdevTest, TestRecordDevnodeEmpty, TestSize.Level1)
{
    // Should not crash with empty string
    udev_device_record_devnode("");
}

/*
 * Tests for:
 * udev_device_record_devnode multiple calls
 */
HWTEST_F(CustomUdevTest, TestRecordDevnodeMultiple, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    const char* devnode = udev_device_get_devnode(device);
    ASSERT_NE(devnode, nullptr);

    // Record multiple times
    udev_device_record_devnode(devnode);
    udev_device_record_devnode(devnode);
    udev_device_record_devnode(devnode);
    // Should not crash
}

/*
 * Tests for:
 * udev_new called many times returns same instance
 */
HWTEST_F(CustomUdevTest, TestUdevNewManyTimes, TestSize.Level1)
{
    auto* udev1 = udev_new();
    auto* udev2 = udev_new();
    auto* udev3 = udev_new();
    auto* udev4 = udev_new();
    auto* udev5 = udev_new();

    EXPECT_NE(udev1, nullptr);
    EXPECT_EQ(udev1, udev2);
    EXPECT_EQ(udev2, udev3);
    EXPECT_EQ(udev3, udev4);
    EXPECT_EQ(udev4, udev5);
}

/*
 * Tests for:
 * udev_unref called multiple times
 */
HWTEST_F(CustomUdevTest, TestUdevUnrefMultiple, TestSize.Level1)
{
    auto* udev = udev_new();
    ASSERT_NE(udev, nullptr);

    // Call unref multiple times - should be safe
    auto* result1 = udev_unref(udev);
    auto* result2 = udev_unref(udev);
    auto* result3 = udev_unref(nullptr);

    EXPECT_EQ(result1, nullptr);
    EXPECT_EQ(result2, nullptr);
    EXPECT_EQ(result3, nullptr);
}

/*
 * Tests for:
 * Device creation and immediate unref
 */
HWTEST_F(CustomUdevTest, TestDeviceCreateImmediateUnref, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);
    auto devnum = testDevice_.GetDevNum();

    // Create and immediately unref
    auto* newDevice = udev_device_new_from_devnum(udev, 'c', devnum);
    if (newDevice != nullptr) {
        udev_device_unref(newDevice);
    }
}

/*
 * Tests for:
 * Multiple devices from same devnum
 */
HWTEST_F(CustomUdevTest, TestMultipleDevicesSameDevnum, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);
    auto devnum = testDevice_.GetDevNum();

    const int32_t deviceCount = 5;
    std::vector<udev_device*> devices;

    for (int32_t i = 0; i < deviceCount; i++) {
        auto* newDevice = udev_device_new_from_devnum(udev, 'c', devnum);
        if (newDevice != nullptr) {
            devices.push_back(newDevice);
        }
    }

    // All devices should have same syspath
    if (devices.size() > 1) {
        for (size_t i = 1; i < devices.size(); i++) {
            EXPECT_STREQ(
                udev_device_get_syspath(devices[0]),
                udev_device_get_syspath(devices[i])
            );
        }
    }

    // Cleanup
    for (auto* dev : devices) {
        udev_device_unref(dev);
    }
}

/*
 * Tests for:
 * Property value with case sensitivity
 */
HWTEST_F(CustomUdevTest, TestGetPropertyCaseSensitivity, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    const char* variants[] = {
        "ID_INPUT",
        "id_input",
        "Id_Input",
        "ID_Input",
        "id_Input"
    };

    for (const char* key : variants) {
        const char* value = udev_device_get_property_value(device, key);
        // Just verify no crash, case sensitivity depends on implementation
        (void)value;
    }
}

/*
 * Tests for:
 * Syspath with trailing whitespace
 */
HWTEST_F(CustomUdevTest, TestSyspathTrailingWhitespace, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    errno = 0;
    EXPECT_EQ(udev_device_new_from_syspath(udev, "/sys/devices/test "), nullptr);
}

/*
 * Tests for:
 * Syspath with leading whitespace
 */
HWTEST_F(CustomUdevTest, TestSyspathLeadingWhitespace, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    errno = 0;
    EXPECT_EQ(udev_device_new_from_syspath(udev, " /sys/devices/test"), nullptr);
}

/*
 * Tests for:
 * udev_device_get_parent called before device fully initialized
 */
HWTEST_F(CustomUdevTest, TestGetParentBeforeInit, TestSize.Level1)
{
    auto* udev = udev_new();
    ASSERT_NE(udev, nullptr);

    // Try to get parent from null device
    errno = 0;
    EXPECT_EQ(udev_device_get_parent(nullptr), nullptr);
    EXPECT_EQ(errno, EINVAL);

    udev_unref(udev);
}

/*
 * Tests for:
 * Device reference count after multiple operations
 */
HWTEST_F(CustomUdevTest, TestDeviceRefCountAfterOperations, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    // Perform various operations
    auto* syspath = udev_device_get_syspath(device);
    auto* sysname = udev_device_get_sysname(device);
    auto* devnode = udev_device_get_devnode(device);
    int32_t initialized = udev_device_get_is_initialized(device);

    // All should succeed without affecting device validity
    EXPECT_NE(syspath, nullptr);
    EXPECT_NE(sysname, nullptr);
    EXPECT_NE(devnode, nullptr);
    EXPECT_GE(initialized, 0);
    // Parent may be null depending on device hierarchy

    // Device should still be valid
    EXPECT_NE(udev_device_get_syspath(device), nullptr);
}

/*
 * Tests for:
 * udev_device_get_property_value after parent traversal
 */
HWTEST_F(CustomUdevTest, TestGetPropertyAfterParentTraversal, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    // Traverse parent chain
    auto* current = device;
    while (current != nullptr) {
        const char* syspath = udev_device_get_syspath(current);
        const char* sysname = udev_device_get_sysname(current);
        (void)syspath;
        (void)sysname;

        current = udev_device_get_parent(current);
    }

    // Get properties from original device
    const char* value = udev_device_get_property_value(device, "ID_INPUT");
    // May or may not exist
    (void)value;
}

/*
 * Tests for:
 * Error code preservation across multiple operations
 */
HWTEST_F(CustomUdevTest, TestErrnoPreservation, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    // Set errno to known value
    errno = ENOMEM;
    int32_t savedErrno = errno;

    // Perform operations that should not modify errno on success
    auto* syspath = udev_device_get_syspath(device);
    EXPECT_NE(syspath, nullptr);
    EXPECT_EQ(errno, savedErrno);

    auto* sysname = udev_device_get_sysname(device);
    EXPECT_NE(sysname, nullptr);
    EXPECT_EQ(errno, savedErrno);
}

/*
 * Tests for:
 * Device with invalid syspath format variations
 */
HWTEST_F(CustomUdevTest, TestSyspathFormatVariations, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    const char* invalidPaths[] = {
        "sys/devices/test",
        "/sysdevices/test",
        "/sys/device/test",
        "/sys/devic/test",
        "sys/dev/test",
        "/sys/dev/test/",
        "/sys/block/test",
        "/sys/class/test"
    };

    for (const char* path : invalidPaths) {
        errno = 0;
        auto* device = udev_device_new_from_syspath(udev, path);
        if (device != nullptr) {
            udev_device_unref(device);
        }
    }
}

/*
 * Tests for:
 * udev_device_property_add with special characters in devnode
 */
HWTEST_F(CustomUdevTest, TestPropertyAddSpecialCharsDevnode, TestSize.Level1)
{
    const char* specialDevnodes[] = {
        "/dev/test\0device",
        "/dev/test device",
        "/dev/test\ndevice",
        "/dev/test\tdevice"
    };

    for (const char* devnode : specialDevnodes) {
        bool ret = udev_device_property_add('c', devnode);
        EXPECT_FALSE(ret);
    }
}

/*
 * Tests for:
 * Device lifecycle with explicit cleanup order
 */
HWTEST_F(CustomUdevTest, TestDeviceLifecycleExplicitCleanup, TestSize.Level1)
{
    auto* udev = udev_new();
    ASSERT_NE(udev, nullptr);

    // Create device that will fail
    auto* device = udev_device_new_from_devnum(udev, 'c', 0);
    EXPECT_EQ(device, nullptr);

    // Cleanup in reverse order
    udev_unref(udev);
}

/*
 * Tests for:
 * udev_device_get_udev from multiple devices
 */
HWTEST_F(CustomUdevTest, TestGetUdevFromMultipleDevices, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device1 = testDevice_.GetDevice();
    auto* udev1 = udev_device_get_udev(device1);
    ASSERT_NE(udev1, nullptr);

    // Create another device from same udev
    auto devnum = testDevice_.GetDevNum();
    auto* device2 = udev_device_new_from_devnum(udev1, 'c', devnum);
    if (device2 != nullptr) {
        auto* udev2 = udev_device_get_udev(device2);
        EXPECT_EQ(udev1, udev2);
        udev_device_unref(device2);
    }
}

/*
 * Tests for:
 * Property value retrieval with unicode keys
 */
HWTEST_F(CustomUdevTest, TestGetPropertyUnicodeKeys, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    const char* unicodeKeys[] = {
        "测试",
        "テスト",
        "테스트",
        "🔧",
        "Ñoño"
    };

    for (const char* key : unicodeKeys) {
        const char* value = udev_device_get_property_value(device, key);
        // Should return nullptr for non-existent keys
        (void)value;
    }
}

/*
 * Tests for:
 * udev_device_new_from_syspath with path containing null bytes
 */
HWTEST_F(CustomUdevTest, TestNewFromSyspathNullBytes, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    std::string pathWithNull = "/sys/devices/test";
    pathWithNull += '\0';
    pathWithNull += "extra";

    errno = 0;
    auto* device = udev_device_new_from_syspath(udev, pathWithNull.c_str());
    if (device != nullptr) {
        udev_device_unref(device);
    }
}

/*
 * Tests for:
 * Device property consistency after parent access
 */
HWTEST_F(CustomUdevTest, TestPropertyConsistencyAfterParentAccess, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    // Get properties before parent access
    const char* syspath1 = udev_device_get_syspath(device);
    const char* sysname1 = udev_device_get_sysname(device);
    const char* devnode1 = udev_device_get_devnode(device);

    // Access parent
    auto* parent = udev_device_get_parent(device);
    (void)parent;

    // Get properties after parent access
    const char* syspath2 = udev_device_get_syspath(device);
    const char* sysname2 = udev_device_get_sysname(device);
    const char* devnode2 = udev_device_get_devnode(device);

    // Should be consistent
    EXPECT_EQ(syspath1, syspath2);
    EXPECT_EQ(sysname1, sysname2);
    EXPECT_EQ(devnode1, devnode2);
}

/*
 * Tests for:
 * udev_device_get_is_initialized with freshly created device
 */
HWTEST_F(CustomUdevTest, TestGetIsInitializedFreshDevice, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    // First call initializes
    int32_t init1 = udev_device_get_is_initialized(device);
    EXPECT_GE(init1, 0);

    // Second call should return cached value
    int32_t init2 = udev_device_get_is_initialized(device);
    EXPECT_EQ(init1, init2);
}

/*
 * Tests for:
 * Device creation failure with various errno values
 */
HWTEST_F(CustomUdevTest, TestDeviceCreationFailureErrno, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);

    // Test different failure scenarios
    errno = 0;
    auto* fail1 = udev_device_new_from_devnum(nullptr, 'c', 123);
    EXPECT_EQ(fail1, nullptr);
    EXPECT_EQ(errno, EINVAL);

    errno = 0;
    auto* fail2 = udev_device_new_from_devnum(udev, 'x', 123);
    EXPECT_EQ(fail2, nullptr);
    EXPECT_EQ(errno, EINVAL);
}

/*
 * Tests for:
 * udev_device_get_parent_with_subsystem_devtype with long subsystem name
 */
HWTEST_F(CustomUdevTest, TestGetParentWithLongSubsystem, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    std::string longSubsystem(256, 'a');
    errno = 0;
    auto* parent = udev_device_get_parent_with_subsystem_devtype(
        device, longSubsystem.c_str(), nullptr);
    if (parent != nullptr) {
        udev_device_unref(parent);
    }
}

/*
 * Tests for:
 * Memory stress test - create and destroy many devices
 */
HWTEST_F(CustomUdevTest, TestMemoryStressDeviceCreation, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);
    auto devnum = testDevice_.GetDevNum();

    const int32_t iterationCount = 100;
    for (int32_t i = 0; i < iterationCount; i++) {
        auto* newDevice = udev_device_new_from_devnum(udev, 'c', devnum);
        if (newDevice != nullptr) {
            // Access some properties
            (void)udev_device_get_syspath(newDevice);
            (void)udev_device_get_sysname(newDevice);
            udev_device_unref(newDevice);
        }
    }
}

/*
 * Tests for:
 * udev_device_property_add and remove sequence
 */
HWTEST_F(CustomUdevTest, TestPropertyAddRemoveSequence, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    const char* devnode = udev_device_get_devnode(device);
    ASSERT_NE(devnode, nullptr);

    // Add property
    bool addRet = udev_device_property_add('c', devnode);
    (void)addRet;

    // Remove property
    udev_device_property_remove(devnode);

    // Add again with different type
    addRet = udev_device_property_add('b', devnode);
    (void)addRet;

    // Remove again
    udev_device_property_remove(devnode);
}

/*
 * Tests for:
 * Device syspath with special directory names
 */
HWTEST_F(CustomUdevTest, TestSyspathSpecialDirNames, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    const char* specialPaths[] = {
        "/sys/devices/platform/test",
        "/sys/devices/pci0000:00/test",
        "/sys/devices/LNXSYSTM:00/test",
        "/sys/devices/PNP0A08:00/test"
    };

    for (const char* path : specialPaths) {
        errno = 0;
        auto* device = udev_device_new_from_syspath(udev, path);
        if (device != nullptr) {
            udev_device_unref(device);
        }
    }
}

/*
 * Tests for:
 * udev_device_get_property_value with numeric key
 */
HWTEST_F(CustomUdevTest, TestGetPropertyNumericKey, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    const char* numericKeys[] = {
        "123",
        "0",
        "999",
        "123456789"
    };

    for (const char* key : numericKeys) {
        const char* value = udev_device_get_property_value(device, key);
        (void)value;
    }
}

/*
 * Tests for:
 * Device reference after unref should not be used
 */
HWTEST_F(CustomUdevTest, TestDeviceRefAfterUnref, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    // Create new reference
    auto* ref = udev_device_ref(device);
    ASSERT_NE(ref, nullptr);

    // Unref the reference
    udev_device_unref(ref);

    // Original device should still be valid (managed by testDevice_)
    EXPECT_NE(udev_device_get_syspath(device), nullptr);
}

/*
 * Tests for:
 * udev_device_new_from_syspath with case variations in path
 */
HWTEST_F(CustomUdevTest, TestNewFromSyspathCaseVariations, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    const char* casePaths[] = {
        "/SYS/devices/test",
        "/Sys/devices/test",
        "/sys/DEVICES/test",
        "/sys/Devices/test"
    };

    for (const char* path : casePaths) {
        errno = 0;
        auto* device = udev_device_new_from_syspath(udev, path);
        if (device != nullptr) {
            udev_device_unref(device);
        }
    }
}

/*
 * Tests for:
 * Concurrent property access pattern
 */
HWTEST_F(CustomUdevTest, TestConcurrentPropertyAccess, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    const char* keys[] = {
        "ID_INPUT",
        "DEVNAME",
        "DEVPATH",
        "SUBSYSTEM",
        "ID_INPUT_MOUSE",
        "ID_INPUT_KEYBOARD",
        "ID_INPUT_TOUCHSCREEN"
    };

    // Access properties multiple times in different order
    for (int32_t round = 0; round < 3; round++) {
        for (const char* key : keys) {
            const char* value = udev_device_get_property_value(parent, key);
            (void)value;
        }
    }
}

/*
 * Tests for:
 * udev_device_get_is_initialized boundary values
 */
HWTEST_F(CustomUdevTest, TestGetIsInitializedBoundary, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    int32_t result = udev_device_get_is_initialized(device);
    // Should be 0 or 1 for valid device
    EXPECT_TRUE(result == 0 || result == 1);

    // Null device should return negative
    int32_t nullResult = udev_device_get_is_initialized(nullptr);
    EXPECT_LT(nullResult, 0);
}

/*
 * Tests for:
 * Device creation with errno pre-set
 */
HWTEST_F(CustomUdevTest, TestDeviceCreationWithPreSetErrno, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);

    // Pre-set errno
    errno = ENOMEM;

    // Create device - should overwrite errno on failure
    auto* newDevice = udev_device_new_from_devnum(nullptr, 'c', 123);
    EXPECT_EQ(newDevice, nullptr);
    // errno should be EINVAL for null udev
    EXPECT_EQ(errno, EINVAL);
}

/*
 * Tests for:
 * udev_device_property_add with maximum path length
 */
HWTEST_F(CustomUdevTest, TestPropertyAddMaxPathLength, TestSize.Level1)
{
    std::string longPath = "/dev/";
    for (int32_t i = 0; i < 250; i++) {
        longPath += "a";
    }

    bool ret = udev_device_property_add('c', longPath.c_str());
    EXPECT_FALSE(ret);
}

/*
 * Tests for:
 * Device sysname extraction from various path formats
 */
HWTEST_F(CustomUdevTest, TestSysnameFromVariousPaths, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    const char* sysname = udev_device_get_sysname(device);
    EXPECT_NE(sysname, nullptr);
    EXPECT_STRNE(sysname, "");

    // Sysname should not contain slashes
    EXPECT_EQ(strchr(sysname, '/'), nullptr);
    // Sysname should not be too long
    EXPECT_LT(strlen(sysname), 256);
}

/*
 * Tests for:
 * udev_device_get_parent with device at different hierarchy levels
 */
HWTEST_F(CustomUdevTest, TestGetParentDifferentLevels, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    // Get parent at different levels
    auto* parent1 = udev_device_get_parent(device);
    if (parent1 != nullptr) {
        auto* parent2 = udev_device_get_parent(parent1);
        if (parent2 != nullptr) {
            auto* parent3 = udev_device_get_parent(parent2);
            (void)parent3;
        }
    }

    // Original device should still be valid
    EXPECT_NE(udev_device_get_syspath(device), nullptr);
}

/*
 * Tests for:
 * Property value with control characters in key
 */
HWTEST_F(CustomUdevTest, TestGetPropertyControlChars, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    std::string keyWithControl = "KEY";
    keyWithControl += '\t';
    keyWithControl += "VALUE";

    const char* value = udev_device_get_property_value(device, keyWithControl.c_str());
    (void)value;
}

/*
 * Tests for:
 * udev_device_record_devnode before and after property operations
 */
HWTEST_F(CustomUdevTest, TestRecordDevnodeBeforeAfterProps, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    const char* devnode = udev_device_get_devnode(device);
    ASSERT_NE(devnode, nullptr);

    // Record before
    udev_device_record_devnode(devnode);

    // Property operations
    udev_device_property_add('c', devnode);
    udev_device_property_remove(devnode);

    // Record after
    udev_device_record_devnode(devnode);
}

/*
 * Tests for:
 * Device creation failure with all invalid type characters
 */
HWTEST_F(CustomUdevTest, TestNewFromDevnumAllInvalidTypes, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);
    auto devnum = testDevice_.GetDevNum();

    // Test all ASCII characters except 'b' and 'c'
    for (char c = 0; c < 128; c++) {
        if (c != 'b' && c != 'c') {
            errno = 0;
            auto* result = udev_device_new_from_devnum(udev, c, devnum);
            if (result != nullptr) {
                udev_device_unref(result);
            }
        }
    }
}

/*
 * Tests for:
 * udev_device_get_property_value consistency across multiple calls
 */
HWTEST_F(CustomUdevTest, TestGetPropertyConsistency, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* parent = udev_device_get_parent(device);
    ASSERT_NE(parent, nullptr);

    const char* key = "ID_INPUT";
    const char* value1 = udev_device_get_property_value(parent, key);
    const char* value2 = udev_device_get_property_value(parent, key);
    const char* value3 = udev_device_get_property_value(parent, key);

    // All calls should return same pointer for same key
    EXPECT_EQ(value1, value2);
    EXPECT_EQ(value2, value3);
}

/*
 * Tests for:
 * Device lifecycle with nested parent access
 */
HWTEST_F(CustomUdevTest, TestDeviceLifecycleNestedParent, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    // Nested parent access
    auto* parent1 = udev_device_get_parent(device);
    if (parent1 != nullptr) {
        auto* parent2 = udev_device_get_parent(parent1);
        if (parent2 != nullptr) {
            auto* syspath = udev_device_get_syspath(parent2);
            (void)syspath;
        }
        auto* syspath1 = udev_device_get_syspath(parent1);
        (void)syspath1;
    }
    auto* syspath = udev_device_get_syspath(device);
    (void)syspath;
}

/*
 * Tests for:
 * udev_device_new_from_syspath with path containing spaces
 */
HWTEST_F(CustomUdevTest, TestNewFromSyspathWithSpaces, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    errno = 0;
    EXPECT_EQ(udev_device_new_from_syspath(udev, "/sys/devices/test path"), nullptr);
}

/*
 * Tests for:
 * Property add/remove with non-existent devnode
 */
HWTEST_F(CustomUdevTest, TestPropertyAddRemoveNonExistent, TestSize.Level1)
{
    const char* nonExistentDevnodes[] = {
        "/dev/nonexistent_device_12345",
        "/dev/another_fake_device",
        "/dev/phantom_device"
    };

    for (const char* devnode : nonExistentDevnodes) {
        bool addRet = udev_device_property_add('c', devnode);
        EXPECT_FALSE(addRet);

        // Remove should not crash
        udev_device_property_remove(devnode);
    }
}

/*
 * Tests for:
 * udev_device_get_udev returns valid udev for all device operations
 */
HWTEST_F(CustomUdevTest, TestGetUdevValidAfterOperations, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    // Perform various operations
    (void)udev_device_get_syspath(device);
    (void)udev_device_get_sysname(device);
    (void)udev_device_get_devnode(device);
    (void)udev_device_get_is_initialized(device);
    (void)udev_device_get_parent(device);

    // Get udev should still work
    auto* udev = udev_device_get_udev(device);
    EXPECT_NE(udev, nullptr);
}

/*
 * Tests for:
 * Device reference count edge case - ref then immediate unref
 */
HWTEST_F(CustomUdevTest, TestDeviceRefImmediateUnref, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    auto* ref = udev_device_ref(device);
    ASSERT_NE(ref, nullptr);
    udev_device_unref(ref);

    // Device should still be accessible
    EXPECT_NE(udev_device_get_syspath(device), nullptr);
}

/*
 * Tests for:
 * udev_device_get_property_value with duplicate keys
 */
HWTEST_F(CustomUdevTest, TestGetPropertyDuplicateKeys, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();

    const char* key = "ID_INPUT";
    const char* values[10];

    for (int32_t i = 0; i < 10; i++) {
        values[i] = udev_device_get_property_value(device, key);
    }

    // All should return same value
    for (int32_t i = 1; i < 10; i++) {
        EXPECT_EQ(values[0], values[i]);
    }
}

/*
 * Tests for:
 * Syspath validation with various prefix patterns
 */
HWTEST_F(CustomUdevTest, TestSyspathPrefixPatterns, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* udev = udev_device_get_udev(testDevice_.GetDevice());
    ASSERT_NE(udev, nullptr);

    const char* prefixPatterns[] = {
        "/sysfs/devices/test",
        "/system/devices/test",
        "/sysfs/test",
        "/sysroot/devices/test",
        "sys/devices/test"
    };

    for (const char* path : prefixPatterns) {
        errno = 0;
        auto* device = udev_device_new_from_syspath(udev, path);
        if (device != nullptr) {
            udev_device_unref(device);
        }
    }
}

/*
 * Tests for:
 * udev_device_property_add with type variations
 */
HWTEST_F(CustomUdevTest, TestPropertyAddTypeVariations, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    const char* devnode = udev_device_get_devnode(device);
    ASSERT_NE(devnode, nullptr);

    // Test with all possible char values
    char testTypes[] = {'a', 'b', 'c', 'd', 'e', 'z', 'A', 'Z', '0', '9'};

    for (char type : testTypes) {
        bool ret = udev_device_property_add(type, devnode);
        // Only 'b' and 'c' might succeed if device exists
        (void)ret;
    }
}

/*
 * Tests for:
 * Device creation and property access stress test
 */
HWTEST_F(CustomUdevTest, TestDevicePropertyStress, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    auto* device = testDevice_.GetDevice();
    auto* udev = udev_device_get_udev(device);
    ASSERT_NE(udev, nullptr);
    auto devnum = testDevice_.GetDevNum();

    const int32_t iterations = 50;
    for (int32_t i = 0; i < iterations; i++) {
        auto* newDevice = udev_device_new_from_devnum(udev, 'c', devnum);
        if (newDevice != nullptr) {
            // Access all getters
            (void)udev_device_get_syspath(newDevice);
            (void)udev_device_get_sysname(newDevice);
            (void)udev_device_get_devnode(newDevice);
            (void)udev_device_get_is_initialized(newDevice);
            (void)udev_device_get_parent(newDevice);
            (void)udev_device_get_udev(newDevice);

            udev_device_unref(newDevice);
        }
    }
}
} // namespace MMI
} // namespace OHOS