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

#ifndef TEST_DEVICE_H
#define TEST_DEVICE_H

#include <chrono>
#include <thread>

#include <libevdev-uinput.h>
#include <libevdev/libevdev.h>

class TestDevice {
public:
    static constexpr auto TEST_BUS = 0xBAD;
    static constexpr auto TEST_VENDOR = 0x1234;
    static constexpr auto TEST_PRODUCT = 0x5678;
    static constexpr auto TEST_VERSION = 0xAA;
    static constexpr auto TEST_NAME = "test device";

    TestDevice()
    {
        evdev_ = libevdev_new();
    }

    ~TestDevice()
    {
        if (uidev_ != nullptr) {
            Destroy();
        }
        libevdev_free(evdev_);
    }

    void DefaultSetup()
    {
        libevdev_set_name(evdev_, TEST_NAME);
        libevdev_set_id_bustype(evdev_, TEST_BUS);
        libevdev_set_id_vendor(evdev_, TEST_VENDOR);
        libevdev_set_id_product(evdev_, TEST_PRODUCT); // fake product id
        libevdev_set_id_version(evdev_, TEST_VERSION); // fake version id
        libevdev_enable_event_type(evdev_, EV_REL);
        libevdev_enable_event_code(evdev_, EV_REL, REL_X, nullptr);
        libevdev_enable_event_code(evdev_, EV_REL, REL_Y, nullptr);
        libevdev_enable_event_type(evdev_, EV_KEY);
        libevdev_enable_event_code(evdev_, EV_KEY, BTN_LEFT, nullptr);
        libevdev_enable_event_code(evdev_, EV_KEY, BTN_MIDDLE, nullptr);
        libevdev_enable_event_code(evdev_, EV_KEY, BTN_RIGHT, nullptr);
    }

    void AbsMouseSetup()
    {
        libevdev_set_name(evdev_, TEST_NAME);
        libevdev_enable_event_type(evdev_, EV_ABS);
        input_absinfo info{.maximum = 100};
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_X, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_Y, &info);
        libevdev_enable_event_type(evdev_, EV_KEY);
        libevdev_enable_event_code(evdev_, EV_KEY, BTN_LEFT, nullptr);
        libevdev_enable_event_code(evdev_, EV_KEY, BTN_MIDDLE, nullptr);
        libevdev_enable_event_code(evdev_, EV_KEY, BTN_RIGHT, nullptr);
        // Test special case with too many axis here too
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_MT_POSITION_X, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_MT_POSITION_Y, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_MT_SLOT, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_MT_SLOT - 1, &info);
    }

    void WheelSetup()
    {
        // Also test special names
        libevdev_set_name(evdev_, TEST_NAME);
        libevdev_enable_event_type(evdev_, EV_REL);
        libevdev_enable_event_code(evdev_, EV_REL, REL_WHEEL, nullptr);
    }

    void KeyboardSetup()
    {
        libevdev_set_name(evdev_, TEST_NAME);
        libevdev_enable_event_type(evdev_, EV_KEY);
        for (int32_t i = KEY_ESC; i < KEY_D; i++) {
            libevdev_enable_event_code(evdev_, EV_KEY, i, nullptr);
        }
    }

    void SwitchSetup()
    {
        libevdev_set_name(evdev_, TEST_NAME);
        libevdev_enable_event_type(evdev_, EV_SW);
        libevdev_enable_event_code(evdev_, EV_SW, 0, nullptr);
    }

    void AccelerometerSetup()
    {
        libevdev_set_name(evdev_, TEST_NAME);
        libevdev_enable_event_type(evdev_, EV_ABS);
        input_absinfo info{.maximum = 100};
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_X, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_Y, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_Z, &info);
        libevdev_enable_property(evdev_, INPUT_PROP_ACCELEROMETER);
    }

    void StickSetup()
    {
        libevdev_set_name(evdev_, TEST_NAME);
        libevdev_enable_property(evdev_, INPUT_PROP_POINTING_STICK);
    }

    void TouchpadSetup()
    {
        libevdev_set_name(evdev_, TEST_NAME);
        libevdev_enable_event_type(evdev_, EV_ABS);
        input_absinfo info{.maximum = 100};
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_X, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_Y, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_MT_POSITION_X, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_MT_POSITION_Y, &info);
        libevdev_enable_event_type(evdev_, EV_KEY);
        libevdev_enable_event_code(evdev_, EV_KEY, BTN_TOOL_FINGER, nullptr);
        libevdev_enable_event_code(evdev_, EV_KEY, BTN_TOUCH, nullptr);
    }

    void TouchscreenSetup()
    {
        libevdev_set_name(evdev_, TEST_NAME);
        libevdev_enable_event_type(evdev_, EV_ABS);
        input_absinfo info{.maximum = 100};
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_X, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_Y, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_MT_POSITION_X, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_MT_POSITION_Y, &info);
        libevdev_enable_event_type(evdev_, EV_KEY);
        libevdev_enable_event_code(evdev_, EV_KEY, BTN_TOUCH, nullptr);
        libevdev_enable_property(evdev_, INPUT_PROP_DIRECT);
    }

    void JoystickSetup()
    {
        libevdev_set_name(evdev_, TEST_NAME);
        libevdev_enable_event_type(evdev_, EV_KEY);
        libevdev_enable_event_code(evdev_, EV_KEY, BTN_JOYSTICK, nullptr);
    }

    void JoystickSetup1()
    {
        libevdev_set_name(evdev_, TEST_NAME);
        libevdev_enable_event_type(evdev_, EV_ABS);
        input_absinfo info{.maximum = 100};
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_X, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_Y, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_RX, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_RY, &info);
    }

    void TabletSetup()
    {
        libevdev_set_name(evdev_, TEST_NAME);
        libevdev_enable_event_type(evdev_, EV_ABS);
        input_absinfo info{.maximum = 100, .resolution = 10};
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_X, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_Y, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_MT_POSITION_X, &info);
        libevdev_enable_event_code(evdev_, EV_ABS, ABS_MT_POSITION_Y, &info);
        libevdev_enable_event_type(evdev_, EV_KEY);
        libevdev_enable_event_code(evdev_, EV_KEY, BTN_STYLUS, nullptr);
    }

    void Destroy()
    {
        libevdev_uinput_destroy(uidev_);
        uidev_ = nullptr;
    }

    auto GetDevNode()
    {
        return libevdev_uinput_get_devnode(uidev_);
    }

    auto GetSysPath()
    {
        return libevdev_uinput_get_syspath(uidev_);
    }

    auto GetDevNum() const
    {
        return devnum_;
    }

    bool SetDevnum()
    {
        const auto* fname = libevdev_uinput_get_devnode(uidev_);
        if (fname == nullptr) {
            return false;
        }
        struct stat st;
        int t = stat(fname, &st);
        if (t < 0) {
            return false;
        }
        devnum_ = st.st_rdev;
        return true;
    }

    void Init(bool def = true)
    {
        using namespace std::chrono_literals;
        constexpr auto initDelay = 50ms;
        ASSERT_NE(evdev_, nullptr);
        if (def) {
            DefaultSetup();
        }
        auto res = libevdev_uinput_create_from_device(evdev_, LIBEVDEV_UINPUT_OPEN_MANAGED, &uidev_);
        auto err = std::error_code{errno, std::system_category()};
        ASSERT_EQ(res, 0) << "Failed to create uinput device. Error: " << err.message()
                          << (err == std::errc::permission_denied ? ". Run test as ROOT!" : "") << std::endl;
        ASSERT_NE(uidev_, nullptr);

        std::this_thread::sleep_for(initDelay);
        ASSERT_TRUE(SetDevnum());
    }

private:
    struct libevdev* evdev_ {};
    struct libevdev_uinput* uidev_ {};
    dev_t devnum_ {};
};
#endif // TEST_DEVICE_H
