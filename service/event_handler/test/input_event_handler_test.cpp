/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "linux/input.h"
#include "linux/uinput.h"
#define protected public
#include "input_event_handler.h"
#undef protected
#include "libinput-seat-export.h"
#include "event_dump.h"
#include "mmi_server.h"
#include "util.h"
#include "log.h"

namespace {
    using namespace testing::ext;
    using namespace OHOS::MMI;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputEventHandlerTest" };

static void LibinputDrainEvents(libinput* li)
{
    libinput_event* event;
    libinput_dispatch(li);
    while ((event = libinput_get_event(li))) {
        libinput_event_destroy(event);
        libinput_dispatch(li);
    }
}

const static libinput_interface LIBINPUT_INTERFACE = {
    .open_restricted = [](const char* path, int32_t flags, void* user_data)->int32_t {
        CHKR(path, OHOS::ERROR_NULL_POINTER, -errno);
        int32_t fd = open(path, flags);
        MMI_LOGD("libinput .open_restricted path:%{public}s,fd:%{public}d", path, fd);
        return fd < 0 ? -errno : fd;
    },
    .close_restricted = [](int32_t fd, void* user_data)
    {
        MMI_LOGI("libinput .close_restricted fd:%d", fd);
        close(fd);
    },
};

const static struct {
    const std::string unitName;
    const std::string argsName;
    const std::string jsonName;
} NAME_MAP[] = {
    {"Test_OnEvent", "keyboard", "inject_event_keyboard.json"},
    {"Test_OnEventKeyboard", "keyboard", "inject_event_keyboard.json"},
    {"Test_OnEventPointer_LeftButton", "mouse", "inject_event_mouse_left_button.json"},
    {"Test_OnEventPointer_Motion", "mouse", "inject_event_mouse_motion.json"},
    {"Test_OnEventPointer_Axis", "mouse", "inject_event_mouse_axis.json"},
    {"Test_OnEventTouch", "touchscreen", "inject_event_touch_screen.json"},
    {"Test_OnEventTabletTool", "touchpad", "inject_event_pad_pen.json"},
    {"Test_OnEventTabletPadKey", "touchpad", "inject_event_pad_key.json"},
    {"Test_OnEventTabletPadRing", "touchpad", "inject_event_pad_ring.json"},
    {"Test_OnEventGesture", "touchpad", "inject_event_pad_finger.json"},
    {"Test_OnEventJoyStickKey", "joystick", "inject_event_joystick_key.json"},
    {"Test_OnEventJoyStickAxis", "joystick", "inject_event_joystick_axis.json"},
};

class InputEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp()
    {
        currentUnitName_ = testing::UnitTest::GetInstance()->current_test_info()->name();
        EXPECT_FALSE(currentUnitName_.empty());
        for (auto& temp : NAME_MAP) {
            if (currentUnitName_ == temp.unitName) {
                currentJsonName_ = temp.jsonName;
                currentArgsName_ = temp.argsName;
                break;
            }
        }
        EXPECT_FALSE(currentUnitName_.empty());
        EXPECT_FALSE(currentJsonName_.empty());
        EXPECT_FALSE(currentArgsName_.empty());
        currentJsonName_ = "/data/events_injection/" + currentJsonName_;
        EXPECT_TRUE(eventHandler_.Init(server_));
        udev_ = udev_new();
        EXPECT_TRUE(udev_);
        input_ = libinput_udev_create_context(&LIBINPUT_INTERFACE, nullptr, udev_);
        EXPECT_TRUE(input_);
        EXPECT_FALSE(libinput_udev_assign_seat(input_, "seat0"));
        virtualDeviceManagerPid_ = fork();
        EXPECT_TRUE(virtualDeviceManagerPid_ >= 0);
        if (virtualDeviceManagerPid_ == 0) {
            execl(DEF_MMI_VIRTUAL_DEVICE_MANAGER, "hosmmi-virtual-device-manager", "start",
                  currentArgsName_.c_str(), nullptr);
        } else {
            usleep(delayTime);
            LibinputDrainEvents(input_);
            eventinjectionPid_ = fork();
            if (eventinjectionPid_ == 0) {
                execl(DEF_MMI_EVENT_INJECTION, "hosmmi-event-injection", "json", currentJsonName_.c_str(), nullptr);
            } else {
                waitpid(eventinjectionPid_, nullptr, 0);
                EXPECT_EQ(libinput_dispatch(input_), 0);
            }
        }
    }
    void TearDown()
    {
        kill(virtualDeviceManagerPid_, SIGKILL);
        waitpid(virtualDeviceManagerPid_, nullptr, 0);
        libinput_event_destroy(event_);
        libinput_unref(input_);
        udev_unref(udev_);
        currentUnitName_.clear();
        currentJsonName_.clear();
        currentArgsName_.clear();
    }
protected:
    MMIServer server_;
    InputEventHandler eventHandler_;
    libinput_event* event_ = nullptr;
    udev* udev_ = nullptr;
    libinput* input_ = nullptr;
    pid_t virtualDeviceManagerPid_ = 0;
    pid_t eventinjectionPid_ = 0;
    std::string currentUnitName_ = "";
    std::string currentJsonName_ = "";
    std::string currentArgsName_ = "";
    const uint64_t delayTime = 1000000;
};

HWTEST_F(InputEventHandlerTest, Test_OnEvent, TestSize.Level1)
{
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    multimodal_libinput_event mmi_event = {event_, nullptr};
    eventHandler_.OnEvent((void*)&mmi_event);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    eventHandler_.OnEvent((void*)&mmi_event);
}

HWTEST_F(InputEventHandlerTest, Test_OnEventKeyboard, TestSize.Level1)
{
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    multimodal_libinput_event mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventKeyboard(mmi_event), OHOS::KEY_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventKeyboard(mmi_event), OHOS::KEY_EVENT_DISP_FAIL);
}

HWTEST_F(InputEventHandlerTest, Test_OnEventPointer_LeftButton, TestSize.Level1)
{
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    multimodal_libinput_event mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventPointer(mmi_event), OHOS::POINT_EVENT_DISP_FAIL);
}

HWTEST_F(InputEventHandlerTest, Test_OnEventPointer_Motion, TestSize.Level1)
{
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    multimodal_libinput_event mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventPointer(mmi_event), OHOS::POINT_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventPointer(mmi_event), OHOS::POINT_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventPointer(mmi_event), OHOS::POINT_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventPointer(mmi_event), OHOS::POINT_EVENT_DISP_FAIL);
}

HWTEST_F(InputEventHandlerTest, Test_OnEventPointer_Axis, TestSize.Level1)
{
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    multimodal_libinput_event mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventPointer(mmi_event), OHOS::POINT_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventPointer(mmi_event), OHOS::POINT_EVENT_DISP_FAIL);
}

HWTEST_F(InputEventHandlerTest, Test_OnEventTouch, TestSize.Level1)
{
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    multimodal_libinput_event mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTouch(mmi_event), OHOS::TOUCH_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTouch(mmi_event), RET_OK);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTouch(mmi_event), OHOS::TOUCH_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTouch(mmi_event), RET_OK);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTouch(mmi_event), OHOS::TOUCH_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTouch(mmi_event), RET_OK);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTouch(mmi_event), OHOS::TOUCH_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTouch(mmi_event), RET_OK);
}

HWTEST_F(InputEventHandlerTest, Test_OnEventTabletTool, TestSize.Level1)
{
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    multimodal_libinput_event mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTabletTool(mmi_event), OHOS::TABLETTOOL_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTabletTool(mmi_event), OHOS::TABLETTOOL_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTabletTool(mmi_event), OHOS::TABLETTOOL_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTabletTool(mmi_event), OHOS::TABLETTOOL_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTabletTool(mmi_event), OHOS::TABLETTOOL_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTabletTool(mmi_event), OHOS::TABLETTOOL_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTabletTool(mmi_event), OHOS::TABLETTOOL_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTabletTool(mmi_event), OHOS::TABLETTOOL_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTabletTool(mmi_event), OHOS::TABLETTOOL_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTabletTool(mmi_event), OHOS::TABLETTOOL_EVENT_DISP_FAIL);
}

HWTEST_F(InputEventHandlerTest, Test_OnEventTabletPadKey, TestSize.Level1)
{
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    multimodal_libinput_event mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTabletPadKey(mmi_event), OHOS::TABLETPAD_KEY_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTabletPadKey(mmi_event), OHOS::TABLETPAD_KEY_EVENT_DISP_FAIL);
}

HWTEST_F(InputEventHandlerTest, Test_OnEventTabletPadRing, TestSize.Level1)
{
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    multimodal_libinput_event mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTabletPad(mmi_event), OHOS::TABLETPAD_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventTabletPad(mmi_event), OHOS::TABLETPAD_EVENT_DISP_FAIL);
}

HWTEST_F(InputEventHandlerTest, Test_OnEventGesture, TestSize.Level1)
{
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    multimodal_libinput_event mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventGesture(mmi_event), OHOS::GESTURE_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventGesture(mmi_event), OHOS::GESTURE_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventGesture(mmi_event), OHOS::GESTURE_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventGesture(mmi_event), OHOS::GESTURE_EVENT_DISP_FAIL);
}

HWTEST_F(InputEventHandlerTest, Test_OnEventJoyStickKey, TestSize.Level1)
{
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    multimodal_libinput_event mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventPointer(mmi_event), OHOS::JOYSTICK_EVENT_DISP_FAIL);
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventPointer(mmi_event), OHOS::JOYSTICK_EVENT_DISP_FAIL);
}

HWTEST_F(InputEventHandlerTest, Test_OnEventJoyStickAxis, TestSize.Level1)
{
    event_ = libinput_get_event(input_);
    EXPECT_TRUE(event_);
    multimodal_libinput_event mmi_event = {event_, nullptr};
    EXPECT_EQ(eventHandler_.OnEventPointer(mmi_event), OHOS::JOYSTICK_EVENT_DISP_FAIL);
}
} // namespace
