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

#include "hotplug_detector.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <system_error>

#include <dirent.h>
#include <fcntl.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <linux/uinput.h>
#include <poll.h>
#include <sys/stat.h>

using ::testing::StartsWith;
using ::testing::ext::TestSize;

constexpr auto DEV_INPUT_PATH = "/dev/input/";

auto SystemError()
{
    return std::error_code{ errno, std::system_category() };
}

class HotplugTest : public ::testing::Test {
public:
};

class FakeInputDevice {
public:
    void Create();
    void Destroy();

private:
    int fd_ = -1;
};

void FakeInputDevice::Create()
{
    fd_ = open("/dev/uinput", O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    auto err = SystemError();
    ASSERT_GE(fd_, 0) << "Failed to create uinput device. Error: " << err.message() <<
        (err == std::errc::permission_denied ? ". Run test as ROOT!" : "") << std::endl;
    int res = ioctl(fd_, UI_SET_EVBIT, EV_KEY);
    ASSERT_GE(res, 0) << "Operation UI_SET_EVBIT failed. Error: " << SystemError().message() << std::endl;
    res = ioctl(fd_, UI_SET_KEYBIT, KEY_SPACE);
    ASSERT_GE(res, 0) << "Operation UI_SET_KEYBIT failed. Error: " << SystemError().message() << std::endl;

    uinput_setup usetup{};
    usetup.id.bustype = BUS_USB;
    usetup.id.vendor = 0x1234;  /* sample vendor */
    usetup.id.product = 0x5678; /* sample product */
    std::string dev("Example device");
    std::copy(dev.begin(), dev.end(), usetup.name);
    res = ioctl(fd_, UI_DEV_SETUP, &usetup);
    ASSERT_GE(res, 0) << "Operation UI_DEV_SETUP failed. Error: " << SystemError().message() << std::endl;
    res = ioctl(fd_, UI_DEV_CREATE);
    ASSERT_GE(res, 0) << "Operation UI_DEV_CREATE failed. Error: " << SystemError().message() << std::endl;
}

void FakeInputDevice::Destroy()
{
    auto res = ioctl(fd_, UI_DEV_DESTROY);
    ASSERT_GE(res, 0) << "Operation UI_DEV_DESTROY failed. Error: " << SystemError().message() << std::endl;
    close(fd_);
    fd_ = -1;
}

bool Exists(const std::string &path)
{
    std::ifstream file{ path };
    return file.good();
}

static void PollEvents(const OHOS::MMI::HotplugDetector &detector)
{
    constexpr int timeout = 10; // milliseconds
    struct pollfd buf = { detector.GetFd(), POLLIN, 0 };
    while (poll(&buf, 1, timeout) > 0) {
        detector.OnEvent();
    }
}

HWTEST_F(HotplugTest, TestRealInputEvents, TestSize.Level1)
{
    bool addCalled = false;
    std::string addPath;
    bool removeCalled = false;
    std::string removePath;

    auto add = [&addCalled, &addPath](std::string path) {
        addCalled = true;
        addPath = std::move(path);
    };
    auto remove = [&removeCalled, &removePath](std::string path) {
        removeCalled = true;
        removePath = std::move(path);
    };
    OHOS::MMI::HotplugDetector detector;
    FakeInputDevice fake;

    EXPECT_TRUE(Exists(DEV_INPUT_PATH));
    EXPECT_TRUE(detector.Init(add, remove));
    ASSERT_TRUE(addCalled);
    EXPECT_THAT(addPath, StartsWith(DEV_INPUT_PATH));
    EXPECT_FALSE(removeCalled);
    auto fd = detector.GetFd();
    ASSERT_GE(fd, 0);
    addCalled = false;
    removeCalled = false;
    addPath.clear();

    PollEvents(detector);
    EXPECT_FALSE(addCalled);
    EXPECT_FALSE(removeCalled);

    ASSERT_NO_FATAL_FAILURE(fake.Create());
    PollEvents(detector);
    EXPECT_TRUE(addCalled);
    EXPECT_FALSE(removeCalled);
    EXPECT_THAT(addPath, StartsWith(DEV_INPUT_PATH));
    EXPECT_TRUE(Exists(addPath));
    addCalled = false;
    removeCalled = false;

    ASSERT_NO_FATAL_FAILURE(fake.Destroy());
    PollEvents(detector);
    EXPECT_FALSE(addCalled);
    EXPECT_TRUE(removeCalled);
    EXPECT_EQ(removePath, addPath);
    addCalled = false;
    removeCalled = false;

    PollEvents(detector);
    EXPECT_FALSE(addCalled);
    EXPECT_FALSE(removeCalled);
}

HWTEST_F(HotplugTest, TestSpecialCases, TestSize.Level1)
{
    OHOS::MMI::HotplugDetector detector;

    auto dummy = [](std::string path) {};

    EXPECT_NO_FATAL_FAILURE(detector.OnEvent());

    EXPECT_TRUE(detector.Init(dummy, dummy));
    auto fd = detector.GetFd();
    ASSERT_GE(fd, 0);

    ASSERT_GE(fcntl(fd, F_SETFL, O_NONBLOCK), 0);

    EXPECT_NO_FATAL_FAILURE(detector.OnEvent());

    detector.Stop();
    EXPECT_EQ(detector.GetFd(), -1);
}

HWTEST_F(HotplugTest, TestSsystemFail, TestSize.Level1)
{
    OHOS::MMI::HotplugDetector detector;
    auto dummy = [](std::string path) {};

    std::vector<DIR *> dirs;
    // Exhaust system resources
    while (true) {
        auto *dir = opendir(DEV_INPUT_PATH);
        if (dir == nullptr) {
            break;
        }
        dirs.push_back(dir);
    }

    // inotify should fail
    EXPECT_FALSE(detector.Init(dummy, dummy));

    // Free one fd
    closedir(dirs.back());
    dirs.pop_back();

    // Scan should fail
    EXPECT_FALSE(detector.Init(dummy, dummy));

    for (auto it = dirs.rbegin(); it != dirs.rend(); ++it) {
        closedir(*it);
    }
}

HWTEST_F(HotplugTest, TestInitFail, TestSize.Level1)
{
    OHOS::MMI::HotplugDetector detector;

    auto empty = [](std::string) {};

    EXPECT_FALSE(detector.Init(nullptr, nullptr));
    EXPECT_FALSE(detector.Init(empty, nullptr));
    EXPECT_FALSE(detector.Init(nullptr, empty));
}
