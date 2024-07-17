/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <fcntl.h>
#include <gtest/gtest.h>

#include "libinput_adapter.h"
#include "mmi_log.h"
#include "unique_fd.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "LibinputAdapterTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
constexpr int32_t WAIT_TIME_FOR_INPUT { 10 };
constexpr int32_t MAX_RETRY_COUNT { 5 };

constexpr static libinput_interface LIBINPUT_INTERFACE = {
    .open_restricted = [](const char *path, int32_t flags, void *user_data)->int32_t {
        if (path == nullptr) {
            MMI_HILOGWK("Input device path is nullptr");
            return RET_ERR;
        }
        char realPath[PATH_MAX] = {};
        if (realpath(path, realPath) == nullptr) {
            std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_FOR_INPUT));
            MMI_HILOGWK("The error path is %{public}s", path);
            return RET_ERR;
        }
        int32_t fd = 0;
        for (int32_t i = 0; i < MAX_RETRY_COUNT; i++) {
            fd = open(realPath, flags);
            if (fd >= 0) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_FOR_INPUT));
        }
        int32_t errNo = errno;
        MMI_HILOGWK("Libinput .open_restricted path:%{public}s,fd:%{public}d,errno:%{public}d", path, fd, errNo);
        return fd < 0 ? RET_ERR : fd;
    },
    .close_restricted = [](int32_t fd, void *user_data)
    {
        if (fd < 0) {
            return;
        }
        MMI_HILOGI("Libinput .close_restricted fd:%{public}d", fd);
        close(fd);
    },
};
} // namespace

class LibinputAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: LibinputAdapterTest_EventDispatch
 * @tc.desc: Cover if (fd == fd_) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LibinputAdapterTest, LibinputAdapterTest_EventDispatch, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LibinputAdapter libinputAdapter;
    int32_t fd = 10;
    libinputAdapter.fd_ = 10;
    libinputAdapter.input_ = libinput_path_create_context(&LIBINPUT_INTERFACE, nullptr);
    ASSERT_NO_FATAL_FAILURE(libinputAdapter.EventDispatch(fd));
}

/**
 * @tc.name: LibinputAdapterTest_EventDispatch_001
 * @tc.desc: Cover else if (fd == hotplugDetector_.GetFd()) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LibinputAdapterTest, LibinputAdapterTest_EventDispatch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LibinputAdapter libinputAdapter;
    int32_t fd = 10;
    libinputAdapter.fd_ = 15;
    libinputAdapter.hotplugDetector_.inotifyFd_ = UniqueFd{ 10 };
    ASSERT_NO_FATAL_FAILURE(libinputAdapter.EventDispatch(fd));
}

/**
 * @tc.name: LibinputAdapterTest_EventDispatch_002
 * @tc.desc: Cover the else branch of if (fd == fd_)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LibinputAdapterTest, LibinputAdapterTest_EventDispatch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LibinputAdapter libinputAdapter;
    int32_t fd = 10;
    libinputAdapter.fd_ = 15;
    libinputAdapter.hotplugDetector_.inotifyFd_ = UniqueFd{ 15 };
    ASSERT_NO_FATAL_FAILURE(libinputAdapter.EventDispatch(fd));
}

/**
 * @tc.name: LibinputAdapterTest_Stop
 * @tc.desc: Cover if (fd_ >= 0) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LibinputAdapterTest, LibinputAdapterTest_Stop, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LibinputAdapter libinputAdapter;
    libinputAdapter.fd_ = 0;
    libinputAdapter.input_ =  nullptr;
    ASSERT_NO_FATAL_FAILURE(libinputAdapter.Stop());
}

/**
 * @tc.name: LibinputAdapterTest_Stop_001
 * @tc.desc: Cover if (input_ != nullptr) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LibinputAdapterTest, LibinputAdapterTest_Stop_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LibinputAdapter libinputAdapter;
    libinputAdapter.fd_ = -1;
    libinputAdapter.input_ = libinput_path_create_context(&LIBINPUT_INTERFACE, nullptr);
    ASSERT_NO_FATAL_FAILURE(libinputAdapter.Stop());
}
} // namespace MMI
} // namespace OHOS