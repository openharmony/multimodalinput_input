/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "uds_socket.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
} // namespace

class UDSSocketTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class UDSSocketUnitTest : public UDSSocket {
public:
    UDSSocketUnitTest() {}
    virtual ~UDSSocketUnitTest() {}
};

HWTEST_F(UDSSocketTest, Close, TestSize.Level1)
{
    UDSSocketUnitTest socObj;
    socObj.Close();
    EXPECT_EQ(-1, socObj.GetFd());
}

HWTEST_F(UDSSocketTest, EpollCreat_001, TestSize.Level1)
{
    int32_t size = 0;

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.EpollCreat(size);
    ASSERT_LE(retResult, 0);
}

HWTEST_F(UDSSocketTest, EpollCreat_002, TestSize.Level1)
{
    int32_t size = -1001;

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.EpollCreat(size);
    ASSERT_LE(retResult, 0);
}

HWTEST_F(UDSSocketTest, EpollCtl_001, TestSize.Level1)
{
    int32_t fd = 1001;
    int32_t op = 0;
    struct epoll_event event = {};

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.EpollCtl(fd, op, event);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, EpollCtl_003, TestSize.Level1)
{
    int32_t fd = -1001;
    int32_t op = 1001;
    struct epoll_event event = {};

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.EpollCtl(fd, op, event);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, EpollCtl_004, TestSize.Level1)
{
    int32_t fd = -1001;
    int32_t op = -2002;
    struct epoll_event event = {};

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.EpollCtl(fd, op, event);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, EpollWait_001, TestSize.Level1)
{
    struct epoll_event events[MAX_EVENT_SIZE] = {};
    int32_t timeout = -1;

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.EpollWait(*events, MAX_EVENT_SIZE, timeout);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, EpollWait_002, TestSize.Level1)
{
    struct epoll_event events[MAX_EVENT_SIZE] = {};
    int32_t timeout = 1001;

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.EpollWait(*events, MAX_EVENT_SIZE, timeout);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, EpollWait_003, TestSize.Level1)
{
    struct epoll_event events[MAX_EVENT_SIZE] = {};
    int32_t timeout = -1001;

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.EpollWait(*events, MAX_EVENT_SIZE, timeout);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, EpollWait_004, TestSize.Level1)
{
    struct epoll_event events[MAX_EVENT_SIZE] = {};
    int32_t timeout = -1001;

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.EpollWait(*events, MAX_EVENT_SIZE, timeout);
    ASSERT_EQ(-1, retResult);
}
} // namespace MMI
} // namespace OHOS
