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

#include "uds_socket.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

class UDSSocketTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class UDSSocketUnitTest : public UDSSocket {
public:
    UDSSocketUnitTest() {}
    virtual ~UDSSocketUnitTest() {}

    size_t ReadUnitTest(char *buf, size_t size)
    {
        return Read(buf, size);
    }

    size_t WriteUnitTest(const char *buf, size_t size)
    {
        return Write(buf, size);
    }

    size_t SendUnitTest(const char *buf, size_t size, int32_t flags = 0)
    {
        return Send(buf, size, flags);
    }

    size_t RecvUnitTest(char *buf, size_t size, int32_t flags = 0)
    {
        return Recv(buf, size, flags);
    }

    size_t RecvfromUnitTest(char *buf, size_t size, uint32_t flags, sockaddr *addr, size_t *addrlen)
    {
        return Recvfrom(buf, size, flags, addr, addrlen);
    }

    size_t SendtoUnitTest(const char *buf, size_t size, uint32_t flags, sockaddr *addr, size_t addrlen)
    {
        return Sendto(buf, size, flags, addr, addrlen);
    }
};

#if BINDER_TODO

HWTEST_F(UDSSocketTest, Close, TestSize.Level1)
{
    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.Close();
    EXPECT_EQ(RET_OK, retResult);
}

HWTEST_F(UDSSocketTest, Bind_001, TestSize.Level1)
{
    char path[1] = "";

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.Bind(path);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, Bind_002, TestSize.Level1)
{
    char path[] = "./";

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.Bind(path);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, Connect_001, TestSize.Level1)
{
    char path[] = "3362";

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.Connect(path);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, Connect_002, TestSize.Level1)
{
    char path[] = "./";

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.Connect(path);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, Listen_001, TestSize.Level1)
{
    int32_t n = -1001;

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.Listen(n);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, Listen_002, TestSize.Level1)
{
    int32_t n = 1001;

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.Listen(n);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, Accept_001, TestSize.Level1)
{
    sockaddr_un addr;

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.Accept(addr);
    EXPECT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, Accept_002, TestSize.Level1)
{
    sockaddr_un addr = {};

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.Accept(addr);
    EXPECT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, Read_001, TestSize.Level1)
{
    char buf[] = "";
    size_t size = 1;

    UDSSocketUnitTest socObj;
    socObj.ReadUnitTest(buf, size);
}

HWTEST_F(UDSSocketTest, Read002, TestSize.Level1)
{
    char buf[] = "THIS IS RECEIVE DATA";
    size_t size = 20;

    UDSSocketUnitTest socObj;
    socObj.ReadUnitTest(buf, size);
}

HWTEST_F(UDSSocketTest, Read003, TestSize.Level1)
{
    char buf[] = "This is receive data.";
    size_t size = -21;

    UDSSocketUnitTest socObj;
    socObj.ReadUnitTest(buf, size);
}

HWTEST_F(UDSSocketTest, Read004, TestSize.Level1)
{
    char *buf = nullptr;
    size_t size = 20;

    UDSSocketUnitTest socObj;
    socObj.ReadUnitTest(buf, size);
}

HWTEST_F(UDSSocketTest, Write_001, TestSize.Level1)
{
    const char *buf = "";
    size_t size = 1;
    UDSSocketUnitTest socObj;

    socObj.WriteUnitTest(buf, size);
}

HWTEST_F(UDSSocketTest, Write_002, TestSize.Level1)
{
    const char *buf = nullptr;
    size_t size = 1;
    UDSSocketUnitTest socObj;

    socObj.WriteUnitTest(buf, size);
}

HWTEST_F(UDSSocketTest, Write_003, TestSize.Level1)
{
    const char *buf = "THIS IS WRITE DATA";
    size_t size = 18;
    UDSSocketUnitTest socObj;

    socObj.WriteUnitTest(buf, size);
}

HWTEST_F(UDSSocketTest, Write_004, TestSize.Level1)
{
    const char *buf = "this is write data";
    size_t size = -18;
    UDSSocketUnitTest socObj;

    socObj.WriteUnitTest(buf, size);
}

HWTEST_F(UDSSocketTest, Send_001, TestSize.Level1)
{
    const char *buf = "";
    size_t size = 1;
    int32_t flags = 0;

    UDSSocketUnitTest socObj;
    socObj.SendUnitTest(buf, size, flags);
}

HWTEST_F(UDSSocketTest, Send_002, TestSize.Level1)
{
    const char *buf = "THIS IS RECEIVE DATA";
    size_t size = 18;
    int32_t flags = 0;

    UDSSocketUnitTest socObj;
    socObj.SendUnitTest(buf, size, flags);
}

HWTEST_F(UDSSocketTest, Send_003, TestSize.Level1)
{
    const char *buf = "This is receive data.";
    size_t size = -18;
    int32_t flags = 0;

    UDSSocketUnitTest socObj;
    socObj.SendUnitTest(buf, size, flags);
}

HWTEST_F(UDSSocketTest, Send_004, TestSize.Level1)
{
    const char *buf = "data";
    size_t size = 4;
    int32_t flags = 1;

    UDSSocketUnitTest socObj;
    socObj.SendUnitTest(buf, size, flags);
}

HWTEST_F(UDSSocketTest, Send_005, TestSize.Level1)
{
    const char *buf = nullptr;
    size_t size = 0;
    int32_t flags = 1;

    UDSSocketUnitTest socObj;
    socObj.SendUnitTest(buf, size, flags);
}

HWTEST_F(UDSSocketTest, Recv_001, TestSize.Level1)
{
    char buf[] = "";
    size_t size = 1;
    int32_t flags = 0;

    UDSSocketUnitTest socObj;
    socObj.RecvUnitTest(buf, size, flags);
}

HWTEST_F(UDSSocketTest, Recv_002, TestSize.Level1)
{
    char buf[] = "This is Recv data.";
    size_t size = 18;
    int32_t flags = 0;

    UDSSocketUnitTest socObj;
    socObj.RecvUnitTest(buf, size, flags);
}

HWTEST_F(UDSSocketTest, Recv_003, TestSize.Level1)
{
    char buf[] = "This is Recv data.";
    size_t size = -18;
    int32_t flags = 0;

    UDSSocketUnitTest socObj;
    socObj.RecvUnitTest(buf, size, flags);
}

HWTEST_F(UDSSocketTest, Recv_004, TestSize.Level1)
{
    char buf[] = "This is Recv data.";
    size_t size = 0;
    int32_t flags = 1;

    UDSSocketUnitTest socObj;
    socObj.RecvUnitTest(buf, size, flags);
}

HWTEST_F(UDSSocketTest, Recv_005, TestSize.Level1)
{
    char *buf = nullptr;
    size_t size = 18;
    int32_t flags = 0;

    UDSSocketUnitTest socObj;
    socObj.RecvUnitTest(buf, size, flags);
}

HWTEST_F(UDSSocketTest, Recv_006, TestSize.Level1)
{
    char *buf = nullptr;
    size_t size = 0;
    int32_t flags = 0;

    UDSSocketUnitTest socObj;
    socObj.RecvUnitTest(buf, size, flags);
}

HWTEST_F(UDSSocketTest, Recvfrom_001, TestSize.Level1)
{
    char buf[] = "";
    size_t size = 1;
    sockaddr *addr = nullptr;
    size_t *addrlen = nullptr;
    uint32_t flags = 0;

    UDSSocketUnitTest socObj;
    socObj.RecvfromUnitTest(buf, size, flags, addr, addrlen);
}

HWTEST_F(UDSSocketTest, Recvfrom_002, TestSize.Level1)
{
    char buf[] = "This Data";
    size_t size = 1;
    sockaddr *addr = nullptr;
    size_t *addrlen = nullptr;
    uint32_t flags = 0;

    UDSSocketUnitTest socObj;
    socObj.RecvfromUnitTest(buf, size, flags, addr, addrlen);
}

HWTEST_F(UDSSocketTest, Recvfrom_003, TestSize.Level1)
{
    char buf[] = "This Data";
    size_t size = 1;
    sockaddr *addr = {};
    size_t *addrlen = nullptr;
    uint32_t flags = 10;

    UDSSocketUnitTest socObj;
    socObj.RecvfromUnitTest(buf, size, flags, addr, addrlen);
}

HWTEST_F(UDSSocketTest, Sendto_001, TestSize.Level1)
{
    const char *buf = "";
    size_t size = 1;
    sockaddr *addr = nullptr;
    size_t addrlen = 0;
    uint32_t flags = 0;

    UDSSocketUnitTest socObj;
    socObj.SendtoUnitTest(buf, size, flags, addr, addrlen);
}

HWTEST_F(UDSSocketTest, Sendto_002, TestSize.Level1)
{
    const char *buf = "This is send to data.";
    size_t size = 21;
    sockaddr *addr = nullptr;
    size_t addrlen = 0;
    uint32_t flags = 0;

    UDSSocketUnitTest socObj;
    socObj.SendtoUnitTest(buf, size, flags, addr, addrlen);
}

HWTEST_F(UDSSocketTest, Sendto_003, TestSize.Level1)
{
    const char *buf = "This is send to data.";
    size_t size = 21;
    sockaddr *addr = {};
    size_t addrlen = 0;
    uint32_t flags = 0;

    UDSSocketUnitTest socObj;
    socObj.SendtoUnitTest(buf, size, flags, addr, addrlen);
}

HWTEST_F(UDSSocketTest, Sendto_004, TestSize.Level1)
{
    const char *buf = "This is send to data.";
    size_t size = 21;
    sockaddr *addr = {};
    size_t addrlen = 10;
    uint32_t flags = 0;

    UDSSocketUnitTest socObj;
    socObj.SendtoUnitTest(buf, size, flags, addr, addrlen);
}

HWTEST_F(UDSSocketTest, Sendto_005, TestSize.Level1)
{
    const char *buf = "This is send to data.";
    size_t size = 21;
    sockaddr *addr = {};
    size_t addrlen = 10;
    uint32_t flags = 22;

    UDSSocketUnitTest socObj;
    socObj.SendtoUnitTest(buf, size, flags, addr, addrlen);
}

HWTEST_F(UDSSocketTest, EpollCreat_001, TestSize.Level1)
{
    int32_t size = 0;

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.EpollCreat(size);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSSocketTest, EpollCreat_002, TestSize.Level1)
{
    int32_t size = -1001;

    UDSSocketUnitTest socObj;
    int32_t retResult = socObj.EpollCreat(size);
    ASSERT_EQ(-1, retResult);
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
#endif
} // namespace
