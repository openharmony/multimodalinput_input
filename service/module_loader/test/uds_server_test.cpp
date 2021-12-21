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
#include "uds_server.h"
#include "proto.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

class UDSServerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

#if BINDER_TODO
class UDSServerUnitTest : public UDSServer {
public:
    void SetFd(int32_t fd)
    {
        fd_ = fd;
    }

    SessionPtr OnAcceptUnitTest()
    {
        return OnAccept();
    }

    void OnRecvUnitTest(int32_t fd, const char *buf, size_t size)
    {
        OnRecv(fd,  buf, size);
    }

    void OnEventUnitTest(const epoll_event& ev, CLMAP<int32_t, StreamBufData>& bufMap)
    {
        OnEvent(ev, bufMap);
    }
};

HWTEST_F(UDSServerTest, Init_001, TestSize.Level1)
{
    const std::string path = "./test";
    UDSServer serObj;
    serObj.Init(path);
}

HWTEST_F(UDSServerTest, Init_002, TestSize.Level1)
{
    const std::string path = "";
    UDSServer serObj;
    serObj.Init(path);
}

HWTEST_F(UDSServerTest, SendMsg_001, TestSize.Level1)
{
    int fd = 1000;
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket newPacket(msgId);

    UDSServer serObj;
    bool retResult = serObj.SendMsg(fd, newPacket);
    EXPECT_FALSE(retResult);
}

HWTEST_F(UDSServerTest, SendMsg_002, TestSize.Level1)
{
    int fd = -1001;
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket newPacket(msgId);

    UDSServer serObj;
    bool retResult = serObj.SendMsg(fd, newPacket);
    ASSERT_FALSE(retResult);
}

HWTEST_F(UDSServerTest, SendMsg_003, TestSize.Level1)
{
    int fd = 3333;
    MmiMessageId msgId = MmiMessageId::BEGIN;
    NetPacket newPacket(msgId);

    UDSServer serObj;
    bool retResult = serObj.SendMsg(fd, newPacket);
    ASSERT_FALSE(retResult);
}

HWTEST_F(UDSServerTest, Broadcast_001, TestSize.Level1)
{
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket newPacket(msgId);

    UDSServer serObj;
    serObj.Broadcast(newPacket);
}

HWTEST_F(UDSServerTest, Broadcast_002, TestSize.Level1)
{
    MmiMessageId msgId = MmiMessageId::BEGIN;
    NetPacket newPacket(msgId);

    UDSServer serObj;
    serObj.Broadcast(newPacket);
}

HWTEST_F(UDSServerTest, Broadcast_003, TestSize.Level1)
{
    MmiMessageId msgId = MmiMessageId::REGISTER_APP_INFO;
    NetPacket newPacket(msgId);

    UDSServer serObj;
    serObj.Broadcast(newPacket);
}

HWTEST_F(UDSServerTest, Broadcast_004, TestSize.Level1)
{
    MmiMessageId msgId = MmiMessageId::REGISTER_MSG_HANDLER;
    NetPacket newPacket(msgId);

    UDSServer serObj;
    serObj.Broadcast(newPacket);
}

HWTEST_F(UDSServerTest, Multicast, TestSize.Level1)
{
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket newPacket(msgId);
    std::vector<int> fds;
    fds.push_back(1);

    UDSServer serObj;
    serObj.Multicast(fds, newPacket);
}

HWTEST_F(UDSServerTest, OnAccept, TestSize.Level1)
{
    UDSServerUnitTest serObjUt;
    serObjUt.OnAcceptUnitTest();
}

HWTEST_F(UDSServerTest, OnRecv, TestSize.Level1)
{
    int32_t fd = 1;
    const char *buf = "333";
    size_t size = 3;

    UDSServerUnitTest serObjUt;
    serObjUt.OnRecvUnitTest(fd, buf, size);
}

HWTEST_F(UDSServerTest, OnEvent, TestSize.Level1)
{
    epoll_event ev = {};
    ev.events = 5;
    CLMAP<int32_t, StreamBufData> bufMap;

    UDSServerUnitTest serObjUt;
    serObjUt.OnEventUnitTest(ev, bufMap);
}

HWTEST_F(UDSServerTest, Stop_001, TestSize.Level1)
{
    UDSServer serObj;
    serObj.Stop();
}

HWTEST_F(UDSServerTest, GetSession_001, TestSize.Level1)
{
    UDSServer UDS_server;
    int32_t fd = 0;
    auto retResult = UDS_server.GetSession(fd);
    EXPECT_TRUE(retResult == nullptr);
}

HWTEST_F(UDSServerTest, GetSession_002, TestSize.Level1)
{
    UDSServer UDS_server;
    int32_t fd = 1000000;
    auto retResult = UDS_server.GetSession(fd);
    EXPECT_TRUE(retResult == nullptr);
}

HWTEST_F(UDSServerTest, GetSession_003, TestSize.Level1)
{
    UDSServer UDS_server;
    int32_t fd = -1;
    auto retResult = UDS_server.GetSession(fd);
    EXPECT_TRUE(retResult == nullptr);
}
#endif
} // namespace
