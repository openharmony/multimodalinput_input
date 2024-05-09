/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "uds_server.h"
#include "proto.h"
#include "udp_wrap.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
const std::string PROGRAM_NAME = "uds_server_test";
constexpr int32_t MODULE_TYPE = 1;
constexpr int32_t UDS_FD = -1;
constexpr int32_t UDS_UID = 100;
constexpr int32_t UDS_PID = 100;
} // namespace

class UDSServerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class UDSServerUnitTest : public UDSServer {
public:
    void SetFd(int32_t fd)
    {
        fd_ = fd;
    }
};

HWTEST_F(UDSServerTest, SendMsg_001, TestSize.Level1)
{
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket pkt(msgId);
    int32_t fd = 1000;
    UDSServer serObj;
    bool retResult = serObj.SendMsg(fd, pkt);
    EXPECT_FALSE(retResult);
}

HWTEST_F(UDSServerTest, SendMsg_002, TestSize.Level1)
{
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket pkt(msgId);

    int32_t fd = -1001;
    UDSServer serObj;
    bool retResult = serObj.SendMsg(fd, pkt);
    ASSERT_FALSE(retResult);
}

HWTEST_F(UDSServerTest, SendMsg_003, TestSize.Level1)
{
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket pkt(msgId);

    int32_t fd = 3333;
    UDSServer serObj;
    bool retResult = serObj.SendMsg(fd, pkt);
    ASSERT_FALSE(retResult);
}

HWTEST_F(UDSServerTest, Multicast, TestSize.Level1)
{
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket pkt(msgId);
    std::vector<int32_t> fds;
    ASSERT_NO_FATAL_FAILURE(fds.push_back(1));

    UDSServer serObj;
    serObj.Multicast(fds, pkt);
}

HWTEST_F(UDSServerTest, Stop_001, TestSize.Level1)
{
    UDSServer serObj;
    ASSERT_NO_FATAL_FAILURE(serObj.UdsStop());
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

/**
 * @tc.name: UdsStop_001
 * @tc.desc: Test the function UdsStop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UdsStop_001, TestSize.Level1)
{
    UDSServer udsServer;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t serverFd = 1;
    int32_t toReturnClientFd = 1;
    int32_t tokenType = 1;
    
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    udsServer.UdsStop();
}

/**
 * @tc.name: GetClientPid_001
 * @tc.desc: Test the function GetClientPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, GetClientPid_001, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = 1;
    int32_t pid1 = 0;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t serverFd = 1;
    int32_t toReturnClientFd = 1;
    int32_t tokenType = 1;
        
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    pid1 = udsServer.GetClientPid(fd);
    EXPECT_EQ(pid1, INVALID_PID);
}

/**
 * @tc.name: AddSocketPairInfo_001
 * @tc.desc: Test the function AddSocketPairInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, AddSocketPairInfo_001, TestSize.Level1)
{
    UDSServer udsServer;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t serverFd = 1;
    int32_t toReturnClientFd = 1;
    int32_t tokenType = 1;
    int32_t ret = 0;
    
    ret = udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SetFdProperty_001
 * @tc.desc: Test the function SetFdProperty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SetFdProperty_001, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t ret = RET_ERR;
    int32_t tokenType = TokenType::TOKEN_NATIVE;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
     
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    ret = udsServer.SetFdProperty(tokenType, serverFd, toReturnClientFd);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SetFdProperty_002
 * @tc.desc: Test the function SetFdProperty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SetFdProperty_002, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t ret = RET_ERR;
    int32_t tokenType = TokenType::TOKEN_SHELL;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
     
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    ret = udsServer.SetFdProperty(tokenType, serverFd, toReturnClientFd);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: Dump_001
 * @tc.desc: Test the function Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, Dump_001, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = 1;
    const std::vector<std::string> args = {"help"};
    int32_t tokenType = TokenType::TOKEN_SHELL;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
     
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    udsServer.Dump(fd, args);
}

/**
 * @tc.name: OnConnected_001
 * @tc.desc: Test the function OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnConnected_001, TestSize.Level1)
{
    UDSServer udsServer;
    SessionPtr sess;
    int32_t tokenType = TokenType::TOKEN_SHELL;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
     
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    udsServer.OnConnected(sess);
}

/**
 * @tc.name: SetRecvFun_001
 * @tc.desc: Test the function SetRecvFun
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SetRecvFun_001, TestSize.Level1)
{
    UDSServer udsServer;
    MsgServerFunCallback fun{ nullptr };
    int32_t tokenType = TokenType::TOKEN_SHELL;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
     
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    udsServer.SetRecvFun(fun);
}

/**
 * @tc.name: OnEpollRecv_001
 * @tc.desc: Test the function OnEpollRecv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnEpollRecv_001, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t size = 100;
    epoll_event ev;
    int32_t tokenType = TokenType::TOKEN_SHELL;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
     
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    int32_t fd = epoll_create(size);    
    udsServer.OnEpollRecv(fd, ev);
}

/**
 * @tc.name: OnEpollRecv_002
 * @tc.desc: Test the function OnEpollRecv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnEpollRecv_002, TestSize.Level1)
{
    UDSServer udsServer;
    epoll_event ev;
    int32_t fd = -1;  
    int32_t tokenType = TokenType::TOKEN_SHELL;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
     
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    udsServer.OnEpollRecv(fd, ev);
}

/**
 * @tc.name: AddEpollEvent_001
 * @tc.desc: Test the function AddEpollEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, AddEpollEvent_001, TestSize.Level1)
{
    UDSServer udsServer;
    std::shared_ptr<mmi_epoll_event> epollEvent=std::make_shared<mmi_epoll_event>();
    int32_t fd = 1;  
    int32_t tokenType = TokenType::TOKEN_SHELL;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
     
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    udsServer.AddEpollEvent(fd, epollEvent);
}

/**
 * @tc.name: DumpSession_001
 * @tc.desc: Test the function DumpSession
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, DumpSession_001, TestSize.Level1)
{
    UDSServer udsServer;
    const std::string title = "test_title";
    int32_t tokenType = TokenType::TOKEN_SHELL;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
     
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    udsServer.DumpSession(title);
}

/**
 * @tc.name: AddSession_001
 * @tc.desc: Test the function AddSession
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, AddSession_001, TestSize.Level1)
{
    UDSServer udsServer;
    SessionPtr sess = nullptr;
    int32_t tokenType = TokenType::TOKEN_SHELL;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
     
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    sess = std::make_shared<UDSSession>(programName, moduleType, serverFd, uid, pid);
    udsServer.AddSession(sess);
}

/**
 * @tc.name: DelSession_001
 * @tc.desc: Test the function DelSession
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, DelSession_001, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = -1;
    int32_t tokenType = TokenType::TOKEN_SHELL;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
     
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    udsServer.DelSession(fd);
}

/**
 * @tc.name: DelSession_002
 * @tc.desc: Test the function DelSession
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, DelSession_002, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = 1;
    int32_t tokenType = TokenType::TOKEN_SHELL;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
     
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    udsServer.DelSession(fd);
}

/**
 * @tc.name: NotifySessionDeleted_001
 * @tc.desc: Test the function NotifySessionDeleted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, NotifySessionDeleted_001, TestSize.Level1)
{
    UDSServer udsServer;
    SessionPtr sess = nullptr;
    int32_t tokenType = TokenType::TOKEN_SHELL;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
     
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    sess = std::make_shared<UDSSession>(programName, moduleType, serverFd, uid, pid);
    udsServer.NotifySessionDeleted(sess);
}

/**
 * @tc.name: GetClientPid_002
 * @tc.desc: Test the scenario of obtaining the client process ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, GetClientPid_002, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = 123;
    auto ret = udsServer.GetClientPid(fd);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: AddSocketPairInfo_002
 * @tc.desc: Test the scenario of adding socket pair information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, AddSocketPairInfo_002, TestSize.Level1)
{
    UDSServer udsServer;
    std::string programName = "program";
    int32_t moduleType = 1;
    int32_t uid = 2;
    int32_t pid = 10;
    int32_t serverFd = 123;
    int32_t toReturnClientFd = 456;
    int32_t tokenType = 1;
    auto ret = udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    if (serverFd != -1) {
        close(serverFd);
    }
    if (toReturnClientFd != -1) {
        close(toReturnClientFd);
    }
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SetFdProperty_003
 * @tc.desc: Test the scenario of setting file descriptor properties
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SetFdProperty_003, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t tokenType = TokenType::TOKEN_NATIVE;
    int32_t serverFd = 123;
    int32_t toReturnClientFd = 456;
    auto ret = udsServer.SetFdProperty(tokenType, serverFd, toReturnClientFd);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: Dump_002
 * @tc.desc: Test the Dump functionality of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, Dump_002, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = 1;
    std::vector<std::string> args = {"help"};
    ASSERT_NO_FATAL_FAILURE(udsServer.Dump(fd, args));
}

/**
 * @tc.name: OnConnected_002
 * @tc.desc: Test the OnConnected function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnConnected_002, TestSize.Level1)
{
    UDSServer udsServer;
    SessionPtr sess = nullptr;
    ASSERT_NO_FATAL_FAILURE(udsServer.OnConnected(sess));
}

/**
 * @tc.name: OnDisconnected_001
 * @tc.desc: Test the OnDisconnected function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnDisconnected_001, TestSize.Level1)
{
    UDSServer udsServer;
    SessionPtr sess = nullptr;
    ASSERT_NO_FATAL_FAILURE(udsServer.OnConnected(sess));
    ASSERT_NO_FATAL_FAILURE(udsServer.OnDisconnected(sess));
}

/**
 * @tc.name: AddEpoll_001
 * @tc.desc: Test the AddEpoll function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, AddEpoll_001, TestSize.Level1)
{
    UDSServer udsServer;
    EpollEventType type = EPOLL_EVENT_BEGIN;
    int32_t fd = 1;
    auto ret = udsServer.AddEpoll(type, fd);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SetRecvFun_002
 * @tc.desc: Test the SetRecvFun function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SetRecvFun_002, TestSize.Level1)
{
    UDSServer udsServer;
    MsgServerFunCallback fun{ nullptr };
    ASSERT_NO_FATAL_FAILURE(udsServer.SetRecvFun(fun));
}

/**
 * @tc.name: ReleaseSession_002
 * @tc.desc: Test the ReleaseSession function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, ReleaseSession_002, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = 1;
    epoll_event ev;
    ASSERT_NO_FATAL_FAILURE(udsServer.ReleaseSession(fd, ev));
}

/**
 * @tc.name: OnPacket_001
 * @tc.desc: Test the OnPacket function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnPacket_001, TestSize.Level1)
{
    UDSServer udsServer;
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket pkt(msgId);
    int32_t fd = 1;
    ASSERT_NO_FATAL_FAILURE(udsServer.OnPacket(fd, pkt));
}

/**
 * @tc.name: OnEpollRecv_003
 * @tc.desc: Test the OnEpollRecv function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnEpollRecv_003, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = -1;
    epoll_event ev;
    ASSERT_NO_FATAL_FAILURE(udsServer.OnEpollRecv(fd, ev));
}

/**
 * @tc.name: OnEpollEvent_001
 * @tc.desc: Test the OnEpollEvent function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnEpollEvent_001, TestSize.Level1)
{
    UDSServer udsServer;
    epoll_event ev;
    ASSERT_NO_FATAL_FAILURE(udsServer.OnEpollEvent(ev));
}

/**
 * @tc.name: AddEpollEvent_002
 * @tc.desc: Test the AddEpollEvent function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, AddEpollEvent_002, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = 1;
    std::shared_ptr<mmi_epoll_event> epollEvent=std::make_shared<mmi_epoll_event>();
    ASSERT_NO_FATAL_FAILURE(udsServer.AddEpollEvent(fd, epollEvent));
}

/**
 * @tc.name: RemoveEpollEvent_001
 * @tc.desc: Test the RemoveEpollEvent function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, RemoveEpollEvent_001, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = 1;
    ASSERT_NO_FATAL_FAILURE(udsServer.RemoveEpollEvent(fd));
}

/**
 * @tc.name: DumpSession_002
 * @tc.desc: The DumpSession function of UDSServer properly outputs session information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, DumpSession_002, TestSize.Level1)
{
    UDSServer udsServer;
    std::string title = "test_title";
    ASSERT_NO_FATAL_FAILURE(udsServer.DumpSession(title));
}

/**
 * @tc.name: AddSession_002
 * @tc.desc: The AddSession function of UDSServer properly adds a session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, AddSession_002, TestSize.Level1)
{
    UDSServer udsServer;
    SessionPtr sess = nullptr;
    bool ret = udsServer.AddSession(sess);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: DelSession_003
 * @tc.desc: The DelSession function of UDSServer properly deletes a session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, DelSession_003, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = -1;
    ASSERT_NO_FATAL_FAILURE(udsServer.DelSession(fd));
    int32_t fds = 1;
    ASSERT_NO_FATAL_FAILURE(udsServer.DelSession(fds));
}

/**
 * @tc.name: NotifySessionDeleted_002
 * @tc.desc: Test the NotifySessionDeleted function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, NotifySessionDeleted_002, TestSize.Level1)
{
    UDSServer udsServer;
    SessionPtr ses = nullptr;
    ASSERT_NO_FATAL_FAILURE(udsServer.NotifySessionDeleted(ses));
}

/**
 * @tc.name: UDSServerTest_GetClientFd
 * @tc.desc: Test Get Client Fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UDSServerTest_GetClientFd, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t pid = 1000;
    int32_t fd = 150;
    udsServer.idxPidMap_.insert(std::make_pair(pid, fd));
    ASSERT_EQ(udsServer.GetClientFd(pid), fd);
}

/**
 * @tc.name: UDSServerTest_GetClientPid
 * @tc.desc: Test Get Client Pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UDSServerTest_GetClientPid, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = 150;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    ASSERT_EQ(udsServer.GetClientPid(fd), UDS_PID);
}

/**
 * @tc.name: UDSServerTest_SendMsg
 * @tc.desc: Test Send Msg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UDSServerTest_SendMsg, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = 150;
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket pkt(msgId);
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    ASSERT_FALSE(udsServer.SendMsg(fd, pkt));
}

/**
 * @tc.name: UDSServerTest_GetSession
 * @tc.desc: Test Get Session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UDSServerTest_GetSession, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = 150;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    ASSERT_EQ(udsServer.GetSession(fd), session);
}

/**
 * @tc.name: UDSServerTest_GetSessionByPid
 * @tc.desc: Test Get Session By Pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UDSServerTest_GetSessionByPid, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = 150;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    udsServer.idxPidMap_.insert(std::make_pair(UDS_PID, fd));
    ASSERT_EQ(udsServer.GetSessionByPid(UDS_PID), session);
}

/**
 * @tc.name: UDSServerTest_AddSession
 * @tc.desc: Test Add Session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UDSServerTest_AddSession, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t udsSessionFd = 100;
    int32_t udsSessionPid = -1;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, udsSessionFd, UDS_UID, udsSessionPid);
    ASSERT_FALSE(udsServer.AddSession(session));

    udsSessionPid = 1000;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, udsSessionFd, UDS_UID, udsSessionPid);
    udsServer.sessionsMap_.insert(std::make_pair(udsSessionFd, sess));
    ASSERT_TRUE(udsServer.AddSession(sess));
    SessionPtr sessPtr = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, udsSessionFd, UDS_UID, udsSessionPid);
    for (int32_t i = 0; i < MAX_SESSON_ALARM + 1; ++i) {
        udsServer.sessionsMap_.insert(std::make_pair(i, sessPtr));
    }
    ASSERT_TRUE(udsServer.AddSession(sessPtr));
}

/**
 * @tc.name: UDSServerTest_DelSession
 * @tc.desc: Test Delete Session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UDSServerTest_DelSession, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = 100;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    udsServer.idxPidMap_.insert(std::make_pair(UDS_PID, fd));
    ASSERT_NO_FATAL_FAILURE(udsServer.DelSession(fd));
}
} // namespace MMI
} // namespace OHOS
