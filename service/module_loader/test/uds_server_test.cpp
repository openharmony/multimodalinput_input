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

#include "mmi_log.h"
#include "proto.h"
#include "uds_server.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "UDSServerTest"
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

/**
 * @tc.name: SendMsg_001
 * @tc.desc: Test the function SendMsg_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SendMsg_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket pkt(msgId);
    int32_t fd = 1000;
    UDSServer serObj;
    bool retResult = serObj.SendMsg(fd, pkt);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: SendMsg_002
 * @tc.desc: Test the function SendMsg_002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SendMsg_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket pkt(msgId);

    int32_t fd = -1001;
    UDSServer serObj;
    bool retResult = serObj.SendMsg(fd, pkt);
    ASSERT_FALSE(retResult);
}

/**
 * @tc.name: SendMsg_003
 * @tc.desc: Test the function SendMsg_003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SendMsg_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket pkt(msgId);

    int32_t fd = 3333;
    UDSServer serObj;
    bool retResult = serObj.SendMsg(fd, pkt);
    ASSERT_FALSE(retResult);
}

/**
 * @tc.name: Multicast
 * @tc.desc: Test the function Multicast
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, Multicast, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket pkt(msgId);
    std::vector<int32_t> fds;
    ASSERT_NO_FATAL_FAILURE(fds.push_back(1));

    UDSServer serObj;
    serObj.Multicast(fds, pkt);
}

/**
 * @tc.name: Stop_001
 * @tc.desc: Test the function Stop_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, Stop_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer serObj;
    ASSERT_NO_FATAL_FAILURE(serObj.UdsStop());
}

/**
 * @tc.name: GetSession_001
 * @tc.desc: Test the function GetSession_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, GetSession_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer UDS_server;
    int32_t fd = 0;
    auto retResult = UDS_server.GetSession(fd);
    EXPECT_TRUE(retResult == nullptr);
}

/**
 * @tc.name: GetSession_002
 * @tc.desc: Test the function GetSession_002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, GetSession_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer UDS_server;
    int32_t fd = 1000000;
    auto retResult = UDS_server.GetSession(fd);
    EXPECT_TRUE(retResult == nullptr);
}

/**
 * @tc.name: GetSession_003
 * @tc.desc: Test the function GetSession_003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, GetSession_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t ret = RET_ERR;
    int32_t tokenType = TokenType::TOKEN_NATIVE;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
    bool readOnly = false;

    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    ret = udsServer.SetFdProperty(tokenType, serverFd, toReturnClientFd, programName, readOnly);
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
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t ret = RET_ERR;
    int32_t tokenType = TokenType::TOKEN_SHELL;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
    bool readOnly = false;

    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    ret = udsServer.SetFdProperty(tokenType, serverFd, toReturnClientFd, programName, readOnly);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: OnConnected_001
 * @tc.desc: Test the function OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnConnected_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: OnConnected_002
 * @tc.desc: Test the OnConnected function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnConnected_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    EpollEventType type = EPOLL_EVENT_BEGIN;
    int32_t fd = 1;
    ASSERT_NO_FATAL_FAILURE(udsServer.AddEpoll(type, fd));
}

/**
 * @tc.name: SetRecvFun_002
 * @tc.desc: Test the SetRecvFun function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SetRecvFun_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    MsgServerFunCallback fun{ nullptr };
    ASSERT_NO_FATAL_FAILURE(udsServer.SetRecvFun(fun));
}

/**
 * @tc.name: OnPacket_001
 * @tc.desc: Test the OnPacket function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnPacket_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 150;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    udsServer.idxPidMap_.insert(std::make_pair(UDS_PID, fd));
    ASSERT_EQ(udsServer.GetSessionByPid(UDS_PID), session);
}

/**
 * @tc.name: UDSServerTest_DelSession
 * @tc.desc: Test Delete Session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UDSServerTest_DelSession, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 100;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    udsServer.idxPidMap_.insert(std::make_pair(UDS_PID, fd));
    ASSERT_NO_FATAL_FAILURE(udsServer.DelSession(fd));
}

/**
 * @tc.name: UdsStop_002
 * @tc.desc: Test the function UdsStop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UdsStop_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    udsServer.epollFd_ = 2;
    ASSERT_NO_FATAL_FAILURE(udsServer.UdsStop());
}

/**
 * @tc.name: GetClientPid_003
 * @tc.desc: Test the function GetClientPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, GetClientPid_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 125;
    int32_t ret = udsServer.GetClientPid(fd);
    EXPECT_EQ(ret, INVALID_PID);
}

/**
 * @tc.name: GetClientPid_004
 * @tc.desc: Test the function GetClientPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, GetClientPid_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 125;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    int32_t ret = udsServer.GetClientPid(fd);
    EXPECT_EQ(ret, 100);
}

/**
 * @tc.name: SendMsg_004
 * @tc.desc: Test the function SendMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SendMsg_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = -10;
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket pkt(msgId);
    bool ret = udsServer.SendMsg(fd, pkt);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SendMsg_005
 * @tc.desc: Test the function SendMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SendMsg_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 10;
    MmiMessageId msgId = MmiMessageId::INVALID;
    NetPacket pkt(msgId);
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    bool ret = udsServer.SendMsg(fd, pkt);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ReleaseSession_001
 * @tc.desc: Test the function ReleaseSession
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, ReleaseSession_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 10;
    epoll_event ev;
    ASSERT_NO_FATAL_FAILURE(udsServer.ReleaseSession(fd, ev));
}

/**
 * @tc.name: ReleaseSession_002
 * @tc.desc: Test the function ReleaseSession
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, ReleaseSession_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 10;
    epoll_event ev;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    ev.data.ptr = nullptr;
    ASSERT_NO_FATAL_FAILURE(udsServer.ReleaseSession(fd, ev));
}
struct device_status_epoll_event {
    int32_t fd { -1 };
    EpollEventType event_type { EPOLL_EVENT_BEGIN };
};

/**
 * @tc.name: ReleaseSession_003
 * @tc.desc: Test the function ReleaseSession
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, ReleaseSession_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 10;
    epoll_event ev;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    auto eventData = static_cast<device_status_epoll_event*>(malloc(sizeof(device_status_epoll_event)));
    ASSERT_NE(eventData, nullptr);
    ev.data.ptr = eventData;
    ASSERT_NO_FATAL_FAILURE(udsServer.ReleaseSession(fd, ev));
    free(eventData);
    eventData = nullptr;
}

/**
 * @tc.name: OnEpollRecv_004
 * @tc.desc: Test the OnEpollRecv function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnEpollRecv_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = -10;
    epoll_event ev;
    ASSERT_NO_FATAL_FAILURE(udsServer.OnEpollRecv(fd, ev));
}

/**
 * @tc.name: OnEpollRecv_005
 * @tc.desc: Test the OnEpollRecv function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnEpollRecv_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 10;
    epoll_event ev;
    ASSERT_NO_FATAL_FAILURE(udsServer.OnEpollRecv(fd, ev));
}

/**
 * @tc.name: OnEpollEvent_002
 * @tc.desc: Test the OnEpollEvent function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnEpollEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    epoll_event ev;
    ev.data.fd = -10;
    ASSERT_NO_FATAL_FAILURE(udsServer.OnEpollEvent(ev));
}

/**
 * @tc.name: OnEpollEvent_003
 * @tc.desc: Test the OnEpollEvent function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, OnEpollEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    epoll_event ev;
    ev.data.fd = 10;
    ASSERT_NO_FATAL_FAILURE(udsServer.OnEpollEvent(ev));
}

/**
 * @tc.name: EarseSessionByFd_001
 * @tc.desc: Test the EarseSessionByFd function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, EarseSessionByFd_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 10;
    ASSERT_NO_FATAL_FAILURE(udsServer.EarseSessionByFd(fd));
}

/**
 * @tc.name: EarseSessionByFd_002
 * @tc.desc: Test the EarseSessionByFd function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, EarseSessionByFd_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 10;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    ASSERT_NO_FATAL_FAILURE(udsServer.EarseSessionByFd(fd));
}

/**
 * @tc.name: InsertSession_001
 * @tc.desc: Test the InsertSession function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, InsertSession_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = -10;
    SessionPtr sp = nullptr;
    bool ret = udsServer.InsertSession(fd, sp);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InsertSession_002
 * @tc.desc: Test the InsertSession function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, InsertSession_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = -10;
    SessionPtr sp = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    bool ret = udsServer.InsertSession(fd, sp);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InsertSession_003
 * @tc.desc: Test the InsertSession function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, InsertSession_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 10;
    SessionPtr sp = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    bool ret = udsServer.InsertSession(fd, sp);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InsertSession_004
 * @tc.desc: Test the InsertSession function of UDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, InsertSession_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 10;
    SessionPtr sp = nullptr;
    bool ret = udsServer.InsertSession(fd, sp);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: UDSServerTest_GetSessionByPid_001
 * @tc.desc: Test Get Session By Pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UDSServerTest_GetSessionByPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t pid = 150;
    udsServer.pid_ = 10;
    ASSERT_EQ(udsServer.GetSessionByPid(pid), nullptr);
}

/**
 * @tc.name: AddSession_003
 * @tc.desc: The AddSession function of UDSServer properly adds a session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, AddSession_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    SessionPtr ses = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ses->fd_ = -10;
    bool ret = udsServer.AddSession(ses);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AddSession_004
 * @tc.desc: The AddSession function of UDSServer properly adds a session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, AddSession_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    SessionPtr ses = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ses->fd_ = 10;
    bool ret = udsServer.AddSession(ses);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: DelSession_004
 * @tc.desc: The DelSession function of UDSServer properly deletes a session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, DelSession_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = -10;
    ASSERT_NO_FATAL_FAILURE(udsServer.DelSession(fd));
    int32_t fds = 10;
    ASSERT_NO_FATAL_FAILURE(udsServer.DelSession(fds));
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    ASSERT_NO_FATAL_FAILURE(udsServer.DelSession(fds));
}

/**
 * @tc.name: UdsStop_003
 * @tc.desc: Test the function WhenEpollFdIsValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UdsStop_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    udsServer.epollFd_ = 2;
    udsServer.UdsStop();
    EXPECT_EQ(udsServer.epollFd_, -1);
}

/**
 * @tc.name: UdsStop_004
 * @tc.desc: Test the function WhenEpollFdIsInvalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UdsStop_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    udsServer.epollFd_ = -1;
    udsServer.UdsStop();
    EXPECT_EQ(udsServer.epollFd_, -1);
}

/**
 * @tc.name: UdsStop_005
 * @tc.desc: Test the function WhenSessionMapIsNotEmpty
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(UDSServerTest, UdsStop_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 2;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    udsServer.UdsStop();
    EXPECT_TRUE(udsServer.GetSessionMapCopy().empty());
}

/**
 * @tc.name: UdsStop_006
 * @tc.desc: Test the function WhenSessionMapIsEmpty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UdsStop_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    udsServer.ClearSessionMap();
    udsServer.UdsStop();
    EXPECT_TRUE(udsServer.GetSessionMapCopy().empty());
}

/**
 * @tc.name: SetFdProperty_003
 * @tc.desc: Test the function SetFdProperty_ShouldReturnRET_ERR_WhenSetServerFdSendBufferFails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SetFdProperty_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t tokenType = 1;
    int32_t serverFd = -1;
    const std::string programName = "program";
    int32_t toReturnClientFd = 1;
    bool readOnly = false;
    int32_t ret = udsServer.SetFdProperty(tokenType, serverFd, toReturnClientFd, programName, readOnly);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SetFdProperty_004
 * @tc.desc: Test the function SetFdProperty_WhenSetServerFdRecvBufferFails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SetFdProperty_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t tokenType = 1;
    int32_t serverFd = 1;
    const std::string programName = "program";
    int32_t toReturnClientFd = -1;
    bool readOnly = false;
    int32_t ret = udsServer.SetFdProperty(tokenType, serverFd, toReturnClientFd, programName, readOnly);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SetFdProperty_005
 * @tc.desc: Test the function SetFdProperty_WhenSetClientFdSendBufferFailsForNativeToken
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SetFdProperty_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t tokenType = TokenType::TOKEN_NATIVE;
    int32_t serverFd = -1;
    const std::string programName = "program";
    int32_t toReturnClientFd = 1;
    bool readOnly = false;
    int32_t ret = udsServer.SetFdProperty(tokenType, serverFd, toReturnClientFd, programName, readOnly);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SetFdProperty_006
 * @tc.desc: Test the function SetFdProperty_WhenSetClientFdRecvBufferFailsForNativeToken
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SetFdProperty_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t tokenType = TokenType::TOKEN_NATIVE;
    int32_t serverFd = 1;
    const std::string programName = "program";
    int32_t toReturnClientFd = -1;
    bool readOnly = false;
    int32_t ret = udsServer.SetFdProperty(tokenType, serverFd, toReturnClientFd, programName, readOnly);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SetFdProperty_007
 * @tc.desc: Test the function SetFdProperty_WhenProgramNameNotInWhitelist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SetFdProperty_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t tokenType = 1;
    int32_t serverFd = 1;
    const std::string programName = "program";
    int32_t toReturnClientFd = 1;
    bool readOnly = false;
    int32_t ret = udsServer.SetFdProperty(tokenType, serverFd, toReturnClientFd, programName, readOnly);
    EXPECT_EQ(ret, RET_ERR);
    EXPECT_FALSE(readOnly);
}

/**
 * @tc.name: SetFdProperty_008
 * @tc.desc: Test the function SetFdProperty_WhenProgramNameIsInWhitelist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, SetFdProperty_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t tokenType = 1;
    int32_t serverFd = 1;
    const std::string programName = "com.ohos.sceneboard";
    int32_t toReturnClientFd = 1;
    bool readOnly = false;
    int32_t ret = udsServer.SetFdProperty(tokenType, serverFd, toReturnClientFd, programName, readOnly);
    EXPECT_EQ(ret, RET_ERR);
    EXPECT_FALSE(readOnly);
}

/**
 * @tc.name: Dump_001
 * @tc.desc: Test the function Dump_WhenSessionMapIsEmpty
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(UDSServerTest, Dump_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 1;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    std::vector<std::string> args;
    udsServer.GetSessionMapCopy();
    ASSERT_NO_FATAL_FAILURE(udsServer.Dump(fd, args));
}

/**
 * @tc.name: Dump_002
 * @tc.desc: Test the function Dump_WhenSessionMapIsNotEmpty
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(UDSServerTest, Dump_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 1;
    std::vector<std::string> args;
    std::map<int, std::shared_ptr<UDSSession>> sessionMap;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    int32_t tokenType =0;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);

    sessionMap[1] = session;
    udsServer.GetSessionMapCopy();
    ASSERT_NO_FATAL_FAILURE(udsServer.Dump(fd, args));
}

/**
 * @tc.name: DumpSession_003
 * @tc.desc: Test the function DumpSession_WhenSessionMapNotEmpty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, DumpSession_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer UDS_server;
    std::string title = "test_title";
    int32_t fd =  2;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    UDS_server.sessionsMap_.insert(std::make_pair(fd, session));
    ASSERT_NO_FATAL_FAILURE(UDS_server.DumpSession(title));
}

/**
 * @tc.name: DumpSession_005
 * @tc.desc: The DumpSession function WhenTitleIsEmpty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, DumpSession_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    std::string title = "";
    ASSERT_NO_FATAL_FAILURE(udsServer.DumpSession(title));
}

/**
 * @tc.name: GetSessionMapCopy_001
 * @tc.desc: The GetSessionMapCopy function WhenSessionMapIsEmpty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, GetSessionMapCopy_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    auto result = udsServer.GetSessionMapCopy();
    EXPECT_EQ(udsServer.GetSessionSize(), 0);
}

/**
 * @tc.name: GetSessionMapCopy_002
 * @tc.desc: The GetSessionMapCopy function WhenSessionMapHasMultipleSessions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, GetSessionMapCopy_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd = 150;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    auto result = udsServer.GetSessionMapCopy();
    EXPECT_EQ(udsServer.GetSessionSize(), 1);
}

/**
 * @tc.name: GetSessionMapCopy_003
 * @tc.desc: The GetSessionMapCopy function WhenSessionMapHasMultipleSessions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, GetSessionMapCopy_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd1 = 150;
    int32_t fd2 = 200;
    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd1, session1));
    udsServer.sessionsMap_.insert(std::make_pair(fd2, session2));
    auto result = udsServer.GetSessionMapCopy();
    udsServer.sessionsMap_[2] = session2;
    EXPECT_EQ(result.size(), 2);
}

/**
 * @tc.name: UDSServerTest_GetClientFd_001
 * @tc.desc: Test Get InvalidFd_WhenPidNotExistsAndPidNotEqual
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UDSServerTest_GetClientFd_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t pid = 1000;
    int32_t fd = INVALID_FD;
    udsServer.idxPidMap_.insert(std::make_pair(pid, fd));
    int result = udsServer.GetClientFd(pid);
    ASSERT_EQ(result, fd);
}

/**
 * @tc.name: UDSServerTest_GetClientFd_002
 * @tc.desc: Test Get InvalidFd_WhenPidNotExistsAndPidEqual
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UDSServerTest_GetClientFd_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t pid = 1000;
    int32_t fd = INVALID_FD;
    udsServer.pid_ = 1000;
    udsServer.idxPidMap_.insert(std::make_pair(pid, fd));
    int result = udsServer.GetClientFd(pid);
    ASSERT_EQ(result, fd);
    EXPECT_EQ(udsServer.pid_, 1000);
}

/**
 * @tc.name: UDSServerTest_GetClientPid_001
 * @tc.desc: Test Get ShouldReturnInvalidPid_WhenSessionIsNull
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, UDSServerTest_GetClientPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t fd =  INVALID_FD;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    ASSERT_EQ(udsServer.GetClientPid(fd), UDS_PID);
}
} // namespace MMI
} // namespace OHOS
