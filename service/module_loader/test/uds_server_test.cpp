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

#include "proto.h"

#define protected public
#include "uds_server.h"
#undef protected

#include "udp_wrap.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
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
 * @tc.name: ReleaseSession_001
 * @tc.desc: Test the function ReleaseSession
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSServerTest, ReleaseSession_001, TestSize.Level1)
{
    UDSServer udsServer;
    int32_t fd = 1;
    epoll_event ev;
    int32_t tokenType = TokenType::TOKEN_SHELL;
    int32_t serverFd = 1;
    const std::string programName = "program";
    const int32_t moduleType = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    int32_t toReturnClientFd = 1;
     
    udsServer.AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
    udsServer.ReleaseSession(fd, ev);
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
} // namespace MMI
} // namespace OHOS
