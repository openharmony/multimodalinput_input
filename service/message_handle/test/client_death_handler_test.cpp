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

#include <gtest/gtest.h>

#include "client_death_handler.h"
#include "iremote_object.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ClientDeathHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class ClientDeathHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

void FunctionTest(int32_t) {}

class RemoteObjectTest : public IRemoteObject {
public:
    explicit RemoteObjectTest(std::u16string descriptor) : IRemoteObject(descriptor) {}
    ~RemoteObjectTest() {}

    int32_t GetObjectRefCount() { return 0; }
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) { return 0; }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient)
    {
        return result;
    }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; }
    int Dump(int fd, const std::vector<std::u16string> &args) { return 0; }

public:
    bool result = false;
};

/**
 * @tc.name: ClientDeathHandlerTest_RegisterClientDeathRecipient
 * @tc.desc: Test RegisterClientDeathRecipient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientDeathHandlerTest, ClientDeathHandlerTest_RegisterClientDeathRecipient, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientDeathHandler clientDeathHdl;
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    int32_t pid = 10;
    remote->result = false;
    clientDeathHdl.clientPidMap_.insert(std::make_pair(pid, remote));
    EXPECT_FALSE(clientDeathHdl.RegisterClientDeathRecipient(remote, pid));
}

/**
 * @tc.name: ClientDeathHandlerTest_RegisterClientDeathRecipient_001
 * @tc.desc: Test RegisterClientDeathRecipient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientDeathHandlerTest, ClientDeathHandlerTest_RegisterClientDeathRecipient_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientDeathHandler clientDeathHdl;
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    int32_t pid = 10;
    remote->result = true;
    clientDeathHdl.clientPidMap_.insert(std::make_pair(pid, remote));
    auto deathCallback = [this](const wptr<IRemoteObject> &object) {
        CALL_DEBUG_ENTER;
    };
    clientDeathHdl.deathRecipient_ = new (std::nothrow) InputBinderClientDeathRecipient(deathCallback);
    EXPECT_TRUE(clientDeathHdl.RegisterClientDeathRecipient(remote, pid));
}

/**
 * @tc.name: ClientDeathHandlerTest_AddClientDeathCallback
 * @tc.desc: Test AddClientDeathCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientDeathHandlerTest, ClientDeathHandlerTest_AddClientDeathCallback, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientDeathHandler clientDeathHdl;
    CallBackType type = CallBackType::CALLBACK_TYPE_AUTHORIZE_HELPER;
    ClientDeathCallback callback = FunctionTest;
    clientDeathHdl.deathCallbacks_.insert(std::make_pair(type, callback));
    EXPECT_FALSE(clientDeathHdl.AddClientDeathCallback(type, callback));
}

/**
 * @tc.name: ClientDeathHandlerTest_AddClientDeathCallback_001
 * @tc.desc: Test AddClientDeathCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientDeathHandlerTest, ClientDeathHandlerTest_AddClientDeathCallback_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientDeathHandler clientDeathHdl;
    CallBackType type = CallBackType::CALLBACK_TYPE_AUTHORIZE_HELPER;
    ClientDeathCallback callback = FunctionTest;
    clientDeathHdl.deathCallbacks_.insert(std::make_pair(type, callback));
    type = static_cast<CallBackType>(10);
    EXPECT_TRUE(clientDeathHdl.AddClientDeathCallback(type, callback));
}

/**
 * @tc.name: ClientDeathHandlerTest_AddClientPid
 * @tc.desc: Test AddClientPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientDeathHandlerTest, ClientDeathHandlerTest_AddClientPid, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientDeathHandler clientDeathHdl;
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    int32_t pid = 10;
    clientDeathHdl.clientPidMap_.insert(std::make_pair(pid, remote));
    EXPECT_TRUE(clientDeathHdl.AddClientPid(remote, pid));

    pid = 11;
    EXPECT_TRUE(clientDeathHdl.AddClientPid(remote, pid));
}

/**
 * @tc.name: ClientDeathHandlerTest_RemoveClientPid
 * @tc.desc: Test RemoveClientPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientDeathHandlerTest, ClientDeathHandlerTest_RemoveClientPid, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientDeathHandler clientDeathHdl;
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    int32_t pid = 123456;
    clientDeathHdl.clientPidMap_.insert(std::make_pair(pid, remote));
    pid = 123;
    EXPECT_NO_FATAL_FAILURE(clientDeathHdl.RemoveClientPid(pid));

    pid = 123456;
    EXPECT_NO_FATAL_FAILURE(clientDeathHdl.RemoveClientPid(pid));
}

/**
 * @tc.name: ClientDeathHandlerTest_FindClientPid
 * @tc.desc: Test FindClientPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientDeathHandlerTest, ClientDeathHandlerTest_FindClientPid, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientDeathHandler clientDeathHdl;
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    int32_t pid = 1000;
    clientDeathHdl.clientPidMap_.insert(std::make_pair(pid, remote));
    EXPECT_EQ(clientDeathHdl.FindClientPid(remote), pid);
    pid = 2000;
    clientDeathHdl.clientPidMap_.insert(std::make_pair(pid, remote));
    EXPECT_EQ(clientDeathHdl.FindClientPid(remote), 1000);
}

/**
 * @tc.name: ClientDeathHandlerTest_FindClientPid_001
 * @tc.desc: Test FindClientPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientDeathHandlerTest, ClientDeathHandlerTest_FindClientPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientDeathHandler clientDeathHdl;
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    int32_t pid = 1000;
    clientDeathHdl.clientPidMap_.insert(std::make_pair(pid, remote));
    sptr<RemoteObjectTest> remoteObject = new RemoteObjectTest(u"test1");
    EXPECT_EQ(clientDeathHdl.FindClientPid(remoteObject), INVALID_PID);
}

/**
 * @tc.name: ClientDeathHandlerTest_OnDeath
 * @tc.desc: Test OnDeath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientDeathHandlerTest, ClientDeathHandlerTest_OnDeath, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientDeathHandler clientDeathHdl;
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    int32_t pid = 1000;
    clientDeathHdl.clientPidMap_.insert(std::make_pair(pid, remote));
    wptr<RemoteObjectTest> remoteObject = new RemoteObjectTest(u"test1");
    EXPECT_NO_FATAL_FAILURE(clientDeathHdl.OnDeath(remoteObject));
}

/**
 * @tc.name: ClientDeathHandlerTest_OnDeath_001
 * @tc.desc: Test OnDeath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientDeathHandlerTest, ClientDeathHandlerTest_OnDeath_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientDeathHandler clientDeathHdl;
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    int32_t pid = 1000;
    clientDeathHdl.clientPidMap_.insert(std::make_pair(pid, remote));
    EXPECT_NO_FATAL_FAILURE(clientDeathHdl.OnDeath(remote));
}
} // namespace MMI
} // namespace OHOS