/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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


#define private public
#define protected public

#include <future>
#include <optional>

#include <unistd.h>
#include <utility>

#include <gtest/gtest.h>

#include "cooperate_client.h"
#include "devicestatus_define.h"
#include "devicestatus_errors.h"


#undef LOG_TAG
#define LOG_TAG "CooperateClientTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
const std::string SYSTEM_BASIC { "system_basic" };
} // namespace

class CooperateClientTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void CooperateClientTest::SetUpTestCase() {}

void CooperateClientTest::TearDownTestCase() {}

void CooperateClientTest::SetUp() {}

void CooperateClientTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

class CoordinationListenerTest : public ICoordinationListener {
    public:
        CoordinationListenerTest() : ICoordinationListener() {}
        void OnCoordinationMessage(const std::string &networkId, CoordinationMessage msg) override
        {
            FI_HILOGD("Register coordination listener test");
            (void) networkId;
        };
    };

class TunnelClientTest : public ITunnelClient {
    public:
        TunnelClientTest() : ITunnelClient() {}
        int32_t Enable(Intention intention, ParamBase &data, ParamBase &reply)
        {
            return RET_ERR;
        }
        int32_t Disable(Intention intention, ParamBase &data, ParamBase &reply)
        {
            return RET_ERR;
        }
        int32_t Start(Intention intention, ParamBase &data, ParamBase &reply)
        {
            return RET_ERR;
        }
        int32_t Stop(Intention intention, ParamBase &data, ParamBase &reply)
        {
            return RET_ERR;
        }
        int32_t AddWatch(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply)
        {
            return RET_OK;
        }
        int32_t RemoveWatch(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply)
        {
            return RET_ERR;
        }
        int32_t SetParam(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply)
        {
            return RET_ERR;
        }
        int32_t GetParam(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply)
        {
            return RET_OK;
        }
        int32_t Control(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply)
        {
            return RET_ERR;
        }
    };

class StreamClientTest : public StreamClient {
    public:
        StreamClientTest() = default;
        void Stop() override
        {}
        int32_t Socket() override
        {
            return RET_ERR;
        }
    };

/**
 * @tc.name: CooperateClientTest_RegisterListener_001
 * @tc.desc: On Coordination Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_RegisterListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    bool isCompatible = true;
    TunnelClientTest tunnel;
    CooperateClient cooperateClient;
    int32_t ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperateClientTest_RegisterListener_002
 * @tc.desc: On Coordination Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_RegisterListener_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    bool isCompatible = true;
    TunnelClientTest tunnel;
    CooperateClient cooperateClient;
    int32_t ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_OnCoordinationListener_001
 * @tc.desc: On Coordination Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_OnCoordinationListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    bool isCompatible = true;
    TunnelClientTest tunnel;
    CooperateClient cooperateClient;
    int32_t ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    StreamClientTest client;
    int32_t userData = 0;
    std::string networkId = "networkId";
    CoordinationMessage msg = CoordinationMessage::ACTIVATE_SUCCESS;
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    pkt << userData << networkId << static_cast<int32_t>(msg);
    ret = cooperateClient.OnCoordinationListener(client, pkt);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_OnCoordinationListener_002
 * @tc.desc: On Coordination Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_OnCoordinationListener_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    bool isCompatible = true;
    TunnelClientTest tunnel;
    CooperateClient cooperateClient;
    int32_t ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    StreamClientTest client;
    CoordinationMessage msg = CoordinationMessage::ACTIVATE_SUCCESS;
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    pkt << static_cast<int32_t>(msg);
    ret = cooperateClient.OnCoordinationListener(client, pkt);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperateClientTest_OnMouseLocationListener_001
 * @tc.desc: On Hot Area Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_OnMouseLocationListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    bool isCompatible = true;
    TunnelClientTest tunnel;
    CooperateClient cooperateClient;
    int32_t ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    Event event;
    std::string networkId = "networkId";
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    pkt << networkId << event.displayX << event.displayY << event.displayWidth << event.displayHeight;
    StreamClientTest client;
    ret = cooperateClient.OnMouseLocationListener(client, pkt);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_OnMouseLocationListener_002
 * @tc.desc: On Hot Area Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_OnMouseLocationListener_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    bool isCompatible = true;
    TunnelClientTest tunnel;
    CooperateClient cooperateClient;
    int32_t ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    std::string networkId = "networkId";
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    StreamClientTest client;
    ret = cooperateClient.OnMouseLocationListener(client, pkt);
    ASSERT_EQ(ret, RET_ERR);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS