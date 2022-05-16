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

#include "mmi_client.h"

#ifdef OHOS_BUILD_MMI_DEBUG
#include <chrono>
#include <cinttypes>
#include <random>
#include "display_info.h"
#include "multimodal_event_handler.h"
#include "util.h"
#endif // OHOS_BUILD_MMI_DEBUG

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
} // namespace

class MMIClientTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class MMIClientUnitTest : public MMIClient {
public:
    void OnDisconnectedUnitTest()
    {
        OnDisconnected();
    }
    void OnConnectedUnitTest()
    {
        OnConnected();
    }
#ifdef OHOS_BUILD_MMI_DEBUG
public:
    static bool Write(const PhysicalDisplayInfo& info, NetPacket& pkt)
    {
        pkt << info.id << info.leftDisplayId << info.upDisplayId << info.topLeftX << info.topLeftY;
        pkt << info.width << info.height << info.name << info.seatId << info.seatName << info.logicWidth;
        pkt << info.logicHeight << info.direction;
        return (!pkt.ChkRWError());
    }
    static bool Write(const LogicalDisplayInfo& info, NetPacket& pkt)
    {
        pkt << info.id << info.topLeftX << info.topLeftY;
        pkt << info.width << info.height << info.name << info.seatId << info.seatName << info.focusWindowId;
        return (!pkt.ChkRWError());
    }
    static int32_t GetRandomInt(int32_t min, int32_t max)
    {
        std::mt19937 gen(std::random_device{}());
        std::uniform_int_distribution<> dis(min, max);
        return dis(gen);
    }
    static void RandomPhysicalInfo(int32_t id, PhysicalDisplayInfo& info)
    {
        info.id = id;
        info.width = 1280;
        info.height = 1024;
        info.name = StringFmt("pd-%d", id);
        info.seatId = StringFmt("seat%d", id);
        info.seatName = StringFmt("seatname%d", id);
    }
    static void RandomLogicalInfo(int32_t id, LogicalDisplayInfo& info)
    {
        info.id = id;
        info.width = 1280;
        info.height = 1024;
        info.name = StringFmt("pd-%d", id);
        info.seatId = StringFmt("seat%d", id);
        info.seatName = StringFmt("seatname%d", id);
    }
    static void RandomWindowInfo(int32_t id, const LogicalDisplayInfo& logcInfo, WindowInfo& info)
    {
        info.id = id;
        info.pid = id;
        info.uid = id;
        info.hotZoneTopLeftX = GetRandomInt(0, 1280);
        info.hotZoneTopLeftY = GetRandomInt(0, 1024);
        info.hotZoneWidth = GetRandomInt(100, 1280);
        info.hotZoneHeight = GetRandomInt(100, 1024);
        info.displayId = logcInfo.id;
    }
    static bool RandomDisplayPacket(NetPacket& pkt, int32_t phyNum = 1)
    {
        if (!pkt.Write(phyNum)) {
            printf("write failed 1\n");
            return false;
        }
        for (auto i = 0; i < phyNum; i++) {
            PhysicalDisplayInfo info = {};
            RandomPhysicalInfo(i+1, info);
            if (!Write(info, pkt)) {
                printf("write failed 2\n");
                return false;
            }
        }
        int32_t logicalNum = GetRandomInt(5, 10);
        if (!pkt.Write(logicalNum)) {
            printf("write failed 3\n");
            return false;
        }
        for (auto i = 0; i < logicalNum; i++) {
            LogicalDisplayInfo logiclInfo = {};
            RandomLogicalInfo(i+1, logiclInfo);
            int32_t windowsNum = GetRandomInt(5, 15);
            logiclInfo.focusWindowId = 100+windowsNum;
            if (!Write(logiclInfo, pkt)) {
                printf("write failed 4\n");
                return false;
            }
            if (!pkt.Write(windowsNum)) {
                printf("write failed 5\n");
                return false;
            }
            for (auto j = 0; j < windowsNum; j++) {
                WindowInfo winInfo = {};
                RandomWindowInfo(i*100+j+1, logiclInfo, winInfo);
                if (!pkt.Write(winInfo)) {
                    printf("write failed 6\n");
                    return false;
                }
            }
        }
        return true;
    }
#endif // OHOS_BUILD_MMI_DEBUG
};
ConnectCallback connectFun;

/**
 * @tc.name:RegisterConnectedFunction
 * @tc.desc:Verify register connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, RegisterConnectedFunction, TestSize.Level1)
{
    MMIClient mmiClient;
    mmiClient.RegisterConnectedFunction(connectFun);
}

/**
 * @tc.name:RegisterConnectedFunction
 * @tc.desc:Verify register disconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, RegisterDisconnectedFunction, TestSize.Level1)
{
    MMIClient mmiClient;
    mmiClient.RegisterDisconnectedFunction(connectFun);
}

/**
 * @tc.name:Re_RegisterConnectedFunction
 * @tc.desc:Verify register connetct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_RegisterConnectedFunction, TestSize.Level1)
{
    MMIClientUnitTest mmiClientTest;
    mmiClientTest.RegisterConnectedFunction(connectFun);
}

/**
 * @tc.name:Re_RegisterDisconnectedFunction
 * @tc.desc:Verify register disconnetct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_RegisterDisconnectedFunction, TestSize.Level1)
{
    MMIClientUnitTest mmiClientTest;
    mmiClientTest.RegisterDisconnectedFunction(connectFun);
}

HWTEST_F(MMIClientTest, Re_OnConnected, TestSize.Level1)
{
    MMIClientUnitTest mmiClientTest;
    mmiClientTest.OnConnectedUnitTest();
}

/**
 * @tc.name:Re_OnConnected_002
 * @tc.desc:Verify connnected unit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_OnConnected_002, TestSize.Level1)
{
    ConnectCallback funTmp;
    MMIClientUnitTest mmiClientTest;
    mmiClientTest.RegisterConnectedFunction(funTmp);
    mmiClientTest.OnConnectedUnitTest();
}

/**
 * @tc.name:Re_OnDisconnected
 * @tc.desc:Verify disconnnected unit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_OnDisconnected, TestSize.Level1)
{
    MMIClientUnitTest mmiClientTest;
    mmiClientTest.OnDisconnectedUnitTest();
}

/**
 * @tc.name:Re_OnDisconnected_002
 * @tc.desc:Verify disconnnected unit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_OnDisconnected_002, TestSize.Level1)
{
    ConnectCallback funTmp;
    MMIClientUnitTest mmiClientTest;
    mmiClientTest.RegisterDisconnectedFunction(funTmp);
    mmiClientTest.OnDisconnectedUnitTest();
}

#ifdef OHOS_BUILD_MMI_DEBUG
HWTEST_F(MMIClientTest, BigPacketTest, TestSize.Level1)
{
    ASSERT_TRUE(MMIEventHdl.InitClient());
    auto client = MMIEventHdl.GetMMIClient();
    ASSERT_NE(client, nullptr);
    const int32_t pid = GetPid();
    const int32_t maxLimit = MMIClientUnitTest::GetRandomInt(1000, 2000);
    auto beginTime = GetSysClockTime();
    printf(" begin: maxLimit:%d beginTime:%" PRId64 "\n", maxLimit, beginTime);
    for (auto i = 1; i <= maxLimit; i++) {
        int32_t phyNum = MMIClientUnitTest::GetRandomInt(5, 10);
        NetPacket pkt(MmiMessageId::BIGPACKET_TEST);
        pkt << pid << i;
        ASSERT_TRUE(MMIClientUnitTest::RandomDisplayPacket(pkt, phyNum));
        EXPECT_TRUE(client->SendMessage(pkt));
    }
    auto endTime = GetSysClockTime();
    printf(" end: endTime:%" PRId64 " D-Value:%" PRId64 "\n", endTime, (endTime - beginTime));
}
#endif // OHOS_BUILD_MMI_DEBUG
} // namespace MMI
} // namespace OHOS
