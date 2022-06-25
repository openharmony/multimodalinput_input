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
#ifdef OHOS_BUILD_MMI_DEBUG
constexpr int32_t DISPLAY_WIDTH = 720;
constexpr int32_t DISPLAY_HEIGHT = 1280;
#endif // OHOS_BUILD_MMI_DEBUG
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
    static bool Write(const WindowInfo& info, NetPacket& pkt)
    {
        pkt << info.id << info.pid << info.uid << info.area << info.defaultHotAreas << info.pointerHotAreas
            << info.agentWindowId << info.flags;
        return (!pkt.ChkRWError());
    }
    static bool Write(const DisplayInfo& info, NetPacket& pkt)
    {
        pkt << info.id << info.x << info.y << info.width << info.height << info.name << info.uniq
            << info.direction;
        return (!pkt.ChkRWError());
    }
    static int32_t GetRandomInt(int32_t min, int32_t max)
    {
        std::mt19937 gen(std::random_device{}());
        std::uniform_int_distribution<> dis(min, max);
        return dis(gen);
    }
    static void RandomHotAreasInfo(std::vector<Rect>& hotAreas)
    {
        Rect area;
        area.x = 0;
        area.y = 0;
        area.width = DISPLAY_WIDTH;
        area.height = DISPLAY_HEIGHT;
        hotAreas.push_back(area);
    }
    static void RandomWindowInfo(int32_t id, int32_t pid, WindowInfo& info)
    {
        info.id = id;
        info.pid = pid;
        info.uid = pid;
        Rect area;
        area.x = 0;
        area.y = 0;
        area.width = DISPLAY_WIDTH;
        area.height = DISPLAY_HEIGHT;
        info.area = area;
        RandomHotAreasInfo(info.defaultHotAreas);
        RandomHotAreasInfo(info.pointerHotAreas);
        info.agentWindowId = id;
        info.flags = 0;
    }
    static void RandomDisplayInfo(int32_t id, DisplayInfo& info)
    {
        info.id = id;
        info.x = 0;
        info.y = 0;
        info.width = DISPLAY_WIDTH;
        info.height = DISPLAY_HEIGHT;
        info.name = StringFmt("pd-%d", id);
        info.uniq = "default0";
        info.direction = Direction::Direction0;
    }
    static bool RandomDisplayPacket(NetPacket& pkt, int32_t pid)
    {
        int32_t width = DISPLAY_WIDTH;
        int32_t height = DISPLAY_HEIGHT;
        int32_t focusWindowId = 1;
        pkt << width << height << focusWindowId;
        uint32_t windowNum = 1;
        pkt << windowNum;
        for (auto i = 0; i < windowNum; i++) {
            WindowInfo info = {};
            RandomWindowInfo(i + 1, pid, info);
            if (!Write(info, pkt)) {
                printf("write WindowInfo failed\n");
                return false;
            }
        }
        uint32_t displayNum = 1;
        pkt << displayNum;
        for (auto i = 0; i < displayNum; i++) {
            DisplayInfo info = {};
            RandomDisplayInfo(i + 1, info);
            if (!Write(info, pkt)) {
                printf("write DisplayInfo failed\n");
                return false;
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
        NetPacket pkt(MmiMessageId::BIGPACKET_TEST);
        ASSERT_TRUE(MMIClientUnitTest::RandomDisplayPacket(pkt, pid));
        EXPECT_TRUE(client->SendMessage(pkt));
    }
    auto endTime = GetSysClockTime();
    printf(" end: endTime:%" PRId64 " D-Value:%" PRId64 "\n", endTime, (endTime - beginTime));
}
#endif // OHOS_BUILD_MMI_DEBUG
} // namespace MMI
} // namespace OHOS
