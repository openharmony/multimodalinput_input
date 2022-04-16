/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <chrono>
#include <random>

#include "display_info.h"

#include "mmi_client.h"
#include "multimodal_event_handler.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MMIClientMain" };
} // namespace

bool Write(const PhysicalDisplayInfo& info, NetPacket& pkt)
{
    pkt << info.id << info.leftDisplayId << info.upDisplayId << info.topLeftX << info.topLeftY;
    pkt << info.width << info.height << info.name << info.seatId << info.seatName << info.logicWidth;
    pkt << info.logicHeight << info.direction;
    return (!pkt.ChkRWError());
}
bool Write(const LogicalDisplayInfo& info, NetPacket& pkt)
{
    pkt << info.id << info.topLeftX << info.topLeftY;
    pkt << info.width << info.height << info.name << info.seatId << info.seatName << info.focusWindowId;
    return (!pkt.ChkRWError());
}
int32_t GetRandomInt(int32_t min, int32_t max)
{
    std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<> dis(min, max);
    //std::default_random_engine e(std::random_device());
    return dis(gen);
}
void RandomPhysicalInfo(int32_t id, PhysicalDisplayInfo& info)
{
    info.id = id;
    info.width = 1280;
    info.height = 1024;
    info.name = StringFmt("pd-%d", id);
    info.seatId = StringFmt("seat%d", id);
    info.seatName = StringFmt("seatname%d", id);
}
void RandomLogicalInfo(int32_t id, LogicalDisplayInfo& info)
{
    info.id = id;
    info.width = 1280;
    info.height = 1024;
    info.name = StringFmt("pd-%d", id);
    info.seatId = StringFmt("seat%d", id);
    info.seatName = StringFmt("seatname%d", id);
}
void RandomWindowInfo(int32_t id, const LogicalDisplayInfo& logcInfo, WindowInfo& info)
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
bool RandomDisplayPacket(NetPacket& pkt, int32_t phyNum = 1)
{
    if (!pkt.Write(phyNum)) {
        MMI_HILOGE("write failed 1");
        return false;
    }
    for (auto i = 0; i < phyNum; i++) {
        PhysicalDisplayInfo info = {};
        RandomPhysicalInfo(i+1, info);
        if (!Write(info, pkt)) {
            MMI_HILOGE("write failed 2");
            return false;
        }
    }
    int32_t logicalNum = GetRandomInt(6, 15);
    if (!pkt.Write(logicalNum)) {
        MMI_HILOGE("write failed 3");
        return false;
    }
    for (auto i = 0; i < logicalNum; i++) {
        LogicalDisplayInfo logiclInfo = {};
        RandomLogicalInfo(i+1, logiclInfo);
        int32_t windowsNum = GetRandomInt(8, 15);
        logiclInfo.focusWindowId = 100+windowsNum;
        if (!Write(logiclInfo, pkt)) {
            MMI_HILOGE("write failed 4");
            return false;
        }
        if (!pkt.Write(windowsNum)) {
            MMI_HILOGE("write failed 5");
            return false;
        }
        for (auto j = 0; j < windowsNum; j++) {
            WindowInfo winInfo = {};
            RandomWindowInfo(i*100+j+1, logiclInfo, winInfo);
            if (!pkt.Write(winInfo)) {
                MMI_HILOGE("write failed 6");
                return false;
            }
        }
    }
    return true;
}
} // namespace MMI
} // namespace OHOS

int32_t main(int32_t argc, const char *argv[])
{
    using namespace OHOS::MMI;
    CALL_LOG_ENTER;
    if (!MMIEventHdl.StartClient()) {
        MMI_HILOGE("StartClient return false");
        return -1;
    }
    const int32_t pid = GetPid();
    auto client = MMIEventHdl.GetMMIClient();
    CHKPR(client, RET_ERR);
    while (1) {
        const int32_t maxLimit = GetRandomInt(2000, 20000);
        for (auto i = 1; i <= maxLimit; i++) {
            int32_t phyNum = GetRandomInt(5, 10);
            NetPacket pkt(MmiMessageId::BIGPACKET_TEST);
            pkt << pid << i;
            if (!RandomDisplayPacket(pkt, phyNum)) {
                MMI_HILOGE("RandomDisplayPacket return false");
                continue;
            }
            if (!client->SendMessage(pkt)) {
                MMI_HILOGE("SendMessage return false");
                continue;
            }
            MMI_HILOGD("id:%{public}d size:%{public}zu", i, pkt.Size());
        }

        const int32_t sleepTime = GetRandomInt(3, 10);
        std::this_thread::sleep_for(std::chrono::seconds(sleepTime));
    }
    MMI_HILOGD("mmi-client stopping. argc:%{public}d, argv:%{public}s", argc, argv[0]);
    return RET_OK;
}