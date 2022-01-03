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

#include "net_packet.h"
#include "log.h"

OHOS::MMI::NetPacket::NetPacket(MmiMessageId idMsg) : idMsg_(idMsg)
{
}

OHOS::MMI::NetPacket::NetPacket(const NetPacket& pack) : NetPacket(pack.GetMsgId())
{
    Clone(pack);
}
OHOS::MMI::NetPacket::~NetPacket()
{
}

void OHOS::MMI::NetPacket::MakeData(StreamBuffer& buf) const
{
    PACKHEAD head = {idMsg_, {static_cast<int32_t>(wIdx_)}};
    buf << head;
    if (wIdx_ > 0) {
        CHK(buf.Write(&szBuff_[0], wIdx_), STREAM_BUF_WRITE_FAIL);
    }
}
