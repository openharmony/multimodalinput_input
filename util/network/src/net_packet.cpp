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

#include "net_packet.h"

namespace OHOS {
namespace MMI {
NetPacket::NetPacket(MmiMessageId msgId) : msgId_(msgId) {}

NetPacket::NetPacket(const NetPacket &pkt) : NetPacket(pkt.GetMsgId())
{
    Clone(pkt);
}
NetPacket::~NetPacket() {}

void NetPacket::MakeData(StreamBuffer &buf) const
{
    PACKHEAD head = { msgId_, wPos_ };
    buf << head;
    if (wPos_ > 0) {
        if (!buf.Write(&szBuff_[0], wPos_)) {
            MMI_HILOGE("Write data to stream failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
            return;
        }
    }
}
} // namespace MMI
} // namespace OHOS
