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
 
#ifndef NET_PACKET_H
#define NET_PACKET_H

#include "proto.h"
#include "stream_buffer.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "NetPacket"

#pragma pack(1)
using PACKHEAD = struct PackHead {
    MmiMessageId idMsg;
    int32_t size;
};
#pragma pack()

namespace OHOS {
namespace MMI {
class NetPacket : public StreamBuffer {
public:
    explicit NetPacket(MmiMessageId msgId);
    NetPacket(const NetPacket &pkt);
    NetPacket &operator = (const NetPacket &pkt);
    DISALLOW_MOVE(NetPacket);
    virtual ~NetPacket();

    virtual void MakeData(StreamBuffer &buf) const;

    size_t GetSize() const
    {
        return Size();
    }
    int32_t GetPacketLength() const
    {
        return (static_cast<int32_t>(sizeof(PackHead)) + wPos_);
    }
    const char *GetData() const
    {
        return Data();
    }
    MmiMessageId GetMsgId() const
    {
        return msgId_;
    }

protected:
    MmiMessageId msgId_ = MmiMessageId::INVALID;
};
} // namespace MMI
} // namespace OHOS
#endif // NET_PACKET_H