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

#ifndef ANCO_CHANNEL_STUB_H
#define ANCO_CHANNEL_STUB_H

#include <functional>
#include <map>

#include "iremote_stub.h"
#include "message_parcel.h"
#include "nocopyable.h"

#include "i_anco_channel.h"

namespace OHOS {
namespace MMI {
class AncoChannelStub : public IRemoteStub<IAncoChannel> {
public:
    AncoChannelStub();
    virtual ~AncoChannelStub() = default;
    DISALLOW_COPY_AND_MOVE(AncoChannelStub);

    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& options) override;

private:
    int32_t StubSyncPointerEvent(MessageParcel &data, MessageParcel &reply);
    int32_t StubSyncKeyEvent(MessageParcel &data, MessageParcel &reply);
    int32_t StubUpdateWindowInfo(MessageParcel &data, MessageParcel &reply);

    std::map<AncoRequestId, int32_t (AncoChannelStub::*)(MessageParcel&, MessageParcel&)> handlers_;
};
} // namespace MMI
} // namespace OHOS
#endif // ANCO_CHANNEL_STUB_H
