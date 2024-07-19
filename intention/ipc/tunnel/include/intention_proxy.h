/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef INTENTION_PROXY_H
#define INTENTION_PROXY_H

#include "iremote_proxy.h"
#include "nocopyable.h"

#include "i_intention.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class IntentionProxy : public IRemoteProxy<IIntention> {
public:
    explicit IntentionProxy(const sptr<IRemoteObject> &impl);
    DISALLOW_COPY_AND_MOVE(IntentionProxy);
    ~IntentionProxy() = default;

    int32_t Enable(Intention intention, MessageParcel &data, MessageParcel &reply) override;
    int32_t Disable(Intention intention, MessageParcel &data, MessageParcel &reply) override;
    int32_t Start(Intention intention, MessageParcel &data, MessageParcel &reply) override;
    int32_t Stop(Intention intention, MessageParcel &data, MessageParcel &reply) override;
    int32_t AddWatch(Intention intention, uint32_t id, MessageParcel &data, MessageParcel &reply) override;
    int32_t RemoveWatch(Intention intention, uint32_t id, MessageParcel &data, MessageParcel &reply) override;
    int32_t SetParam(Intention intention, uint32_t id, MessageParcel &data, MessageParcel &reply) override;
    int32_t GetParam(Intention intention, uint32_t id, MessageParcel &data, MessageParcel &reply) override;
    int32_t Control(Intention intention, uint32_t id, MessageParcel &data, MessageParcel &reply) override;

private:
    static inline BrokerDelegator<IntentionProxy> delegator_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // INTENTION_PROXY_H
