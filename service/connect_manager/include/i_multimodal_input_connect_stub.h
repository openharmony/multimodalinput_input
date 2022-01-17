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

#ifndef OHOS_MULTIMODAL_INPUT_CONNECT_STUB_H
#define OHOS_MULTIMODAL_INPUT_CONNECT_STUB_H

#include "i_multimodal_input_connect.h"
#include "log.h"
#include "iremote_stub.h"
#include "message_parcel.h"
#include "nocopyable.h"
#include "multimodal_input_connect_define.h"

namespace OHOS {
namespace MMI {
class IMultimodalInputConnectStub : public IRemoteStub<IMultimodalInputConnect> {
public:
    IMultimodalInputConnectStub() = default;
    virtual ~IMultimodalInputConnectStub() = default;

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& options) override;

protected:
    bool IsAuthorizedCalling() const;
    int32_t GetCallingUid() const;
    int32_t GetCallingPid() const;
    virtual int32_t HandleAllocSocketFd(MessageParcel &data, MessageParcel &reply) = 0;
    int32_t StubAddInputEventFilter(MessageParcel& data, MessageParcel& reply);

private:
    static const int SYSTEM_UID = 1000;
    static const int ROOT_UID = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // OHOS_MULTIMODAL_INPUT_CONNECT_STUB_H
