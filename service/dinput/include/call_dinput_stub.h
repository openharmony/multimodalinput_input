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

#ifndef CALL_DINPUT_STUB_H
#define CALL_DINPUT_STUB_H
#ifdef OHOS_DISTRIBUTED_INPUT_MODEL

#include "iremote_stub.h"

#include "i_call_dinput.h"
#include "message_parcel.h"

namespace OHOS {
namespace MMI {
class CallDinputStub : public IRemoteStub<ICallDinput> {
public:
    CallDinputStub() = default;
    virtual ~CallDinputStub() = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& options) override;
protected:
    int32_t StubHandlePrepareDinput(MessageParcel& data, MessageParcel& reply);
    int32_t StubHandleUnprepareDinput(MessageParcel& data, MessageParcel& reply);
    int32_t StubHandleStartDinput(MessageParcel& data, MessageParcel& reply);
    int32_t StubHandleStopDinput(MessageParcel& data, MessageParcel& reply);
    int32_t StubHandleRemoteInputAbility(MessageParcel& data, MessageParcel& reply);
};
} // namespace MMI
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_INPUT_MODEL
#endif // CALL_DINPUT_STUB_H
