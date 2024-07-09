/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef I_INPUT_BINDER_CLIENT_STUB_H
#define I_INPUT_BINDER_CLIENT_STUB_H

#include "iremote_stub.h"
#include "message_parcel.h"

#include "i_input_binder_client.h"

namespace OHOS {
namespace MMI {
class InputBinderClientStub : public IRemoteStub<IInputBinderClient> {
public:
    InputBinderClientStub() = default;
    virtual ~InputBinderClientStub() = default;
    virtual int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                    MessageOption &option) override;
};
} // namespace MMI
} // namespace OHOS
#endif // I_INPUT_BINDER_CLIENT_STUB_H
