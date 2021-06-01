/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef MULTIMODAL_INPUT_SERVICE_STUB_H
#define MULTIMODAL_INPUT_SERVICE_STUB_H

#include "iremote_object.h"
#include "iremote_stub.h"

#include "i_multimodal_input_service.h"

namespace OHOS {
class MultimodalInputServiceStub : public IRemoteStub<IMultimodalInputService> {
public:
    int OnRemoteRequest(uint32_t code,
        MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    bool IsPermissionValid();
};
} // namespace OHOS

#endif // MULTIMODAL_INPUT_SERVICE_STUB_H
