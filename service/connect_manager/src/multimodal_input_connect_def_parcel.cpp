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

#include "multimodal_input_connect_def_parcel.h"

#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultimodalInputConnectDefParcel"

namespace OHOS {
namespace MMI {
bool ConnectReqParcel::Marshalling(Parcel& out) const
{
    WRITEINT32(out, data.moduleId);
    return out.WriteString(data.clientName);
}

ConnectReqParcel *ConnectReqParcel::Unmarshalling(Parcel& in)
{
    auto* request = new (std::nothrow) ConnectReqParcel();
    if (request == nullptr) {
        return nullptr;
    }

    if (!in.ReadInt32(request->data.moduleId)) {
        delete request;
        request = nullptr;
        return nullptr;
    }

    request->data.clientName = in.ReadString();
    return request;
}
} // namespace MMI
} // namespace OHOS
