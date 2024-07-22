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

#include "default_params.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
DefaultParam::DefaultParam(int32_t userData)
    : userData(userData)
{}

bool DefaultParam::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteInt32(userData);
}

bool DefaultParam::Unmarshalling(MessageParcel &parcel)
{
    return parcel.ReadInt32(userData);
}

bool DefaultReply::Marshalling(MessageParcel &parcel) const
{
    return true;
}

bool DefaultReply::Unmarshalling(MessageParcel &parcel)
{
    return true;
}

BooleanReply::BooleanReply(bool state) : state(state)
{}

__attribute__((no_sanitize("cfi"))) bool BooleanReply::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteBool(state);
}

bool BooleanReply::Unmarshalling(MessageParcel &parcel)
{
    return parcel.ReadBool(state);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS