/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "event_filter_parcel.h"
#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "PointerEventParcel" };
} // namespace

bool PointerEventParcel::Marshalling(Parcel& out) const
{
    if (data_ == nullptr) {
        data_ = PointerEvent::Create();
    }
    CHKPF(data_);
    if (!data_->WriteToParcel(out)) {
        data_ = nullptr;
        return false;
    }
    return true;
}

PointerEventParcel *PointerEventParcel::Unmarshalling(Parcel& in)
{
    auto* request = new (std::nothrow) PointerEventParcel();
    if (request == nullptr) {
        return nullptr;
    }

    if (request->data_ == nullptr) {
        request->data_ = PointerEvent::Create();
    }

    if (request->data_ == nullptr) {
        return nullptr;
    }

    if (!request->data_->ReadFromParcel(in)) {
        request->data_ = nullptr;
        delete request;
        request = nullptr;
        return nullptr;
    }
    return request;
}
} // namespace MMI
} // namespace OHOS
