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

#include "multimodal_input_connect_death_recipient.h"

#include "mmi_log.h"

namespace OHOS {
namespace MMI {
MultimodalInputConnectDeathRecipient::MultimodalInputConnectDeathRecipient(
    const std::function<void(const wptr<IRemoteObject> &object)> &deathCallback)
    : deathCallback_(deathCallback) {}

void MultimodalInputConnectDeathRecipient::OnRemoteDied(const OHOS::wptr<OHOS::IRemoteObject> &object)
{
    if (deathCallback_ != nullptr) {
        deathCallback_(object);
    }
}
} // namespace MMI
} // namespace OHOS
