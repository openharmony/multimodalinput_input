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

#ifndef MULTIMODAL_INPUT_CONNECT_DEATH_RECIPIENT_H
#define MULTIMODAL_INPUT_CONNECT_DEATH_RECIPIENT_H

#include "iremote_broker.h"

namespace OHOS {
namespace MMI {
class MultimodalInputConnectDeathRecipient final : public IRemoteObject::DeathRecipient {
public:
    explicit MultimodalInputConnectDeathRecipient(const std::function<void(const wptr<IRemoteObject> &object)>
                                                  &deathCallback);
    DISALLOW_COPY_AND_MOVE(MultimodalInputConnectDeathRecipient);
    ~MultimodalInputConnectDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject> &object) override;

private:
    std::function<void(const wptr<IRemoteObject> &object)> deathCallback_;
};
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_INPUT_CONNECT_DEATH_RECIPIENT_H