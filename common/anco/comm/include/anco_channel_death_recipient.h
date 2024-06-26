/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ANCO_CHANNEL_DEATH_RECIPIENT_H
#define ANCO_CHANNEL_DEATH_RECIPIENT_H

#include "iremote_object.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {

class AncoChannelDeathRecipient final : public IRemoteObject::DeathRecipient {
public:
    explicit AncoChannelDeathRecipient(
        std::function<void(const wptr<IRemoteObject>&)> deathCallback);
    ~AncoChannelDeathRecipient() override = default;
    DISALLOW_COPY_AND_MOVE(AncoChannelDeathRecipient);

    void OnRemoteDied(const wptr<IRemoteObject> &object) override;

private:
    std::function<void(const wptr<IRemoteObject>&)> deathCallback_;
};
} // namespace MMI
} // namespace OHOS
#endif // ANCO_CHANNEL_DEATH_RECIPIENT_H