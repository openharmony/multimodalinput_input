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

#ifndef ANCO_CHANNEL_PROXY_H
#define ANCO_CHANNEL_PROXY_H

#include "iremote_object.h"
#include "iremote_proxy.h"
#include "nocopyable.h"

#include "i_anco_channel.h"

namespace OHOS {
namespace MMI {
class AncoChannelProxy final : public IRemoteProxy<IAncoChannel> {
public:
    explicit AncoChannelProxy(const sptr<IRemoteObject> &remoteObj);
    ~AncoChannelProxy() override = default;
    DISALLOW_COPY_AND_MOVE(AncoChannelProxy);

    int32_t SyncInputEvent(std::shared_ptr<PointerEvent> pointerEvent) override;
    int32_t SyncInputEvent(std::shared_ptr<KeyEvent> keyEvent) override;
    int32_t UpdateWindowInfo(std::shared_ptr<AncoWindows> windows) override;

private:
    static inline BrokerDelegator<AncoChannelProxy> delegator_;
};
} // namespace MMI
} // namespace OHOS
#endif // ANCO_CHANNEL_PROXY_H
