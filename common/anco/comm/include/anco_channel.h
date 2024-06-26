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

#ifndef ANCO_CHANNEL_H
#define ANCO_CHANNEL_H

#include "nocopyable.h"

#include "anco_channel_stub.h"
#include "i_anco_consumer.h"

namespace OHOS {
namespace MMI {
class AncoChannel final : public AncoChannelStub {
public:
    explicit AncoChannel(std::shared_ptr<IAncoConsumer> consumer);
    ~AncoChannel() = default;
    DISALLOW_COPY_AND_MOVE(AncoChannel);

    int32_t SyncInputEvent(std::shared_ptr<PointerEvent> pointerEvent) override;
    int32_t SyncInputEvent(std::shared_ptr<KeyEvent> keyEvent) override;
    int32_t UpdateWindowInfo(std::shared_ptr<AncoWindows> windows) override;

private:
    std::shared_ptr<IAncoConsumer> consumer_;
};
} // namespace MMI
} // namespace OHOS
#endif // ANCO_CHANNEL_H
