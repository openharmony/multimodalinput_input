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

#ifndef I_ANCO_CHANNEL_H
#define I_ANCO_CHANNEL_H

#include "iremote_broker.h"

#include "i_anco_consumer.h"

namespace OHOS {
namespace MMI {

enum class AncoRequestId {
    SYNC_POINTER_EVENT = 0,
    SYNC_KEY_EVENT,
    UPDATE_WINDOW_INFO,
};

class IAncoChannel : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.multimodalinput.IAncoChannel");

    virtual int32_t SyncInputEvent(std::shared_ptr<PointerEvent> pointerEvent) = 0;
    virtual int32_t SyncInputEvent(std::shared_ptr<KeyEvent> keyEvent) = 0;
    virtual int32_t UpdateWindowInfo(std::shared_ptr<AncoWindows> windows) = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // I_ANCO_CHANNEL_H
