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
#ifndef INPUT_EVENT_DATA_TRANSFORMATION_H
#define INPUT_EVENT_DATA_TRANSFORMATION_H
#include "key_event.h"
#include "net_packet.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class InputEventDataTransformation {
    InputEventDataTransformation() = delete;
    DISALLOW_COPY_AND_MOVE(InputEventDataTransformation);

public:
    static int32_t KeyEventToNetPacket(const std::shared_ptr<KeyEvent> key, NetPacket &pkt);
    static int32_t NetPacketToKeyEvent(NetPacket &pkt, std::shared_ptr<KeyEvent> key);
    static int32_t SerializeInputEvent(std::shared_ptr<InputEvent> event, NetPacket &pkt);
    static int32_t DeserializeInputEvent(NetPacket &pkt, std::shared_ptr<InputEvent> event);
    static int32_t Marshalling(std::shared_ptr<PointerEvent> event, NetPacket &pkt);
    static int32_t Unmarshalling(NetPacket &pkt, std::shared_ptr<PointerEvent> event);
private:
    static int32_t SerializePointerItem(NetPacket &pkt, PointerEvent::PointerItem &item);
    static int32_t DeserializePointerItem(NetPacket &pkt, PointerEvent::PointerItem &item);
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_EVENT_DATA_TRANSFORMATION_H
