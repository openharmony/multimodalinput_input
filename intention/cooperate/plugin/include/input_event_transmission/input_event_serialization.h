/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef INPUT_EVENT_SERIALIZATION_H
#define INPUT_EVENT_SERIALIZATION_H

#include "key_event.h"
#include "net_packet.h"
#include "pointer_event.h"
#include "switch_event.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
class InputEventSerialization {
    InputEventSerialization() = delete;
    DISALLOW_COPY_AND_MOVE(InputEventSerialization);

public:
    static int32_t KeyEventToNetPacket(const std::shared_ptr<MMI::KeyEvent> key, NetPacket &pkt);
    static int32_t NetPacketToKeyEvent(NetPacket &pkt, std::shared_ptr<MMI::KeyEvent> key);
    static int32_t SwitchEventToNetPacket(const std::shared_ptr<MMI::SwitchEvent> key, NetPacket &pkt);
    static int32_t NetPacketToSwitchEvent(NetPacket &pkt, std::shared_ptr<MMI::SwitchEvent> key);
    static int32_t Marshalling(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt);
    static int32_t Unmarshalling(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event);
#ifdef OHOS_BUILD_ENABLE_SECURITY_PART
    static int32_t MarshallingEnhanceData(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt);
    static int32_t UnmarshallingEnhanceData(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event);
    static int32_t MarshallingEnhanceData(std::shared_ptr<MMI::KeyEvent> event, NetPacket &pkt);
    static int32_t UnmarshallingEnhanceData(NetPacket &pkt, std::shared_ptr<MMI::KeyEvent> event);
#endif // OHOS_BUILD_ENABLE_SECURITY_PART
private:
    static int32_t SerializeInputEvent(std::shared_ptr<MMI::InputEvent> event, NetPacket &pkt);
    static int32_t DeserializeInputEvent(NetPacket &pkt, std::shared_ptr<MMI::InputEvent> event);
    static int32_t SerializeBaseInfo(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt);
    static int32_t DeserializeBaseInfo(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event);
    static int32_t SerializeAxes(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt);
    static int32_t DeserializeAxes(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event);
    static int32_t SerializePressedButtons(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt);
    static int32_t DeserializePressedButtons(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event);
    static int32_t SerializePointerItem(NetPacket &pkt, MMI::PointerEvent::PointerItem &item);
    static int32_t DeserializePointerItem(NetPacket &pkt, MMI::PointerEvent::PointerItem &item);
    static int32_t SerializePointers(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt);
    static int32_t DeserializePointers(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event);
    static int32_t SerializePressedKeys(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt);
    static int32_t DeserializePressedKeys(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event);
    static int32_t SerializeBuffer(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt);
    static int32_t DeserializeBuffer(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event);
    static void ReadFunctionKeys(NetPacket &pkt, std::shared_ptr<MMI::KeyEvent> key);

#ifdef OHOS_BUILD_ENABLE_SECURITY_PART
    static constexpr uint32_t MAX_HMAC_SIZE = 64;
    struct SecCompPointEvent {
        double touchX;
        double touchY;
        uint64_t timeStamp;
    };
#endif // OHOS_BUILD_ENABLE_SECURITY_PART
};
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // INPUT_EVENT_SERIALIZATION_H
