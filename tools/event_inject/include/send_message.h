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

#ifndef SEND_MESSAGE_H
#define SEND_MESSAGE_H
#include "msg_head.h"
#include "net_packet.h"

namespace OHOS {
namespace MMI {
class SendMessage {
public:
    SendMessage() = default;
    ~SendMessage() = default;
    int32_t GetDevIndexName(const std::string& deviceName);
    int32_t SendToHdi(const InputEventArray& inputEventArray);
    int32_t SendToHdi(const int32_t& devType, const RawInputEvent& event);
    bool SendMsg(const NetPacket& ckt);
    void TransitionHdiEvent(const struct input_event& event, RawInputEvent& sEvent);
private:
    static constexpr int32_t INJECT_SLEEP_TIMES = 10;
};
} // namespace MMI
} // namespace OHOS
#endif // SEND_MESSAGE_H