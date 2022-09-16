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
#ifndef CLIENT_MSG_HANDLER_H
#define CLIENT_MSG_HANDLER_H

#include "nocopyable.h"

#include "msg_handler.h"
#include "uds_client.h"

namespace OHOS {
namespace MMI {
typedef std::function<int32_t(const UDSClient&, NetPacket&)> ClientMsgFun;
class ClientMsgHandler : public MsgHandler<MmiMessageId, ClientMsgFun> {
public:
    ClientMsgHandler() = default;
    DISALLOW_COPY_AND_MOVE(ClientMsgHandler);
    virtual ~ClientMsgHandler();

    void Init();
    void InitProcessedCallback();
    void OnMsgHandler(const UDSClient& client, NetPacket& pkt);

protected:
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t OnKeyEvent(const UDSClient& client, NetPacket& pkt);
    int32_t OnKeyMonitor(const UDSClient& client, NetPacket& pkt);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t OnPointerEvent(const UDSClient& client, NetPacket& pkt);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t OnSubscribeKeyEventCallback(const UDSClient& client, NetPacket& pkt);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && (defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || \
    defined(OHOS_BUILD_ENABLE_MONITOR))
    int32_t ReportKeyEvent(const UDSClient& client, NetPacket& pkt);
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
#if (defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)) && \
    (defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR))
    int32_t ReportPointerEvent(const UDSClient& client, NetPacket& pkt);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    int32_t OnInputDevice(const UDSClient& client, NetPacket& pkt);
    int32_t OnInputDeviceIds(const UDSClient& client, NetPacket& pkt);
    int32_t OnSupportKeys(const UDSClient& client, NetPacket& pkt);
    int32_t OnInputKeyboardType(const UDSClient& client, NetPacket& pkt);
    int32_t OnDevListener(const UDSClient& client, NetPacket& pkt);
    int32_t OnAnr(const UDSClient& client, NetPacket& pkt);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    int32_t OnCooperationListiner(const UDSClient& client, NetPacket& pkt);
    int32_t OnCooperationMessage(const UDSClient& client, NetPacket& pkt);
    int32_t OnCooperationState(const UDSClient& client, NetPacket& pkt);
#endif // OHOS_BUILD_ENABLE_COOPERATE

private:
    static void OnDispatchEventProcessed(int32_t eventId);

private:
    std::function<void(int32_t)> dispatchCallback_ { nullptr };
};
} // namespace MMI
} // namespace OHOS
#endif // CLIENT_MSG_HANDLER_H
