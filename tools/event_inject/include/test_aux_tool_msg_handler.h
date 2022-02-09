/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef TEST_AUX_TOOL_MSG_HANDLER_H
#define TEST_AUX_TOOL_MSG_HANDLER_H
#include "msg_handler.h"
#include "uds_client.h"

namespace OHOS {
namespace MMI {
    constexpr int32_t CHECK_TIME = 200;
    using MsgHandlerFun = std::function<int32_t(const UDSClient&, NetPacket&)>;
    class TestAuxToolMsgHandler : public MsgHandler<MsgHandlerFun> {
    public:
        TestAuxToolMsgHandler() = default;
        ~TestAuxToolMsgHandler() = default;
        bool Init();
        void OnMsgHandler(const UDSClient& client, NetPacket& pkt);
        int32_t OnAiServerReply(const UDSClient& client, NetPacket& pkt);
        int32_t OnHdiServerReply(const UDSClient& client, NetPacket& pkt);
    };
}
}
#endif // TEST_AUX_TOOL_MSG_HANDLER_H