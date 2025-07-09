/*
* Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "mock.h"

#include "stream_buffer.h"
#include "pointer_event.h"
#include "input_event_data_transformation.h"
#include "uds_session.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
    
bool StreamBuffer::ChkRWError() const
{
    return MOCKHANDLER->mockChkRWErrorRet;
}

bool PointerEvent::GetPointerItem(int32_t pointerId, PointerItem &pointerItem) const
{
    return MOCKHANDLER->mockGetPointerItemRet;
}

int32_t InputEventDataTransformation::Marshalling(std::shared_ptr<PointerEvent> event, NetPacket &pkt)
{
    return MOCKHANDLER->mockMarshallingRet;
}

bool UDSSession::SendMsg(NetPacket &pkt)
{
    return MOCKHANDLER->mockSendMsgRet;
}

void UDSServer::AddSessionDeletedCallback(std::function<void(SessionPtr)> callback)
{
    callback(MOCKHANDLER->mockSessionPara);
}
}  // namespace MMI
}  // namespace OHOS
