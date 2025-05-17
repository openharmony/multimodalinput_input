/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "input_device_consumer_handler.h"
#include "input_device_manager.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceConsumerHandler"

namespace OHOS {
namespace MMI {

int32_t InputDeviceConsumerHandler::SetDeviceConsumerHandler(const std::vector<std::string>& deviceNames,
    SessionPtr sess)
{
    CALL_INFO_TRACE;
    CHKPR(sess, ERROR_NULL_POINTER);
    for (auto& name : deviceNames) {
        SessionHandler handler { sess };
        auto it = deviceConsumerHandler_.deviceHandler_.find(name);
        if (it != deviceConsumerHandler_.deviceHandler_.end()) {
            it->second.insert(handler);
        } else {
            deviceConsumerHandler_.deviceHandler_.emplace(name, std::set<SessionHandler>{handler});
        }
    }
    return RET_OK;
}

int32_t InputDeviceConsumerHandler::ClearDeviceConsumerHandler(const std::vector<std::string>& deviceNames,
    SessionPtr sess)
{
    return deviceConsumerHandler_.RemoveDeviceHandler(deviceNames, sess);
}

void InputDeviceConsumerHandler::DeviceHandler::HandleEvent(std::string name,
    std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    auto it = deviceHandler_.find(name);
    if (it == deviceHandler_.end()) {
        return;
    }
    MMI_HILOGD("devicehandler size: %{public}zu", deviceHandler_.size());
    NetPacket pkt(MmiMessageId::DEVICE_CONSUMER_HANDLER_EVENT);
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write pointer event failed");
        return;
    }
    for (const auto &item : pointerEvent->GetPointerIds()) {
        PointerEvent::PointerItem pointerItem;
        if (!pointerEvent->GetPointerItem(item, pointerItem)) {
            MMI_HILOGE("Get pointer item failed");
            return;
        }
        MMI_HILOGD("orientation:%{public}d ,blodid:%{public}d, toolType:%{public}d",
            pointerItem.GetOrientation(), pointerItem.GetBlobId(), pointerItem.GetToolType());
    }
    if (InputEventDataTransformation::Marshalling(pointerEvent, pkt) != RET_OK) {
        MMI_HILOGE("Marshalling pointer event failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return;
    }
    for (const auto& [deviceName, handlers] : deviceHandler_) {
        if (deviceName == name) {
            for (const auto& handler : handlers) {
                handler.SendToClient(pointerEvent, pkt);
            }
        }
    }
}

int32_t InputDeviceConsumerHandler::DeviceHandler::RemoveDeviceHandler(const std::vector<std::string>& deviceNames,
    SessionPtr sess)
{
    for (const auto& name : deviceNames) {
        auto it = deviceHandler_.find(name);
        if (it != deviceHandler_.end()) {
            it->second.erase(sess);
        }
    }
    return RET_OK;
}

void InputDeviceConsumerHandler::HandleDeviceConsumerEvent(std::string name,
    const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    deviceConsumerHandler_.HandleEvent(name, pointerEvent);
}

void InputDeviceConsumerHandler::SessionHandler::SendToClient(std::shared_ptr<PointerEvent> pointerEvent,
    NetPacket &pkt) const
{
    CHKPV(pointerEvent);
    CHKPV(session_);
    MMI_HILOGD("Service SendToClient pid:%{public}d", session_->GetPid());
    if (!session_->SendMsg(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
    }
}
} // namespace MMI
} // namespace OHOS
