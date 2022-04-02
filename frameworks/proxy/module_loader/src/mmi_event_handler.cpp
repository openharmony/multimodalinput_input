/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "mmi_event_handler.h"

#include <cinttypes>

#include "config_multimodal.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MMIEventHandler" };
}

using namespace AppExecFwk;
MMIEventHandler::MMIEventHandler() : MMIEventHandler(EventRunner::Create(false), nullptr)
{
    CALL_LOG_ENTER;
}

MMIEventHandler::MMIEventHandler(const std::shared_ptr<EventRunner> &runner, MMIClientPtr client)
    : EventHandler(runner), mmiClient_(client)
{
}

MMIEventHandler::~MMIEventHandler()
{
}

bool MMIEventHandler::PostTask(EventHandlerPtr eventHandler, const AppExecFwk::EventHandler::Callback &callback)
{
    CHKPF(eventHandler);
    if (!eventHandler->PostHighPriorityTask(callback)) {
        MMI_HILOGE("post task failed");
        return false;
    }
    return true;
}

const std::string& MMIEventHandler::GetErrorStr(ErrCode code) const
{
    const static std::string defErrString = "Unknown event handler error!";
    const static std::map<ErrCode, std::string> mapStrings = {
        {ERR_OK, "ERR_OK."},
        {EVENT_HANDLER_ERR_INVALID_PARAM, "Invalid parameters"},
        {EVENT_HANDLER_ERR_NO_EVENT_RUNNER, "Have not set event runner yet"},
        {EVENT_HANDLER_ERR_FD_NOT_SUPPORT, "Not support to listen file descriptors"},
        {EVENT_HANDLER_ERR_FD_ALREADY, "File descriptor is already in listening"},
        {EVENT_HANDLER_ERR_FD_FAILED, "Failed to listen file descriptor"},
        {EVENT_HANDLER_ERR_RUNNER_NO_PERMIT, "No permit to start or stop deposited event runner"},
        {EVENT_HANDLER_ERR_RUNNER_ALREADY, "Event runner is already running"}
    };
    auto it = mapStrings.find(code);
    if (it != mapStrings.end()) {
        return it->second;
    }
    return defErrString;
}

MMIEventHandlerPtr MMIEventHandler::GetSharedPtr()
{
    return std::static_pointer_cast<MMIEventHandler>(shared_from_this());
}

void MMIEventHandler::OnReconnect(const InnerEvent::Pointer &event)
{
    CALL_LOG_ENTER;
    CHKPV(mmiClient_);
    if (mmiClient_->Reconnect() != RET_OK) {
        SendEvent(MMI_EVENT_HANDLER_ID_RECONNECT, 0, CLIENT_RECONNECT_COOLING_TIME);
    }
}

void MMIEventHandler::OnStop(const InnerEvent::Pointer &event)
{
    CALL_LOG_ENTER;
    auto runner = GetEventRunner();
    if (runner != nullptr) {
        runner->Stop();
    }
    RemoveAllEvents();
    RemoveAllFileDescriptorListeners();
}

void MMIEventHandler::ProcessEvent(const InnerEvent::Pointer &event)
{
    auto eventId = event->GetInnerEventId();
    switch (eventId) {
        case MMI_EVENT_HANDLER_ID_RECONNECT: {
            OnReconnect(event);
            break;
        }
        case MMI_EVENT_HANDLER_ID_STOP: {
            OnStop(event);
            break;
        }
        default: {
            MMI_HILOGW("Unknown event handler id:%{public}u", eventId);
            break;
        }
    }
}
} // namespace MMI
} // namespace OHOS
