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
#include "mmi_event_handler.h"
#include <cinttypes>
#include "error_multimodal.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MMIEventHandler" };
}

using namespace AppExecFwk;
MMIEventHandler::MMIEventHandler(const std::shared_ptr<EventRunner> &runner, MMIClientPtr client) :
    EventHandler(runner),
    mmiClient_(client)
{
}

MMIEventHandler::~MMIEventHandler()
{
}

const std::string& MMIEventHandler::GetErrorStr(ErrCode code) const
{
    const static std::string defErrString = "Unknown event handler error!";
    const static std::map<ErrCode, std::string> mapStrings = {
        {ERR_OK, "ERR_OK."},
        {EVENT_HANDLER_ERR_INVALID_PARAM, "Invalid parameters."},
        {EVENT_HANDLER_ERR_NO_EVENT_RUNNER, "Have not set event runner yet."},
        {EVENT_HANDLER_ERR_FD_NOT_SUPPORT, "Not support to listen file descriptors."},
        {EVENT_HANDLER_ERR_FD_ALREADY, "File descriptor is already in listening."},
        {EVENT_HANDLER_ERR_FD_FAILED, "Failed to listen file descriptor."},
        {EVENT_HANDLER_ERR_RUNNER_NO_PERMIT, "No permit to start or stop deposited event runner."},
        {EVENT_HANDLER_ERR_RUNNER_ALREADY, "Event runner is already running."}
    };
    auto it = mapStrings.find(code);
    if (it != mapStrings.end()) {
        return it->second;
    }
    return defErrString;
}

void MMIEventHandler::OnReconnect(const InnerEvent::Pointer &event)
{
    MMI_LOGD("enter");
    CHKPV(mmiClient_);
    if (mmiClient_->Reconnect() != RET_OK) {
        SendEvent(MMI_EVENT_HANDLER_ID_RECONNECT, 0, EVENT_TIME_ONRECONNECT);
    }
}

void MMIEventHandler::OnStop(const InnerEvent::Pointer &event)
{
    MMI_LOGD("enter");
    GetEventRunner()->Stop();
    RemoveAllFileDescriptorListeners();
    RemoveAllEvents();
}

void MMIEventHandler::ProcessEvent(const InnerEvent::Pointer &event)
{
    uint64_t tid = GetThisThreadIdOfLL();
    int32_t pid = GetPid();
    MMI_LOGD("enter. pid:%{public}d tid:%{public}" PRIu64, pid, tid);
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
            MMI_LOGE("Unknown event handler id:%{public}u", eventId);
            break;
        }
    }
}
} // namespace MMI
} // namespace OHOS
