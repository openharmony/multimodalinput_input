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
#include "error_multimodal.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MMIEventHandler" };
}

using namespace AppExecFwk;
MMIEventHandler::MMIEventHandler(const std::shared_ptr<EventRunner> &runner) : EventHandler(runner)
{
}

MMIEventHandler::~MMIEventHandler()
{
}

void MMIEventHandler::OnReconnect(const InnerEvent::Pointer &event)
{
    MMI_LOGD("enter");
    SendEvent(MMI_EVENT_HANDLER_ID_ONTIMER, 0, EVENT_TIME_ONRECONNECT);
}

void MMIEventHandler::OnTimer(const InnerEvent::Pointer &event)
{
    MMI_LOGD("enter");
    SendEvent(MMI_EVENT_HANDLER_ID_ONTIMER, 0, EVENT_TIME_ONTIMER);
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
    MMI_LOGD("enter");
    auto eventId = event->GetInnerEventId();
    switch (eventId) {
        case MMI_EVENT_HANDLER_ID_RECONNECT: {
            OnReconnect(event);
            break;
        }
        case MMI_EVENT_HANDLER_ID_ONTIMER: {
            OnTimer(event);
            break;
        }
        case MMI_EVENT_HANDLER_ID_STOP: {
            OnStop(event);
            break;
        }
        default: {
            MMI_LOGE("Unknown event handler id=%{public}u", eventId);
            break;
        }
    }
}

} // namespace MMI
} // namespace OHOS
