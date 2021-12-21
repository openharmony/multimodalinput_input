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

#include "input_event_monitor_manager.h"
#include "input_event_data_transformation.h"
#include "proto.h"

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputEventMonitorManager" };
    }
}

OHOS::MMI::InputEventMonitorManager::InputEventMonitorManager()
{
}

OHOS::MMI::InputEventMonitorManager::~InputEventMonitorManager()
{
}

int32_t OHOS::MMI::InputEventMonitorManager::AddInputEventMontior(int32_t eventType, SessionPtr session)
{
    CHKR(session, NULL_POINTER, RET_ERR);
    std::lock_guard<std::mutex> lock(mu_);
    MonitorItem monitorItem;
    monitorItem.eventType = eventType;
    monitorItem.session =  session;
    std::list<MonitorItem>::iterator iter;
    iter = std::find(monitors_.begin(), monitors_.end(), monitorItem);
    if (iter != monitors_.end()) {
        MMI_LOGE("SetEventKeyMonitor: repeate register");
        return RET_ERR;
    } else {
        iter = monitors_.insert(iter, monitorItem);
        MMI_LOGD("eventType: %{public}d, fd: %{public}d register in server", eventType, session->GetFd());
        return RET_OK;
    }
}

void OHOS::MMI::InputEventMonitorManager::RemoveInputEventMontior(int32_t eventType, SessionPtr session)
{
    CHK(session, NULL_POINTER);
    std::lock_guard<std::mutex> lock(mu_);
    MonitorItem monitorItem;
    monitorItem.eventType = eventType;
    monitorItem.session =  session;
    std::list<MonitorItem>::iterator iter;
    iter = std::find(monitors_.begin(), monitors_.end(), monitorItem);
    if (iter == monitors_.end()) {
        MMI_LOGE("RemoveInputEventMontior::monitorItem does not exist");
    } else {
        MMI_LOGD("eventType: %{public}d, fd: %{public}d remove from server", eventType, session->GetFd());
        iter = monitors_.erase(iter);
    }
}

void OHOS::MMI::InputEventMonitorManager::OnMonitorInputEvent(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
{
    CHK(keyEvent, NULL_POINTER);
    if (monitors_.empty()) {
        MMI_LOGE("InputEventMonitorManager::%{public}s no monitor to send msg", __func__);
    }
    NetPacket newPkt(MmiMessageId::ON_KEYMONITOR);
    InputEventDataTransformation::KeyEventToNetPacket(keyEvent, newPkt);
    std::list<MonitorItem>::iterator iter;
    for (iter = monitors_.begin(); iter != monitors_.end(); iter++) {
        newPkt << iter->session->GetPid();
        MMI_LOGD("server send the msg to client: keyCode = %{public}d, pid = %{public}d", keyEvent->GetKeyCode(),
            iter->session->GetPid());
        iter->session->SendMsg(newPkt);
    }
}

void OHOS::MMI::InputEventMonitorManager::ReportKeyEvent(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
{
    CHK(keyEvent, NULL_POINTER);
    MMI_LOGD("KeyEvent from libinput: keyCode = %{public}d, keyAction = %{public}d , action = %{public}d,"
             "deviceId=%{private}d, actionTime = %{public}d", keyEvent->GetKeyCode(), keyEvent->GetKeyAction(),
             keyEvent->GetAction(), keyEvent->GetDeviceId(), keyEvent->GetActionTime());
    OnMonitorInputEvent(keyEvent);
}
