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
    CHKPR(session, ERROR_NULL_POINTER, ERROR_NULL_POINTER);
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
    CHKP(session, ERROR_NULL_POINTER);
    std::lock_guard<std::mutex> lock(mu_);
    MonitorItem monitorItem;
    monitorItem.eventType = eventType;
    monitorItem.session =  session;
    auto iter = std::find(monitors_.begin(), monitors_.end(), monitorItem);
    if (iter == monitors_.end()) {
        MMI_LOGE("RemoveInputEventMontior::monitorItem does not exist");
    } else {
        MMI_LOGD("eventType: %{public}d, fd: %{public}d remove from server", eventType, session->GetFd());
        iter = monitors_.erase(iter);
    }
}

void OHOS::MMI::InputEventMonitorManager::OnMonitorInputEvent(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
{
    CHKP(keyEvent, ERROR_NULL_POINTER);
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
    CHKP(keyEvent, ERROR_NULL_POINTER);
    MMI_LOGD("KeyEvent from libinput:keyCode=%{public}d, keyAction=%{public}d, action=%{public}d, "
             "deviceId=%{private}d, actionTime=%{public}d", keyEvent->GetKeyCode(), keyEvent->GetKeyAction(),
             keyEvent->GetAction(), keyEvent->GetDeviceId(), keyEvent->GetActionTime());
    OnMonitorInputEvent(keyEvent);
}

int32_t OHOS::MMI::InputEventMonitorManager::AddInputEventTouchpadMontior(int32_t eventType, SessionPtr session)
{
    MMI_LOGD("InputEventMonitorManager::AddInputEventTouchpadMontior");
    std::lock_guard<std::mutex> lock(mu_);
    MonitorItem monitorItemTouchpad;
    monitorItemTouchpad.eventType = eventType;
    monitorItemTouchpad.session = session;
    auto iter = std::find(monitorsTouch_.begin(), monitorsTouch_.end(), monitorItemTouchpad);
    if (iter != monitorsTouch_.end()) {
        MMI_LOGE("SetEventTouchpadMonitor:repeate register");
        return RET_ERR;
    } else {
        iter = monitorsTouch_.insert(iter, monitorItemTouchpad);
        MMI_LOGD("eventType: %{public}d, fd: %{public}d register in server", eventType, session->GetFd());
        MMI_LOGD("Service AddInputEventTouchpadMontior Success");
        return RET_OK;
    }
}

void OHOS::MMI::InputEventMonitorManager::RemoveInputEventTouchpadMontior(int32_t eventType, SessionPtr session)
{
    MMI_LOGD("InputEventMonitorManager::RemoveInputEventTouchpadMontior");
    std::lock_guard<std::mutex> lock(mu_);
    MonitorItem monitorItemtouchpad;
    monitorItemtouchpad.eventType = eventType;
    monitorItemtouchpad.session = session;
    std::list<MonitorItem>::iterator iter;
    iter = std::find(monitorsTouch_.begin(), monitorsTouch_.end(), monitorItemtouchpad);
    if (iter == monitorsTouch_.end()) {
        MMI_LOGE("RemoveInputEventTouchpadMontior::monitorItemtouchpad does not exist");
    } else {
        MMI_LOGD("eventType: %{public}d, fd: %{public}d remove from server", eventType, session->GetFd());
        iter = monitorsTouch_.erase(iter);
        MMI_LOGD("Service RemoveInputEventTouchpadMontior Success");
    }
}

void OHOS::MMI::InputEventMonitorManager::OnTouchpadMonitorInputEvent(
    std::shared_ptr<OHOS::MMI::PointerEvent> pointerEvent)
{
    MMI_LOGD("InputEventMonitorManager::OnTouchpadMonitorInputEvent");
    if (monitorsTouch_.empty()) {
        MMI_LOGE("InputEventMonitorManager::%{public}s no monitor to send msg", __func__);
    }
    NetPacket newPkt(MmiMessageId::ON_TOUCHPAD_MONITOR);
    InputEventDataTransformation::SerializePointerEvent(pointerEvent, newPkt);
    std::list<MonitorItem>::iterator iter;
    for (iter = monitorsTouch_.begin(); iter != monitorsTouch_.end(); iter++) {
        newPkt << iter->session->GetPid();
        MMI_LOGD("server send the msg to client: EventType = %{public}d, pid = %{public}d",
            pointerEvent->GetEventType(), iter->session->GetPid());
        iter->session->SendMsg(newPkt);
        MMI_LOGD("Service SendMsg Success");
    }
}

bool OHOS::MMI::InputEventMonitorManager::ReportTouchpadEvent(std::shared_ptr<OHOS::MMI::PointerEvent> pointerEvent)
{
    PointerEvent::PointerItem pointer;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointer);
    MMI_LOGT("monitor-serviceeventTouchpad:time=%{public}d;"
             "sourceType=%{public}d;action=%{public}d;"
             "pointerId=%{public}d;point.x=%{public}d;point.y=%{public}d;press=%{public}d"
             "*********************************************************",
             pointerEvent->GetActionTime(), pointerEvent->GetSourceType(), pointerEvent->GetPointerAction(),
             pointerEvent->GetPointerId(), pointer.GetGlobalX(), pointer.GetGlobalY(), pointer.IsPressed());
    OnTouchpadMonitorInputEvent(pointerEvent);
    return true;
}