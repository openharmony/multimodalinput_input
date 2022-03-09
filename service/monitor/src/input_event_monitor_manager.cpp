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

#include "input_event_monitor_manager.h"
#include <cinttypes>
#include "input_event_data_transformation.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputEventMonitorManager" };
} // namespace

InputEventMonitorManager::InputEventMonitorManager() {}

InputEventMonitorManager::~InputEventMonitorManager() {}

int32_t InputEventMonitorManager::AddInputEventMontior(SessionPtr session, int32_t eventType)
{
    MMI_LOGD("Enter");
    CHKPR(session, ERROR_NULL_POINTER);
    MonitorItem monitorItem;
    monitorItem.eventType = eventType;
    monitorItem.session =  session;
    auto iter = std::find(monitors_.begin(), monitors_.end(), monitorItem);
    if (iter != monitors_.end()) {
        MMI_LOGE("Key register repeat");
        return RET_ERR;
    }
    iter = monitors_.insert(iter, monitorItem);
    MMI_LOGD("eventType:%{public}d,fd:%{public}d register in server", eventType, session->GetFd());
    return RET_OK;
}

void InputEventMonitorManager::RemoveInputEventMontior(SessionPtr session, int32_t eventType)
{
    MMI_LOGD("Enter");
    CHKPV(session);
    MonitorItem monitorItem;
    monitorItem.eventType = eventType;
    monitorItem.session =  session;
    auto it = std::find(monitors_.begin(), monitors_.end(), monitorItem);
    if (it != monitors_.end()) {
        monitors_.erase(it);
        MMI_LOGW("EventType:%{public}d,fd:%{public}d remove from server", eventType, session->GetFd());
    }
    MMI_LOGD("Leave");
}

void InputEventMonitorManager::OnMonitorInputEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    MMI_LOGD("KeyEvent from libinput, keyCode:%{public}d, keyAction:%{public}d, action:%{public}d, "
             "actionTime:%{public}" PRId64 "", keyEvent->GetKeyCode(), keyEvent->GetKeyAction(),
             keyEvent->GetAction(), keyEvent->GetActionTime());
    if (monitors_.empty()) {
        MMI_LOGE("No monitor to send msg");
        return;
    }
    NetPacket pkt(MmiMessageId::ON_KEYMONITOR);
    InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt);
    for (const auto &item : monitors_) {
        CHKPV(item.session);
        pkt << item.session->GetPid();
        MMI_LOGD("server send the msg to client: keyCode:%{public}d,pid:%{public}d", keyEvent->GetKeyCode(),
            item.session->GetPid());
        item.session->SendMsg(pkt);
    }
}

int32_t InputEventMonitorManager::AddInputEventTouchpadMontior(int32_t eventType, SessionPtr session)
{
    MMI_LOGD("Enter");
    MonitorItem monitorItemTouchpad;
    monitorItemTouchpad.eventType = eventType;
    monitorItemTouchpad.session = session;
    auto iter = std::find(monitorsTouch_.begin(), monitorsTouch_.end(), monitorItemTouchpad);
    if (iter != monitorsTouch_.end()) {
        MMI_LOGE("Touchpad register repeat");
        return RET_ERR;
    }
    iter = monitorsTouch_.insert(iter, monitorItemTouchpad);
    MMI_LOGD("Success, eventType:%{public}d,fd:%{public}d register in server",
        eventType, session->GetFd());
    return RET_OK;
}

void InputEventMonitorManager::RemoveInputEventTouchpadMontior(int32_t eventType, SessionPtr session)
{
    MMI_LOGD("Enter");
    MonitorItem monitorItemtouchpad;
    monitorItemtouchpad.eventType = eventType;
    monitorItemtouchpad.session = session;
    auto iter = std::find(monitorsTouch_.begin(), monitorsTouch_.end(), monitorItemtouchpad);
    if (iter == monitorsTouch_.end()) {
        MMI_LOGE("monitorItemtouchpad does not exist");
    } else {
        MMI_LOGD("eventType:%{public}d,fd:%{public}d remove from server", eventType, session->GetFd());
        iter = monitorsTouch_.erase(iter);
        MMI_LOGD("Service RemoveInputEventTouchpadMontior Success");
    }
    MMI_LOGD("Leave");
}

void InputEventMonitorManager::OnTouchpadMonitorInputEvent(
    std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Enter");
    CHKPV(pointerEvent);
    if (monitorsTouch_.empty()) {
        MMI_LOGE("%{public}s no monitor to send msg", __func__);
    }
    NetPacket pkt(MmiMessageId::ON_TOUCHPAD_MONITOR);
    InputEventDataTransformation::Marshalling(pointerEvent, pkt);
    std::list<MonitorItem>::iterator iter;
    for (const auto &item :  monitorsTouch_) {
        pkt << item.session->GetPid();
        MMI_LOGD("server send the msg to client: EventType:%{public}d,pid:%{public}d",
            pointerEvent->GetEventType(), item.session->GetPid());
        item.session->SendMsg(pkt);
        MMI_LOGD("Service SendMsg Success");
    }
    MMI_LOGD("Leave");
}

bool InputEventMonitorManager::ReportTouchpadEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    PointerEvent::PointerItem item;
    if (!(pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item))) {
        MMI_LOGE("Get pointer parameter failed");
        return false;
    }
    MMI_LOGD("Monitor-serviceeventTouchpad:time:%{public}" PRId64 ","
             "sourceType:%{public}d,action:%{public}d,"
             "pointer:%{public}d,point.x:%{public}d,point.y:%{public}d,press:%{public}d",
             pointerEvent->GetActionTime(), pointerEvent->GetSourceType(), pointerEvent->GetPointerAction(),
             pointerEvent->GetPointerId(), item.GetGlobalX(), item.GetGlobalY(), item.IsPressed());
    OnTouchpadMonitorInputEvent(pointerEvent);
    return true;
}
} // namespace MMI
} // namespace OHOS