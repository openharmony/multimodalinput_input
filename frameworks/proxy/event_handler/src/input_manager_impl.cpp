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

#include "input_manager_impl.h"

#include <cinttypes>

#include "define_multimodal.h"
#include "error_multimodal.h"

#include "bytrace_adapter.h"
#include "event_filter_service.h"
#include "input_device_cooperate_impl.h"
#include "mmi_client.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputManagerImpl" };
} // namespace

struct MonitorEventConsumer : public IInputEventConsumer {
    explicit MonitorEventConsumer(const std::function<void(std::shared_ptr<PointerEvent>)> &monitor)
        : monitor_ (monitor) {}

    explicit MonitorEventConsumer(const std::function<void(std::shared_ptr<KeyEvent>)> &monitor)
        : keyMonitor_ (monitor) {}

    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const
    {
        CHKPV(keyEvent);
        CHKPV(keyMonitor_);
        keyMonitor_(keyEvent);
    }

    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
    {
        CHKPV(pointerEvent);
        CHKPV(monitor_);
        monitor_(pointerEvent);
    }

    void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const
    {
        CHKPV(axisEvent);
        CHKPV(axisMonitor_);
        axisMonitor_(axisEvent);
    }

private:
    std::function<void(std::shared_ptr<PointerEvent>)> monitor_;
    std::function<void(std::shared_ptr<KeyEvent>)> keyMonitor_;
    std::function<void(std::shared_ptr<AxisEvent>)> axisMonitor_;
};

InputManagerImpl::InputManagerImpl() {}
InputManagerImpl::~InputManagerImpl() {}

void InputManagerImpl::UpdateDisplayInfo(const DisplayGroupInfo &displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Get mmi client is nullptr");
        return;
    }
    if (displayGroupInfo.windowsInfo.empty() || displayGroupInfo.displaysInfo.empty()) {
        MMI_HILOGE("The windows info or display info is empty!");
        return;
    }
    for (const auto &item : displayGroupInfo.windowsInfo) {
        if ((item.defaultHotAreas.size() > WindowInfo::MAX_HOTAREA_COUNT) ||
            (item.pointerHotAreas.size() > WindowInfo::MAX_HOTAREA_COUNT) ||
            item.defaultHotAreas.empty() || item.pointerHotAreas.empty()) {
            MMI_HILOGE("Hot areas check failed! defaultHotAreas:size:%{public}zu,"
                       "pointerHotAreas:size:%{public}zu",
                       item.defaultHotAreas.size(), item.pointerHotAreas.size());
            return;
        }
    }
    displayGroupInfo_ = displayGroupInfo;
    SendDisplayInfo();
    PrintDisplayInfo();
}

int32_t InputManagerImpl::AddInputEventFilter(std::function<bool(std::shared_ptr<PointerEvent>)> filter)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    std::lock_guard<std::mutex> guard(mtx_);
    bool hasSendToMmiServer = true;
    if (eventFilterService_ == nullptr) {
        hasSendToMmiServer = false;
        eventFilterService_ = new (std::nothrow) EventFilterService();
        CHKPR(eventFilterService_, RET_ERR);
    }

    eventFilterService_->SetPointerEventPtr(filter);
    if (!hasSendToMmiServer) {
        int32_t ret = MultimodalInputConnMgr->AddInputEventFilter(eventFilterService_);
        if (ret != RET_OK) {
            MMI_HILOGE("AddInputEventFilter has send to server failed, ret:%{public}d", ret);
            eventFilterService_ = nullptr;
            return RET_ERR;
        }
        return RET_OK;
    }
    return RET_OK;
#else
    MMI_HILOGW("Pointer and touchscreen device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
}

void InputManagerImpl::SetWindowInputEventConsumer(std::shared_ptr<IInputEventConsumer> inputEventConsumer,
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
{
    CALL_INFO_TRACE;
    CHK_PID_AND_TID();
    CHKPV(inputEventConsumer);
    CHKPV(eventHandler);
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient(eventHandler)) {
        MMI_HILOGE("Client init failed");
        return;
    }
    consumer_ = inputEventConsumer;
    eventHandler_ = eventHandler;
}

int32_t InputManagerImpl::SubscribeKeyEvent(std::shared_ptr<KeyOption> keyOption,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    CALL_INFO_TRACE;
    CHK_PID_AND_TID();
    std::lock_guard<std::mutex> guard(mtx_);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    CHKPR(keyOption, RET_ERR);
    CHKPR(callback, RET_ERR);
    return KeyEventInputSubscribeMgr.SubscribeKeyEvent(keyOption, callback);
#else
    MMI_HILOGW("Keyboard device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

void InputManagerImpl::UnsubscribeKeyEvent(int32_t subscriberId)
{
    CALL_INFO_TRACE;
    CHK_PID_AND_TID();
    std::lock_guard<std::mutex> guard(mtx_);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    KeyEventInputSubscribeMgr.UnsubscribeKeyEvent(subscriberId);
#else
    MMI_HILOGW("Keyboard device does not support");
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void InputManagerImpl::OnKeyEventTask(std::shared_ptr<IInputEventConsumer> consumer,
    std::shared_ptr<KeyEvent> keyEvent)
{
    CHK_PID_AND_TID();
    CHKPV(consumer);
    consumer->OnInputEvent(keyEvent);
    MMI_HILOGD("Key event callback keyCode:%{public}d", keyEvent->GetKeyCode());
}

void InputManagerImpl::OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHK_PID_AND_TID();
    CHKPV(keyEvent);
    CHKPV(eventHandler_);
    CHKPV(consumer_);
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    std::shared_ptr<IInputEventConsumer> inputConsumer = nullptr;
    {
        std::lock_guard<std::mutex> guard(mtx_);
        eventHandler = eventHandler_;
        inputConsumer = consumer_;
    }
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::KEY_DISPATCH_EVENT);
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    if (client->IsEventHandlerChanged()) {
        if (!eventHandler->PostHighPriorityTask(std::bind(&InputManagerImpl::OnKeyEventTask,
            this, inputConsumer, keyEvent))) {
            MMI_HILOGE("Post task failed");
            return;
        }
    } else {
        inputConsumer->OnInputEvent(keyEvent);
        MMI_HILOGD("Key event report keyCode:%{public}d", keyEvent->GetKeyCode());
    }
    MMI_HILOGD("Key event keyCode:%{public}d", keyEvent->GetKeyCode());
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void InputManagerImpl::OnPointerEventTask(std::shared_ptr<IInputEventConsumer> consumer,
    std::shared_ptr<PointerEvent> pointerEvent)
{
    CHK_PID_AND_TID();
    CHKPV(consumer);
    CHKPV(pointerEvent);
    consumer->OnInputEvent(pointerEvent);
    MMI_HILOGD("Pointer event callback pointerId:%{public}d", pointerEvent->GetPointerId());
}

void InputManagerImpl::OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHK_PID_AND_TID();
    CHKPV(pointerEvent);
    CHKPV(eventHandler_);
    CHKPV(consumer_);
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    std::shared_ptr<IInputEventConsumer> inputConsumer = nullptr;
    {
        std::lock_guard<std::mutex> guard(mtx_);
        eventHandler = eventHandler_;
        inputConsumer = consumer_;
    }
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::POINT_DISPATCH_EVENT);
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    if (client->IsEventHandlerChanged()) {
        if (!eventHandler->PostHighPriorityTask(std::bind(&InputManagerImpl::OnPointerEventTask,
            this, inputConsumer, pointerEvent))) {
            MMI_HILOGE("Post task failed");
            return;
        }
    } else {
        inputConsumer->OnInputEvent(pointerEvent);
        MMI_HILOGD("Pointer event report pointerId:%{public}d", pointerEvent->GetPointerId());
    }
    MMI_HILOGD("Pointer event pointerId:%{public}d", pointerEvent->GetPointerId());
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

int32_t InputManagerImpl::PackDisplayData(NetPacket &pkt)
{
    pkt << displayGroupInfo_.width << displayGroupInfo_.height << displayGroupInfo_.focusWindowId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write logical data failed");
        return RET_ERR;
    }
    if (PackWindowInfo(pkt) == RET_ERR) {
        MMI_HILOGE("Packet write windows info failed");
        return RET_ERR;
    }
    return PackDisplayInfo(pkt);
}

int32_t InputManagerImpl::PackWindowInfo(NetPacket &pkt)
{
    uint32_t num = static_cast<uint32_t>(displayGroupInfo_.windowsInfo.size());
    pkt << num;
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        pkt << item.id << item.pid << item.uid << item.area
            << item.defaultHotAreas << item.pointerHotAreas
            << item.agentWindowId << item.flags;
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write windows data failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputManagerImpl::PackDisplayInfo(NetPacket &pkt)
{
    uint32_t num = static_cast<uint32_t>(displayGroupInfo_.displaysInfo.size());
    pkt << num;
    for (const auto &item : displayGroupInfo_.displaysInfo) {
        pkt << item.id << item.x << item.y << item.width
            << item.height << item.name << item.uniq << item.direction;
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write display data failed");
        return RET_ERR;
    }
    return RET_OK;
}

void InputManagerImpl::PrintDisplayInfo()
{
    MMI_HILOGI("logicalInfo,width:%{public}d,height:%{public}d,focusWindowId:%{public}d",
        displayGroupInfo_.width, displayGroupInfo_.height, displayGroupInfo_.focusWindowId);
    MMI_HILOGI("windowsInfos,num:%{public}zu", displayGroupInfo_.windowsInfo.size());
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        MMI_HILOGI("windowsInfos,id:%{public}d,pid:%{public}d,uid:%{public}d,"
            "area.x:%{public}d,area.y:%{public}d,area.width:%{public}d,area.height:%{public}d,"
            "defaultHotAreas.size:%{public}zu,pointerHotAreas.size:%{public}zu,"
            "agentWindowId:%{public}d,flags:%{public}d",
            item.id, item.pid, item.uid, item.area.x, item.area.y, item.area.width,
            item.area.height, item.defaultHotAreas.size(), item.pointerHotAreas.size(),
            item.agentWindowId, item.flags);
        for (const auto &win : item.defaultHotAreas) {
            MMI_HILOGI("defaultHotAreas:x:%{public}d,y:%{public}d,width:%{public}d,height:%{public}d",
                win.x, win.y, win.width, win.height);
        }
        for (const auto &pointer : item.pointerHotAreas) {
            MMI_HILOGI("pointerHotAreas:x:%{public}d,y:%{public}d,width:%{public}d,height:%{public}d",
                pointer.x, pointer.y, pointer.width, pointer.height);
        }
    }

    MMI_HILOGI("displayInfos,num:%{public}zu", displayGroupInfo_.displaysInfo.size());
    for (const auto &item : displayGroupInfo_.displaysInfo) {
        MMI_HILOGI("displayInfos,id:%{public}d,x:%{public}d,y:%{public}d,"
            "width:%{public}d,height:%{public}d,name:%{public}s,"
            "uniq:%{public}s,direction:%{public}d",
            item.id, item.x, item.y, item.width, item.height, item.name.c_str(),
            item.uniq.c_str(), item.direction);
    }
}

int32_t InputManagerImpl::AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_MONITOR)
    CHKPR(monitor, INVALID_HANDLER_ID);
    auto consumer = std::make_shared<MonitorEventConsumer>(monitor);
    return AddMonitor(consumer);
#else
    MMI_HILOGW("Keyboard device or monitor function does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_KEYBOARD || OHOS_BUILD_ENABLE_MONITOR
}

int32_t InputManagerImpl::AddMonitor(std::function<void(std::shared_ptr<PointerEvent>)> monitor)
{
    CALL_INFO_TRACE;
#if (defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)) && defined(OHOS_BUILD_ENABLE_MONITOR)
    CHKPR(monitor, INVALID_HANDLER_ID);
    auto consumer = std::make_shared<MonitorEventConsumer>(monitor);
    return AddMonitor(consumer);
#else
    MMI_HILOGW("Pointer/touchscreen device or monitor function does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_MONITOR ||  OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
}

int32_t InputManagerImpl::AddMonitor(std::shared_ptr<IInputEventConsumer> consumer)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_MONITOR
    CHKPR(consumer, INVALID_HANDLER_ID);
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return IMonitorMgr->AddMonitor(consumer);
#else
    MMI_HILOGI("Monitor function does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_MONITOR
}

void InputManagerImpl::RemoveMonitor(int32_t monitorId)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_MONITOR
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return;
    }
    IMonitorMgr->RemoveMonitor(monitorId);
#else
    MMI_HILOGI("Monitor function does not support");
#endif // OHOS_BUILD_ENABLE_MONITOR
}

void InputManagerImpl::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_MONITOR
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return;
    }
    IMonitorMgr->MarkConsumed(monitorId, eventId);
#else
    MMI_HILOGI("Monitor function does not support");
#endif // OHOS_BUILD_ENABLE_MONITOR
}

void InputManagerImpl::MoveMouse(int32_t offsetX, int32_t offsetY)
{
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    std::lock_guard<std::mutex> guard(mtx_);
    if (MMIEventHdl.MoveMouseEvent(offsetX, offsetY) != RET_OK) {
        MMI_HILOGE("Failed to inject move mouse offset event");
    }
#else
    MMI_HILOGW("Pointer device or pointer drawing module does not support");
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
}

int32_t InputManagerImpl::AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    CHKPR(interceptor, INVALID_HANDLER_ID);
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputInterMgr->AddInterceptor(interceptor, HANDLE_EVENT_TYPE_ALL);
#else
    MMI_HILOGW("Interceptor function does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
}

int32_t InputManagerImpl::AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    CHKPR(interceptor, INVALID_HANDLER_ID);
    std::lock_guard<std::mutex> guard(mtx_);
    auto consumer = std::make_shared<MonitorEventConsumer>(interceptor);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputInterMgr->AddInterceptor(consumer, HANDLE_EVENT_TYPE_KEY);
#else
    MMI_HILOGW("Keyboard device or interceptor function does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_INTERCEPTOR
}

void InputManagerImpl::RemoveInterceptor(int32_t interceptorId)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return;
    }
    InputInterMgr->RemoveInterceptor(interceptorId);
#else
    MMI_HILOGW("Interceptor function does not support");
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
}

void InputManagerImpl::SimulateInputEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    CHKPV(keyEvent);
    std::lock_guard<std::mutex> guard(mtx_);
    if (MMIEventHdl.InjectEvent(keyEvent) != RET_OK) {
        MMI_HILOGE("Failed to inject keyEvent");
    }
#else
    MMI_HILOGW("Keyboard device does not support");
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

void InputManagerImpl::SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    CHKPV(pointerEvent);
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE ||
        pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHPAD) {
#ifndef OHOS_BUILD_ENABLE_POINTER
        MMI_HILOGW("Pointer device does not support");
        return;
#endif
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
#ifndef OHOS_BUILD_ENABLE_TOUCH
        MMI_HILOGW("Touchscreen device does not support");
        return;
#endif
    }
#ifndef OHOS_BUILD_ENABLE_JOYSTICK
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_JOYSTICK) {
        MMI_HILOGW("Joystick device does not support");
        return;
    }
#endif
    std::lock_guard<std::mutex> guard(mtx_);
    if (MMIEventHdl.InjectPointerEvent(pointerEvent) != RET_OK) {
        MMI_HILOGE("Failed to inject pointer event");
    }
#else
    MMI_HILOGW("Pointer and touchscreen device does not support");
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
}

int32_t InputManagerImpl::SetPointerVisible(bool visible)
{
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    CALL_DEBUG_ENTER;
    int32_t ret = MultimodalInputConnMgr->SetPointerVisible(visible);
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer visible failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device or pointer drawing module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
}

bool InputManagerImpl::IsPointerVisible()
{
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    CALL_DEBUG_ENTER;
    bool visible;
    int32_t ret = MultimodalInputConnMgr->IsPointerVisible(visible);
    if (ret != 0) {
        MMI_HILOGE("Get pointer visible failed, ret:%{public}d", ret);
    }
    return visible;
#else
    MMI_HILOGW("Pointer device or pointer drawing module does not support");
    return false;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
}

int32_t InputManagerImpl::SetPointerSpeed(int32_t speed)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = MultimodalInputConnMgr->SetPointerSpeed(speed);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to set pointer speed");
        return RET_ERR;
    }
    return RET_OK;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetPointerSpeed(int32_t &speed)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = MultimodalInputConnMgr->GetPointerSpeed(speed);
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer speed failed");
        return RET_ERR;
    }
    return RET_OK;
#else
    return ERROR_UNSUPPORT;
    MMI_HILOGW("Pointer device does not support");
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetPointerStyle(int32_t windowId, int32_t pointerStyle)
{
    CALL_DEBUG_ENTER;
    if (windowId < 0 || pointerStyle < 0) {
        MMI_HILOGE("The param is invalid");
        return RET_ERR;
    }
    int32_t ret = MultimodalInputConnMgr->SetPointerStyle(windowId, pointerStyle);
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer style failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t InputManagerImpl::GetPointerStyle(int32_t windowId, int32_t &pointerStyle)
{
    CALL_DEBUG_ENTER;
    if (windowId < 0) {
        MMI_HILOGE("The param is invalid");
        return RET_ERR;
    }
    int32_t ret = MultimodalInputConnMgr->GetPointerStyle(windowId, pointerStyle);
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer style failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

void InputManagerImpl::OnConnected()
{
    CALL_DEBUG_ENTER;
    if (displayGroupInfo_.windowsInfo.empty() || displayGroupInfo_.displaysInfo.empty()) {
        MMI_HILOGI("The windows info or display info is empty");
        return;
    }
    SendDisplayInfo();
    PrintDisplayInfo();
    if (anrObservers_.empty()) {
        return;
    }
    int32_t ret = MultimodalInputConnMgr->SetAnrObserver();
    if (ret != RET_OK) {
        MMI_HILOGE("Set anr observerfailed, ret:%{public}d", ret);
    }
}

void InputManagerImpl::SendDisplayInfo()
{
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    if (PackDisplayData(pkt) == RET_ERR) {
        MMI_HILOGE("Pack display info failed");
        return;
    }
    if (!client->SendMessage(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
    }
}

int32_t InputManagerImpl::RegisterDevListener(std::string type, std::shared_ptr<IInputDeviceListener> listener)
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.RegisterDevListener(type, listener);
}

int32_t InputManagerImpl::UnregisterDevListener(std::string type,
    std::shared_ptr<IInputDeviceListener> listener)
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.UnregisterDevListener(type, listener);
}

int32_t InputManagerImpl::GetDeviceIds(std::function<void(std::vector<int32_t>&)> callback)
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.GetInputDeviceIdsAsync(callback);
}

int32_t InputManagerImpl::GetDevice(int32_t deviceId,
    std::function<void(std::shared_ptr<InputDevice>)> callback)
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.GetInputDeviceAsync(deviceId, callback);
}

int32_t InputManagerImpl::SupportKeys(int32_t deviceId, std::vector<int32_t> &keyCodes,
    std::function<void(std::vector<bool>&)> callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.SupportKeys(deviceId, keyCodes, callback);
}

int32_t InputManagerImpl::GetKeyboardType(int32_t deviceId, std::function<void(int32_t)> callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.GetKeyboardType(deviceId, callback);
}

void InputManagerImpl::SetAnrObserver(std::shared_ptr<IAnrObserver> observer)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return;
    }
    for (auto iter = anrObservers_.begin(); iter != anrObservers_.end(); ++iter) {
        if (*iter == observer) {
            MMI_HILOGE("Observer already exist");
            return;
        }
    }
    anrObservers_.push_back(observer);
    int32_t ret = MultimodalInputConnMgr->SetAnrObserver();
    if (ret != RET_OK) {
        MMI_HILOGE("Set anr observer failed, ret:%{public}d", ret);
    }
}

void InputManagerImpl::OnAnr(int32_t pid)
{
    CALL_DEBUG_ENTER;
    CHK_PID_AND_TID();
    {
        std::lock_guard<std::mutex> guard(mtx_);
        for (const auto &observer : anrObservers_) {
            CHKPC(observer);
            observer->OnAnr(pid);
        }
    }
    MMI_HILOGI("ANR noticed pid:%{public}d", pid);
}

int32_t InputManagerImpl::SetInputDevice(const std::string &dhid, const std::string &screenId)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetInputDevice(dhid, screenId);
    if (ret != RET_OK) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
    }
    return ret;
#else
    (void)(dhid);
    (void)(screenId);
    MMI_HILOGW("Enable input device cooperate does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

int32_t InputManagerImpl::RegisterCooperateListener(std::shared_ptr<IInputDeviceCooperateListener> listener)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("client init failed");
        return RET_ERR;
    }
    return InputDevCooperateImpl.RegisterCooperateListener(listener);
#else
    MMI_HILOGW("Cooperate does not support");
    (void)(listener);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

int32_t InputManagerImpl::UnregisterCooperateListener(std::shared_ptr<IInputDeviceCooperateListener> listener)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("client init failed");
        return RET_ERR;
    }
    return InputDevCooperateImpl.UnregisterCooperateListener(listener);
#else
    MMI_HILOGW("Cooperate does not support");
    (void)(listener);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

int32_t InputManagerImpl::EnableInputDeviceCooperate(bool enabled,
    std::function<void(std::string, CooperationMessage)> callback)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("client init failed");
        return RET_ERR;
    }
    return InputDevCooperateImpl.EnableInputDeviceCooperate(enabled, callback);
#else
    MMI_HILOGW("Cooperate does not support");
    (void)(enabled);
    (void)(callback);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

int32_t InputManagerImpl::StartInputDeviceCooperate(const std::string &sinkDeviceId, int32_t srcInputDeviceId,
    std::function<void(std::string, CooperationMessage)> callback)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("client init failed");
        return RET_ERR;
    }
    return InputDevCooperateImpl.StartInputDeviceCooperate(sinkDeviceId, srcInputDeviceId, callback);
#else
    MMI_HILOGW("Cooperate does not support");
    (void)(sinkDeviceId);
    (void)(srcInputDeviceId);
    (void)(callback);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

int32_t InputManagerImpl::StopDeviceCooperate(std::function<void(std::string, CooperationMessage)> callback)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("client init failed");
        return RET_ERR;
    }
    return InputDevCooperateImpl.StopDeviceCooperate(callback);
#else
    MMI_HILOGW("Cooperate does not support");
    (void)(callback);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

int32_t InputManagerImpl::GetInputDeviceCooperateState(const std::string &deviceId, std::function<void(bool)> callback)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("client init failed");
        return RET_ERR;
    }
    return InputDevCooperateImpl.GetInputDeviceCooperateState(deviceId, callback);
#else
    MMI_HILOGW("Cooperate does not support");
    (void)(deviceId);
    (void)(callback);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

bool InputManagerImpl::GetFunctionKeyState(int32_t funcKey)
{
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    CALL_DEBUG_ENTER;
    bool state { false };
    int32_t ret = MultimodalInputConnMgr->GetFunctionKeyState(funcKey, state);
    if (ret != RET_OK) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
    }
    return state;
#else
    MMI_HILOGW("Keyboard device does not support");
    return false;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

int32_t InputManagerImpl::SetFunctionKeyState(int32_t funcKey, bool enable)
{
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    CALL_DEBUG_ENTER;
    int32_t ret = MultimodalInputConnMgr->SetFunctionKeyState(funcKey, enable);
    if (ret != RET_OK) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
#else
    MMI_HILOGW("Keyboard device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}
} // namespace MMI
} // namespace OHOS
