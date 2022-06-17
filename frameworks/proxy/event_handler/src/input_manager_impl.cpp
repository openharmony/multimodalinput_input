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

#include "input_manager_impl.h"

#include <cinttypes>

#include "define_multimodal.h"
#include "error_multimodal.h"

#include "bytrace_adapter.h"
#include "define_interceptor_manager.h"
#include "event_filter_service.h"
#include "input_event_monitor_manager.h"
#include "mmi_client.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputManagerImpl" };
} // namespace

struct MonitorEventConsumer : public IInputEventConsumer {
    explicit MonitorEventConsumer(const std::function<void(std::shared_ptr<PointerEvent>)>& monitor)
        : monitor_ (monitor)
    {
    }

    explicit MonitorEventConsumer(const std::function<void(std::shared_ptr<KeyEvent>)>& monitor)
        : keyMonitor_ (monitor)
    {
    }

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

bool InputManagerImpl::InitEventHandler()
{
    CALL_LOG_ENTER;
    if (mmiEventHandler_ != nullptr) {
        MMI_HILOGE("Repeated initialization operations");
        return false;
    }

    std::mutex mtx;
    static constexpr int32_t timeout = 3;
    std::unique_lock <std::mutex> lck(mtx);
    ehThread_ = std::thread(std::bind(&InputManagerImpl::OnThread, this));
    ehThread_.detach();
    if (cv_.wait_for(lck, std::chrono::seconds(timeout)) == std::cv_status::timeout) {
        MMI_HILOGE("EventThandler thread start timeout");
        return false;
    }
    return true;
}

MMIEventHandlerPtr InputManagerImpl::GetEventHandler() const
{
    CHKPP(mmiEventHandler_);
    return mmiEventHandler_->GetSharedPtr();
}

EventHandlerPtr InputManagerImpl::GetCurrentEventHandler() const
{
    auto eventHandler = AppExecFwk::EventHandler::Current();
    if (eventHandler == nullptr) {
        eventHandler = GetEventHandler();
    }
    return eventHandler;
}

void InputManagerImpl::OnThread()
{
    CALL_LOG_ENTER;
    CHK_PIDANDTID();
    SetThreadName("mmi_client_EventHdr");
    mmiEventHandler_ = std::make_shared<MMIEventHandler>();
    CHKPV(mmiEventHandler_);
    auto eventRunner = mmiEventHandler_->GetEventRunner();
    CHKPV(eventRunner);
    cv_.notify_one();
    eventRunner->Run();
}

void InputManagerImpl::UpdateDisplayInfo(const DisplayGroupInfo &displayGroupInfo)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("get mmi client is nullptr");
        return;
    }
    if (displayGroupInfo.windowsInfo.empty() || displayGroupInfo.displaysInfo.empty()) {
        MMI_HILOGE("windows info or display info is empty!");
        return;
    }
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        if ((item.defaultHotAreas.size() > WindowInfo::MAX_HOTAREA_COUNT) ||
            (item.pointerHotAreas.size() > WindowInfo::MAX_HOTAREA_COUNT) ||
            item.defaultHotAreas.empty() || item.pointerHotAreas.empty()) {
            MMI_HILOGE("hot areas check failed! defaultHotAreas:size:%{public}zu,"
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
    CALL_LOG_ENTER;
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
            MMI_HILOGE("AddInputEventFilter has send to server fail, ret:%{public}d", ret);
            delete eventFilterService_;
            eventFilterService_ = nullptr;
            return RET_ERR;
        }
        MMI_HILOGI("AddInputEventFilter has send to server success");
        return RET_OK;
    }
    return RET_OK;
}

void InputManagerImpl::SetWindowInputEventConsumer(std::shared_ptr<IInputEventConsumer> inputEventConsumer,
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
{
    CALL_LOG_ENTER;
    CHKPV(inputEventConsumer);
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("client init failed");
        return;
    }
    consumer_ = inputEventConsumer;
    eventHandler_ = eventHandler;
    if (eventHandler_ == nullptr) {
        eventHandler_ = InputMgrImpl->GetCurrentEventHandler();
    }
}

void InputManagerImpl::OnKeyEventTask(std::shared_ptr<IInputEventConsumer> consumer,
    std::shared_ptr<KeyEvent> keyEvent)
{
    CHK_PIDANDTID();
    CHKPV(consumer);
    consumer->OnInputEvent(keyEvent);
    MMI_HILOGD("key event callback keyCode:%{public}d", keyEvent->GetKeyCode());
}

void InputManagerImpl::OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHK_PIDANDTID();
    CHKPV(keyEvent);
    CHKPV(eventHandler_);
    CHKPV(consumer_);
    std::lock_guard<std::mutex> guard(mtx_);
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::KEY_DISPATCH_EVENT);
    if (!MMIEventHandler::PostTask(eventHandler_,
        std::bind(&InputManagerImpl::OnKeyEventTask, this, consumer_, keyEvent))) {
        MMI_HILOGE("post task failed");
    }
    MMI_HILOGD("key event keyCode:%{public}d", keyEvent->GetKeyCode());
}

void InputManagerImpl::OnPointerEventTask(std::shared_ptr<IInputEventConsumer> consumer,
    std::shared_ptr<PointerEvent> pointerEvent)
{
    CHK_PIDANDTID();
    CHKPV(consumer);
    CHKPV(pointerEvent);
    consumer->OnInputEvent(pointerEvent);
    MMI_HILOGD("pointer event callback pointerId:%{public}d", pointerEvent->GetPointerId());
}

void InputManagerImpl::OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHK_PIDANDTID();
    CHKPV(pointerEvent);
    CHKPV(eventHandler_);
    CHKPV(consumer_);
    std::lock_guard<std::mutex> guard(mtx_);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::POINT_DISPATCH_EVENT);
    if (!MMIEventHandler::PostTask(eventHandler_,
        std::bind(&InputManagerImpl::OnPointerEventTask, this, consumer_, pointerEvent))) {
        MMI_HILOGE("post task failed");
    }
    MMI_HILOGD("pointer event pointerId:%{public}d", pointerEvent->GetPointerId());
}

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
    for (const auto& item : displayGroupInfo_.windowsInfo) {
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
    int32_t num = static_cast<int32_t>(displayGroupInfo_.displaysInfo.size());
    pkt << num;
    for (const auto& item : displayGroupInfo_.displaysInfo) {
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
    CHKPR(monitor, INVALID_HANDLER_ID);
    auto consumer = std::make_shared<MonitorEventConsumer>(monitor);
    CHKPR(consumer, INVALID_HANDLER_ID);
    return InputManagerImpl::AddMonitor(consumer);
}

int32_t InputManagerImpl::AddMonitor(std::function<void(std::shared_ptr<PointerEvent>)> monitor)
{
    CHKPR(monitor, INVALID_HANDLER_ID);
    auto consumer = std::make_shared<MonitorEventConsumer>(monitor);
    CHKPR(consumer, INVALID_HANDLER_ID);
    return InputManagerImpl::AddMonitor(consumer);
}

int32_t InputManagerImpl::AddMonitor(std::shared_ptr<IInputEventConsumer> consumer)
{
    CHKPR(consumer, INVALID_HANDLER_ID);
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("client init failed");
        return RET_ERR;
    }
    int32_t monitorId = monitorManager_.AddMonitor(consumer);
    return monitorId;
}

void InputManagerImpl::RemoveMonitor(int32_t monitorId)
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("client init failed");
        return;
    }
    monitorManager_.RemoveMonitor(monitorId);
}

void InputManagerImpl::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("client init failed");
        return;
    }
    monitorManager_.MarkConsumed(monitorId, eventId);
}

void InputManagerImpl::MoveMouse(int32_t offsetX, int32_t offsetY)
{
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    std::lock_guard<std::mutex> guard(mtx_);
    if (MMIEventHdl.MoveMouseEvent(offsetX, offsetY) != RET_OK) {
        MMI_HILOGE("Failed to inject move mouse offset event");
    }
#else
    MMI_HILOGW("Pointer drawing module does not support");
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
}

int32_t InputManagerImpl::AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor)
{
    CHKPR(interceptor, INVALID_HANDLER_ID);
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("client init failed");
        return RET_ERR;
    }
    return InputInterMgr->AddInterceptor(interceptor, HandleEventType::ALL);
}

int32_t InputManagerImpl::AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor)
{
    CHKPR(interceptor, INVALID_HANDLER_ID);
    std::lock_guard<std::mutex> guard(mtx_);
    auto consumer = std::make_shared<MonitorEventConsumer>(interceptor);
    CHKPR(consumer, INVALID_HANDLER_ID);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("client init failed");
        return RET_ERR;
    }
    return InputInterMgr->AddInterceptor(consumer, HandleEventType::KEY);
}

void InputManagerImpl::RemoveInterceptor(int32_t interceptorId)
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("client init failed");
        return;
    }
    InputInterMgr->RemoveInterceptor(interceptorId);
}

void InputManagerImpl::SimulateInputEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    std::lock_guard<std::mutex> guard(mtx_);
    if (MMIEventHdl.InjectEvent(keyEvent) != RET_OK) {
        MMI_HILOGE("Failed to inject keyEvent");
    }
}

void InputManagerImpl::SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    std::lock_guard<std::mutex> guard(mtx_);
    if (MMIEventHdl.InjectPointerEvent(pointerEvent) != RET_OK) {
        MMI_HILOGE("Failed to inject pointer event");
    }
}

int32_t InputManagerImpl::SetPointerVisible(bool visible)
{
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    CALL_LOG_ENTER;
    int32_t ret = MultimodalInputConnMgr->SetPointerVisible(visible);
    if (ret != RET_OK) {
        MMI_HILOGE("send to server fail, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer drawing module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
}

bool InputManagerImpl::IsPointerVisible()
{
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    CALL_LOG_ENTER;
    bool visible;
    int32_t ret = MultimodalInputConnMgr->IsPointerVisible(visible);
    if (ret != 0) {
        MMI_HILOGE("send to server fail, ret:%{public}d", ret);
    }
    return visible;
#else
    MMI_HILOGW("Pointer drawing module dose not support");
    return false;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
}

void InputManagerImpl::OnConnected()
{
    CALL_LOG_ENTER;
    if (displayGroupInfo_.windowsInfo.empty() || displayGroupInfo_.displaysInfo.empty()) {
        MMI_HILOGE("windows info or display info is empty");
        return;
    }
    SendDisplayInfo();
    PrintDisplayInfo();
}

void InputManagerImpl::SendDisplayInfo()
{
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    if (PackDisplayData(pkt) == RET_ERR) {
        MMI_HILOGE("pack display info failed");
        return;
    }
    if (!client->SendMessage(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
    }
}

void InputManagerImpl::SupportKeys(int32_t deviceId, std::vector<int32_t> &keyCodes,
    std::function<void(std::vector<bool>&)> callback)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("client init failed");
        return;
    }
    InputDevImpl.SupportKeys(deviceId, keyCodes, callback);
}

void InputManagerImpl::GetKeyboardType(int32_t deviceId, std::function<void(int32_t)> callback)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return;
    }
    InputDevImpl.GetKeyboardType(deviceId, callback);
}
} // namespace MMI
} // namespace OHOS
