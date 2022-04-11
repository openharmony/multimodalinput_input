/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "input_manager_impl.h"

#include <cinttypes>

#include "define_multimodal.h"
#include "error_multimodal.h"

#include "bytrace_adapter.h"
#include "event_filter_service.h"
#include "input_event_monitor_manager.h"
#include "interceptor_manager.h"
#include "mmi_client.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputManagerImpl" };
} // namespace

constexpr int32_t MASK_KEY = 1;
constexpr int32_t MASK_TOUCH = 2;
constexpr int32_t ADD_MASK_BASE = 10;

struct MonitorEventConsumer : public IInputEventConsumer {
public:
    explicit MonitorEventConsumer(const std::function<void(std::shared_ptr<PointerEvent>)>& monitor)
    {
        if (monitor != nullptr) {
            monitor_ = monitor;
        }
    }

    explicit MonitorEventConsumer(const std::function<void(std::shared_ptr<KeyEvent>)>& monitor)
    {
        if (monitor != nullptr) {
            keyMonitor_ = monitor;
        }
    }

    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const
    {
        if (keyMonitor_ != nullptr) {
            keyMonitor_(keyEvent);
        }
    }

    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
    {
        if (monitor_ != nullptr) {
            monitor_(pointerEvent);
        }
    }

    void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const { }

private:
    std::function<void(std::shared_ptr<PointerEvent>)> monitor_;
    std::function<void(std::shared_ptr<KeyEvent>)> keyMonitor_;
};

bool InputManagerImpl::InitEventHandler()
{
    CALL_LOG_ENTER;
    if (mmiEventHandler_ != nullptr) {
        MMI_HILOGE("Repeated initialization operations");
        return false;
    }

    std::mutex mtx;
    constexpr int32_t timeout = 3;
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

void InputManagerImpl::UpdateDisplayInfo(const std::vector<PhysicalDisplayInfo> &physicalDisplays,
    const std::vector<LogicalDisplayInfo> &logicalDisplays)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.StartClient()) {
        MMI_HILOGE("get mmi client is nullptr");
        return;
    }
    if (physicalDisplays.empty() || logicalDisplays.empty()) {
        MMI_HILOGE("display info check failed! physicalDisplays size:%{public}zu,logicalDisplays size:%{public}zu",
            physicalDisplays.size(), logicalDisplays.size());
        return;
    }
    physicalDisplays_ = physicalDisplays;
    logicalDisplays_ = logicalDisplays;
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
        int32_t ret = MultimodalInputConnectManager::GetInstance()->AddInputEventFilter(eventFilterService_);
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

void InputManagerImpl::SetWindowInputEventConsumer(std::shared_ptr<IInputEventConsumer> inputEventConsumer)
{
    CALL_LOG_ENTER;
    CHKPV(inputEventConsumer);
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.StartClient()) {
        MMI_HILOGE("client init failed");
        return;
    }
    consumer_ = inputEventConsumer;
    eventHandler_ = InputMgrImpl->GetCurrentEventHandler();
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
    if (PackPhysicalDisplay(pkt) == RET_ERR) {
        MMI_HILOGE("pack physical display failed");
        return RET_ERR;
    }
    return PackLogicalDisplay(pkt);
}

int32_t InputManagerImpl::PackPhysicalDisplay(NetPacket &pkt)
{
    uint32_t num = static_cast<uint32_t>(physicalDisplays_.size());
    if (!pkt.Write(num)) {
        MMI_HILOGE("Packet write num failed");
        return RET_ERR;
    }
    for (uint32_t i = 0; i < num; i++) {
        if (!pkt.Write(physicalDisplays_[i].id)) {
            MMI_HILOGE("Packet write physical data failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].leftDisplayId)) {
            MMI_HILOGE("Packet write physical leftDisplay failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].upDisplayId)) {
            MMI_HILOGE("Packet write physical upDisplay failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].topLeftX)) {
            MMI_HILOGE("Packet write physical topLeftX failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].topLeftY)) {
            MMI_HILOGE("Packet write physical topLeftY failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].width)) {
            MMI_HILOGE("Packet write physical width failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].height)) {
            MMI_HILOGE("Packet write physical height failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].name)) {
            MMI_HILOGE("Packet write physical name failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].seatId)) {
            MMI_HILOGE("Packet write physical seatId failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].seatName)) {
            MMI_HILOGE("Packet write physical seatName failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].logicWidth)) {
            MMI_HILOGE("Packet write physical logicWidth failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].logicHeight)) {
            MMI_HILOGE("Packet write physical logicHeight failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].direction)) {
            MMI_HILOGE("Packet write physical direction failed");
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t InputManagerImpl::PackLogicalDisplay(NetPacket &pkt)
{
    int32_t num = static_cast<int32_t>(logicalDisplays_.size());
    if (!pkt.Write(num)) {
        MMI_HILOGE("Packet write logical num failed");
        return RET_ERR;
    }
    for (int32_t i = 0; i < num; i++) {
        if (!pkt.Write(logicalDisplays_[i].id)) {
            MMI_HILOGE("Packet write logical data failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].topLeftX)) {
            MMI_HILOGE("Packet write logical topLeftX failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].topLeftY)) {
            MMI_HILOGE("Packet write logical topLeftY failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].width)) {
            MMI_HILOGE("Packet write logical width failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].height)) {
            MMI_HILOGE("Packet write logical height failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].name)) {
            MMI_HILOGE("Packet write logical name failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].seatId)) {
            MMI_HILOGE("Packet write logical seat failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].seatName)) {
            MMI_HILOGE("Packet write logical seatName failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].focusWindowId)) {
            MMI_HILOGE("Packet write logical focusWindow failed");
            return RET_ERR;
        }
        int32_t numWindow = static_cast<int32_t>(logicalDisplays_[i].windowsInfo.size());
        if (!pkt.Write(numWindow)) {
            MMI_HILOGE("Packet write logical numWindow failed");
            return RET_ERR;
        }
        for (int32_t j = 0; j < numWindow; j++) {
            if (!pkt.Write(logicalDisplays_[i].windowsInfo[j])) {
                MMI_HILOGE("Packet write logical windowsInfo failed");
                return RET_ERR;
            }
        }
    }
    return RET_OK;
}

void InputManagerImpl::PrintDisplayInfo()
{
    MMI_HILOGD("physicalDisplays,num:%{public}zu", physicalDisplays_.size());
    for (const auto &item : physicalDisplays_) {
        MMI_HILOGD("physicalDisplays,id:%{public}d,leftDisplay:%{public}d,upDisplay:%{public}d,"
            "topLeftX:%{public}d,topLeftY:%{public}d,width:%{public}d,height:%{public}d,"
            "name:%{public}s,seatId:%{public}s,seatName:%{public}s,logicWidth:%{public}d,"
            "logicHeight:%{public}d,direction:%{public}d",
            item.id, item.leftDisplayId, item.upDisplayId,
            item.topLeftX, item.topLeftY, item.width,
            item.height, item.name.c_str(), item.seatId.c_str(),
            item.seatName.c_str(), item.logicWidth, item.logicHeight,
            item.direction);
    }

    MMI_HILOGD("logicalDisplays,num:%{public}zu", logicalDisplays_.size());
    for (const auto &item : logicalDisplays_) {
        MMI_HILOGD("logicalDisplays, id:%{public}d,topLeftX:%{public}d,topLeftY:%{public}d,"
            "width:%{public}d,height:%{public}d,name:%{public}s,"
            "seatId:%{public}s,seatName:%{public}s,focusWindowId:%{public}d,window num:%{public}zu",
            item.id, item.topLeftX, item.topLeftY,
            item.width, item.height, item.name.c_str(),
            item.seatId.c_str(), item.seatName.c_str(),
            item.focusWindowId, item.windowsInfo.size());
        for (const auto &win : item.windowsInfo) {
            MMI_HILOGD("windowid:%{public}d,pid:%{public}d,uid:%{public}d,hotZoneTopLeftX:%{public}d,"
                "hotZoneTopLeftY:%{public}d,hotZoneWidth:%{public}d,hotZoneHeight:%{public}d,display:%{public}d,"
                "agentWindowId:%{public}d,winTopLeftX:%{public}d,winTopLeftY:%{public}d,flags:%{public}d",
                win.id, win.pid,
                win.uid, win.hotZoneTopLeftX,
                win.hotZoneTopLeftY, win.hotZoneWidth,
                win.hotZoneHeight, win.displayId,
                win.agentWindowId,
                win.winTopLeftX, win.winTopLeftY, win.flags);
        }
    }
}

int32_t InputManagerImpl::AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor)
{
    CHKPR(monitor, ERROR_NULL_POINTER);
    std::lock_guard<std::mutex> guard(mtx_);
    auto consumer = std::make_shared<MonitorEventConsumer>(monitor);
    CHKPR(consumer, ERROR_NULL_POINTER);
    return InputManagerImpl::AddMonitor(consumer);
}

int32_t InputManagerImpl::AddMonitor(std::function<void(std::shared_ptr<PointerEvent>)> monitor)
{
    CHKPR(monitor, ERROR_NULL_POINTER);
    std::lock_guard<std::mutex> guard(mtx_);
    auto consumer = std::make_shared<MonitorEventConsumer>(monitor);
    CHKPR(consumer, ERROR_NULL_POINTER);
    return InputManagerImpl::AddMonitor(consumer);
}

int32_t InputManagerImpl::AddMonitor(std::shared_ptr<IInputEventConsumer> consumer)
{
    CHKPR(consumer, ERROR_NULL_POINTER);
    int32_t monitorId = monitorManager_.AddMonitor(consumer);
    return monitorId;
}

void InputManagerImpl::RemoveMonitor(int32_t monitorId)
{
    std::lock_guard<std::mutex> guard(mtx_);
    monitorManager_.RemoveMonitor(monitorId);
}

void InputManagerImpl::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    std::lock_guard<std::mutex> guard(mtx_);
    monitorManager_.MarkConsumed(monitorId, eventId);
}

int32_t InputManagerImpl::AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor)
{
    CHKPR(interceptor, INVALID_HANDLER_ID);
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t interceptorId = interceptorManager_.AddInterceptor(interceptor);
    if (interceptorId >= 0) {
        interceptorId = interceptorId * ADD_MASK_BASE + MASK_TOUCH;
    }
    return interceptorId;
}

int32_t InputManagerImpl::AddInterceptor(int32_t sourceType,
                                         std::function<void(std::shared_ptr<PointerEvent>)> interceptor)
{
    return -1;
}

int32_t InputManagerImpl::AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor)
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (interceptor == nullptr) {
        MMI_HILOGE("%{public}s param should not be null", __func__);
        return MMI_STANDARD_EVENT_INVALID_PARAM;
    }
    int32_t interceptorId = InterceptorMgr.AddInterceptor(interceptor);
    if (interceptorId >= 0) {
        interceptorId = interceptorId * ADD_MASK_BASE + MASK_KEY;
    }
    return interceptorId;
}

void InputManagerImpl::RemoveInterceptor(int32_t interceptorId)
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (interceptorId <= 0) {
        MMI_HILOGE("Specified interceptor does not exist");
        return;
    }
    int32_t mask = interceptorId % ADD_MASK_BASE;
    interceptorId /= ADD_MASK_BASE;
    switch (mask) {
        case MASK_TOUCH:
            interceptorManager_.RemoveInterceptor(interceptorId);
            break;
        case MASK_KEY:
            InterceptorMgr.RemoveInterceptor(interceptorId);
            break;
        default:
            MMI_HILOGE("Can't find the mask, mask:%{public}d", mask);
            break;
    }
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

void InputManagerImpl::OnConnected()
{
    CALL_LOG_ENTER;
    if (physicalDisplays_.empty() || logicalDisplays_.empty()) {
        MMI_HILOGE("display info check failed! physicalDisplays_ size:%{public}zu,logicalDisplays_ size:%{public}zu",
            physicalDisplays_.size(), logicalDisplays_.size());
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
} // namespace MMI
} // namespace OHOS
