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

#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
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
constexpr int32_t MASK_TOUCHPAD = 3;
constexpr int32_t ADD_MASK_BASE = 10;

struct PublicIInputEventConsumer : public IInputEventConsumer {
public:
    explicit PublicIInputEventConsumer(const std::function<void(std::shared_ptr<PointerEvent>)>& monitor)
    {
        if (monitor != nullptr) {
            monitor_ = monitor;
        }
    }

    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const { }
    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
    {
        if (monitor_ != nullptr) {
            monitor_(pointerEvent);
        }
    }

    void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const { }

private:
    std::function<void(std::shared_ptr<PointerEvent>)> monitor_;
};

void InputManagerImpl::UpdateDisplayInfo(const std::vector<PhysicalDisplayInfo> &physicalDisplays,
    const std::vector<LogicalDisplayInfo> &logicalDisplays)
{
    CALL_LOG_ENTER;
    if (physicalDisplays.empty() || logicalDisplays.empty()) {
        MMI_LOGE("display info check failed! physicalDisplays size:%{public}zu,logicalDisplays size:%{public}zu",
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
            MMI_LOGE("AddInputEventFilter has send to server fail, ret:%{public}d", ret);
            delete eventFilterService_;
            eventFilterService_ = nullptr;
            return RET_ERR;
        }
        MMI_LOGI("AddInputEventFilter has send to server success");
        return RET_OK;
    }
    return RET_OK;
}

void InputManagerImpl::SetWindowInputEventConsumer(std::shared_ptr<IInputEventConsumer> inputEventConsumer)
{
    CALL_LOG_ENTER;
    MMIEventHdl.GetMultimodeInputInfo();
    CHKPV(inputEventConsumer);
    consumer_ = inputEventConsumer;
}

void InputManagerImpl::OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_LOG_ENTER;
    CHKPV(keyEvent);
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::KEY_DISPATCH_EVENT);
    if (consumer_ != nullptr) {
        CHKPV(keyEvent);
        consumer_->OnInputEvent(keyEvent);
        return;
    }
}

void InputManagerImpl::OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Pointer event received, processing");
    CHKPV(pointerEvent);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::POINT_DISPATCH_EVENT);
    if (consumer_ != nullptr) {
        CHKPV(pointerEvent);
        MMI_LOGD("Passed on to consumer");
        consumer_->OnInputEvent(pointerEvent);
        return;
    }
}

int32_t InputManagerImpl::PackDisplayData(NetPacket &pkt)
{
    if (PackPhysicalDisplay(pkt) == RET_ERR) {
        MMI_LOGE("pack physical display failed");
        return RET_ERR;
    }
    return PackLogicalDisplay(pkt);
}

int32_t InputManagerImpl::PackPhysicalDisplay(NetPacket &pkt)
{
    uint32_t num = static_cast<uint32_t>(physicalDisplays_.size());
    if (!pkt.Write(num)) {
        MMI_LOGE("Packet write num failed");
        return RET_ERR;
    }
    for (uint32_t i = 0; i < num; i++) {
        if (!pkt.Write(physicalDisplays_[i].id)) {
            MMI_LOGE("Packet write physical data failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].leftDisplayId)) {
            MMI_LOGE("Packet write physical leftDisplay failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].upDisplayId)) {
            MMI_LOGE("Packet write physical upDisplay failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].topLeftX)) {
            MMI_LOGE("Packet write physical topLeftX failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].topLeftY)) {
            MMI_LOGE("Packet write physical topLeftY failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].width)) {
            MMI_LOGE("Packet write physical width failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].height)) {
            MMI_LOGE("Packet write physical height failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].name)) {
            MMI_LOGE("Packet write physical name failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].seatId)) {
            MMI_LOGE("Packet write physical seatId failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].seatName)) {
            MMI_LOGE("Packet write physical seatName failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].logicWidth)) {
            MMI_LOGE("Packet write physical logicWidth failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].logicHeight)) {
            MMI_LOGE("Packet write physical logicHeight failed");
            return RET_ERR;
        }
        if (!pkt.Write(physicalDisplays_[i].direction)) {
            MMI_LOGE("Packet write physical direction failed");
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t InputManagerImpl::PackLogicalDisplay(NetPacket &pkt)
{
    int32_t num = static_cast<int32_t>(logicalDisplays_.size());
    if (!pkt.Write(num)) {
        MMI_LOGE("Packet write logical num failed");
        return RET_ERR;
    }
    for (int32_t i = 0; i < num; i++) {
        if (!pkt.Write(logicalDisplays_[i].id)) {
            MMI_LOGE("Packet write logical data failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].topLeftX)) {
            MMI_LOGE("Packet write logical topLeftX failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].topLeftY)) {
            MMI_LOGE("Packet write logical topLeftY failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].width)) {
            MMI_LOGE("Packet write logical width failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].height)) {
            MMI_LOGE("Packet write logical height failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].name)) {
            MMI_LOGE("Packet write logical name failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].seatId)) {
            MMI_LOGE("Packet write logical seat failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].seatName)) {
            MMI_LOGE("Packet write logical seatName failed");
            return RET_ERR;
        }
        if (!pkt.Write(logicalDisplays_[i].focusWindowId)) {
            MMI_LOGE("Packet write logical focusWindow failed");
            return RET_ERR;
        }
        int32_t numWindow = static_cast<int32_t>(logicalDisplays_[i].windowsInfo.size());
        if (!pkt.Write(numWindow)) {
            MMI_LOGE("Packet write logical numWindow failed");
            return RET_ERR;
        }
        for (int32_t j = 0; j < numWindow; j++) {
            if (!pkt.Write(logicalDisplays_[i].windowsInfo[j])) {
                MMI_LOGE("Packet write logical windowsInfo failed");
                return RET_ERR;
            }
        }
    }
    return RET_OK;
}

void InputManagerImpl::PrintDisplayInfo()
{
    MMI_LOGD("physicalDisplays,num:%{public}zu", physicalDisplays_.size());
    for (const auto &item : physicalDisplays_) {
        MMI_LOGD("physicalDisplays,id:%{public}d,leftDisplay:%{public}d,upDisplay:%{public}d,"
            "topLeftX:%{public}d,topLeftY:%{public}d,width:%{public}d,height:%{public}d,"
            "name:%{public}s,seatId:%{public}s,seatName:%{public}s,logicWidth:%{public}d,"
            "logicHeight:%{public}d,direction:%{public}d",
            item.id, item.leftDisplayId, item.upDisplayId,
            item.topLeftX, item.topLeftY, item.width,
            item.height, item.name.c_str(), item.seatId.c_str(),
            item.seatName.c_str(), item.logicWidth, item.logicHeight,
            item.direction);
    }

    MMI_LOGD("logicalDisplays,num:%{public}zu", logicalDisplays_.size());
    for (const auto &item : logicalDisplays_) {
        MMI_LOGD("logicalDisplays, id:%{public}d,topLeftX:%{public}d,topLeftY:%{public}d,"
            "width:%{public}d,height:%{public}d,name:%{public}s,"
            "seatId:%{public}s,seatName:%{public}s,focusWindowId:%{public}d,window num:%{public}zu",
            item.id, item.topLeftX, item.topLeftY,
            item.width, item.height, item.name.c_str(),
            item.seatId.c_str(), item.seatName.c_str(),
            item.focusWindowId, item.windowsInfo.size());

        for (const auto &win : item.windowsInfo) {
            MMI_LOGD("windowid:%{public}d,pid:%{public}d,uid:%{public}d,hotZoneTopLeftX:%{public}d,"
                "hotZoneTopLeftY:%{public}d,hotZoneWidth:%{public}d,hotZoneHeight:%{public}d,display:%{public}d,"
                "agentWindowId:%{public}d,winTopLeftX:%{public}d,winTopLeftY:%{public}d",
                win.id, win.pid,
                win.uid, win.hotZoneTopLeftX,
                win.hotZoneTopLeftY, win.hotZoneWidth,
                win.hotZoneHeight, win.displayId,
                win.agentWindowId,
                win.winTopLeftX, win.winTopLeftY);
        }
    }
}

int32_t InputManagerImpl::AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor)
{
    CHKPR(monitor, ERROR_NULL_POINTER);
    int32_t monitorId = InputMonitorMgr.AddInputEventMontior(monitor);
    monitorId = monitorId * ADD_MASK_BASE + MASK_KEY;
    return monitorId;
}

int32_t InputManagerImpl::AddMontior(std::function<void(std::shared_ptr<PointerEvent>)> monitor)
{
    CHKPR(monitor, ERROR_NULL_POINTER);
    std::shared_ptr<IInputEventConsumer> consumer =
        std::make_shared<PublicIInputEventConsumer>(monitor);
    return InputManagerImpl::AddMonitor(consumer);
}

int32_t InputManagerImpl::AddMonitor(std::shared_ptr<IInputEventConsumer> consumer)
{
    CHKPR(consumer, ERROR_NULL_POINTER);
    int32_t monitorId = monitorManager_.AddMonitor(consumer);
    monitorId = monitorId * ADD_MASK_BASE + MASK_TOUCH;
    return monitorId;
}

void InputManagerImpl::RemoveMonitor(int32_t monitorId)
{
    int32_t mask = monitorId % ADD_MASK_BASE;
    monitorId /= ADD_MASK_BASE;

    switch (mask) {
        case MASK_KEY:
            InputMonitorMgr.RemoveInputEventMontior(monitorId);
            break;
        case MASK_TOUCH:
            monitorManager_.RemoveMonitor(monitorId);
            break;
        case MASK_TOUCHPAD:
            InputMonitorMgr.RemoveInputEventTouchpadMontior(monitorId);
            break;
        default:
            MMI_LOGE("Can't find the mask, mask:%{public}d", mask);
            break;
    }
}

void InputManagerImpl::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    monitorManager_.MarkConsumed(monitorId, eventId);
}

int32_t InputManagerImpl::AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor)
{
    CHKPR(interceptor, INVALID_HANDLER_ID);
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
    if (interceptor == nullptr) {
        MMI_LOGE("%{public}s param should not be null", __func__);
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
    if (interceptorId <= 0) {
        MMI_LOGE("Specified interceptor does not exist");
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
            MMI_LOGE("Can't find the mask, mask:%{public}d", mask);
            break;
    }
}

void InputManagerImpl::SimulateInputEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    if (MMIEventHdl.InjectEvent(keyEvent) != RET_OK) {
        MMI_LOGE("Failed to inject keyEvent");
    }
}

void InputManagerImpl::SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (MultimodalEventHandler::GetInstance().InjectPointerEvent(pointerEvent) != RET_OK) {
        MMI_LOGE("Failed to inject pointer event");
    }
}

void InputManagerImpl::OnConnected()
{
    CALL_LOG_ENTER;
    if (physicalDisplays_.empty() || logicalDisplays_.empty()) {
        MMI_LOGE("display info check failed! physicalDisplays_ size:%{public}zu,logicalDisplays_ size:%{public}zu",
            physicalDisplays_.size(), logicalDisplays_.size());
        return;
    }
    SendDisplayInfo();
    PrintDisplayInfo();
}

void InputManagerImpl::SendDisplayInfo()
{
    if (MultimodalEventHandler::GetInstance().GetMMIClient() == nullptr) {
        MMI_LOGE("get mmi client is nullptr");
        return;
    }

    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    if (PackDisplayData(pkt) == RET_ERR) {
        MMI_LOGE("pack display info failed");
        return;
    }
    MultimodalEventHandler::GetInstance().GetMMIClient()->SendMessage(pkt);
}
} // namespace MMI
} // namespace OHOS
