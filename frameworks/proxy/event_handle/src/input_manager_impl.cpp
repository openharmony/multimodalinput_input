/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "bytrace.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "event_filter_service.h"
#include "input_event_monitor_manager.h"
#include "input_monitor_manager.h"
#include "interceptor_manager.h"
#include "mmi_client.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

namespace OHOS {
namespace MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputManagerImpl" };
}

constexpr int32_t MASK_KEY = 1;
constexpr int32_t MASK_TOUCH = 2;
constexpr int32_t MASK_TOUCHPAD = 3;
constexpr int32_t ADD_MASK_BASE = 10;

void InputManagerImpl::UpdateDisplayInfo(const std::vector<PhysicalDisplayInfo> &physicalDisplays,
    const std::vector<LogicalDisplayInfo> &logicalDisplays)
{
    MMI_LOGD("InputManagerImpl::UpdateDisplayInfo enter!");
    if (physicalDisplays.size() == 0 || logicalDisplays.size() == 0) {
        MMI_LOGE("display info check failed! physicalDisplays size is %{public}d, logicalDisplays size is %{public}d",
            static_cast<int32_t>(physicalDisplays.size()), static_cast<int32_t>(logicalDisplays.size()));
        return;
    }

    physicalDisplays_ = physicalDisplays;
    logicalDisplays_ = logicalDisplays;
    PrintDisplayDebugInfo();

    if (MultimodalEventHandler::GetInstance().GetMMIClient()) {
        OHOS::MMI::NetPacket ckt(MmiMessageId::DISPLAY_INFO);
        if (PackDisplayData(ckt) == RET_ERR) {
            MMI_LOGE("pack display info failed");
            return;
        }
        MultimodalEventHandler::GetInstance().GetMMIClient()->SendMessage(ckt);
    } else {
        MMI_LOGE("GetMMIClient is failed");
    }

    MMI_LOGD("InputManagerImpl::UpdateDisplayInfo leave!");
}

int32_t InputManagerImpl::AddInputEventFilter(std::function<bool(std::shared_ptr<PointerEvent>)> filter)
{
    MMI_LOGT("enter");
    if (eventFilterService_ == nullptr) {
        eventFilterService_ = new EventFilterService();
        MMI_LOGD("new EventFilterService");
    }

    if (eventFilterService_ == nullptr) {
        MMI_LOGE("eventFilterService_ is nullptr");
        return RET_ERR;
    }

    eventFilterService_->SetPointerEventPtr(filter);

    static bool hasSendToMmiServer = false;
    if (!hasSendToMmiServer) {
        int32_t ret = MultimodalInputConnectManager::GetInstance()->AddInputEventFilter(eventFilterService_);
        if (ret == RET_OK) {
            hasSendToMmiServer = true;
            MMI_LOGI("AddInputEventFilter has send to server success");
            return RET_OK;
        } else {
            MMI_LOGE("AddInputEventFilter has send to server fail, ret = %{public}d", ret);
            return RET_ERR;
        }        
    }

    MMI_LOGT("leave, success with hasSendToMmiServer is already true");
    return RET_OK;
}

void InputManagerImpl::SetWindowInputEventConsumer(std::shared_ptr<OHOS::MMI::IInputEventConsumer> inputEventConsumer)
{
    MMI_LOGD("enter");
    MMIEventHdl.GetMultimodeInputInfo();
    CHK(inputEventConsumer, ERROR_NULL_POINTER);
    consumer = inputEventConsumer;
    MMI_LOGD("leave");
}

void InputManagerImpl::OnKeyEvent(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
{
    MMI_LOGD("enter");
    int32_t getKeyCode = keyEvent->GetKeyCode();
    std::string keyCodestring = std::to_string(getKeyCode);
    MMI_LOGT("\n OnKeyEvent client trace getKeyCode = %{public}s\n", keyCodestring.c_str());
    int32_t EVENT_KEY = 1;
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyCodestring, EVENT_KEY);
    if (consumer != nullptr) {
        CHK(keyEvent != nullptr, ERROR_NULL_POINTER);
        consumer->OnInputEvent(keyEvent);
        MMI_LOGD("leave");
        return;
    }
    MMI_LOGD("consumer is null");
}

void InputManagerImpl::OnPointerEvent(std::shared_ptr<OHOS::MMI::PointerEvent> pointerEvent)
{
    MMI_LOGD("Pointer event received, processing ...");
    if (consumer != nullptr) {
        CHK(pointerEvent != nullptr, ERROR_NULL_POINTER);
        MMI_LOGD("Passed on to consumer ...");
        consumer->OnInputEvent(pointerEvent);
        return;
    }

    MMI_LOGD("No comsumer respond, let it go.");
}

int32_t InputManagerImpl::PackDisplayData(OHOS::MMI::NetPacket &ckt)
{
    if (PackPhysicalDisplay(ckt) == RET_ERR) {
        MMI_LOGE("pack physical display failed");
        return RET_ERR;
    }
    return PackLogicalDisplay(ckt);
}

int32_t InputManagerImpl::PackPhysicalDisplay(NetPacket &ckt)
{
    int32_t num = physicalDisplays_.size();
    CHKR(ckt.Write(num), STREAM_BUF_WRITE_FAIL, RET_ERR);
    for (int32_t i = 0; i < num; i++) {
        CHKR(ckt.Write(physicalDisplays_[i].id), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(physicalDisplays_[i].leftDisplayId), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(physicalDisplays_[i].upDisplayId), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(physicalDisplays_[i].topLeftX), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(physicalDisplays_[i].topLeftY), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(physicalDisplays_[i].width), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(physicalDisplays_[i].height), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(physicalDisplays_[i].name), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(physicalDisplays_[i].seatId), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(physicalDisplays_[i].seatName), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(physicalDisplays_[i].logicWidth), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(physicalDisplays_[i].logicHeight), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(physicalDisplays_[i].direction), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    return RET_OK;
}

int32_t InputManagerImpl::PackLogicalDisplay(NetPacket &ckt)
{
    int32_t num = logicalDisplays_.size();
    CHKR(ckt.Write(num), STREAM_BUF_WRITE_FAIL, RET_ERR);
    for (int32_t i = 0; i < num; i++) {
        CHKR(ckt.Write(logicalDisplays_[i].id), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(logicalDisplays_[i].topLeftX), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(logicalDisplays_[i].topLeftY), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(logicalDisplays_[i].width), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(logicalDisplays_[i].height), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(logicalDisplays_[i].name), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(logicalDisplays_[i].seatId), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(logicalDisplays_[i].seatName), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(ckt.Write(logicalDisplays_[i].focusWindowId), STREAM_BUF_WRITE_FAIL, RET_ERR);
        int32_t numWindow = logicalDisplays_[i].windowsInfo_.size();
        CHKR(ckt.Write(numWindow), STREAM_BUF_WRITE_FAIL, RET_ERR);
        for (int32_t j = 0; j < numWindow; j++) {
            CHKR(ckt.Write(logicalDisplays_[i].windowsInfo_[j]), STREAM_BUF_WRITE_FAIL, RET_ERR);
        }
    }
    return RET_OK;
}

void InputManagerImpl::PrintDisplayDebugInfo()
{
    MMI_LOGD("physicalDisplays,num:%{public}d", static_cast<int32_t>(physicalDisplays_.size()));
    for (int32_t i = 0; i < static_cast<int32_t>(physicalDisplays_.size()); i++) {
        MMI_LOGD("physicalDisplays,id:%{public}d, leftDisplayId:%{public}d, upDisplayId:%{public}d, "
            "topLeftX:%{public}d, topLeftY:%{public}d, width:%{public}d,height:%{public}d,name:%{public}s,"
            "seatId:%{public}s, seatName:%{public}s, logicWidth:%{public}d, logicHeight:%{public}d, "
            "direction:%{public}d",
            physicalDisplays_[i].id, physicalDisplays_[i].leftDisplayId, physicalDisplays_[i].upDisplayId,
            physicalDisplays_[i].topLeftX, physicalDisplays_[i].topLeftY, physicalDisplays_[i].width,
            physicalDisplays_[i].height, physicalDisplays_[i].name.c_str(), physicalDisplays_[i].seatId.c_str(),
            physicalDisplays_[i].seatName.c_str(), physicalDisplays_[i].logicWidth, physicalDisplays_[i].logicHeight,
            physicalDisplays_[i].direction);
    }

    MMI_LOGD("logicalDisplays,num:%{public}d", static_cast<int32_t>(logicalDisplays_.size()));
    for (int32_t i = 0; i < static_cast<int32_t>(logicalDisplays_.size()); i++) {
        MMI_LOGD("logicalDisplays, id:%{public}d,topLeftX:%{public}d, topLeftY:%{public}d, "
            "width:%{public}d,height:%{public}d,name:%{public}s,"
            "seatId:%{public}s, seatName:%{public}s,focusWindowId:%{public}d,window num:%{public}d",
            logicalDisplays_[i].id, logicalDisplays_[i].topLeftX, logicalDisplays_[i].topLeftY,
            logicalDisplays_[i].width, logicalDisplays_[i].height, logicalDisplays_[i].name.c_str(),
            logicalDisplays_[i].seatId.c_str(), logicalDisplays_[i].seatName.c_str(),
            logicalDisplays_[i].focusWindowId, static_cast<int32_t>(logicalDisplays_[i].windowsInfo_.size()));

        for (int32_t j = 0; j < static_cast<int32_t>(logicalDisplays_[i].windowsInfo_.size()); j++) {
            MMI_LOGD("windowid:%{public}d, pid:%{public}d,uid:%{public}d,topLeftX:%{public}d,"
                "topLeftY:%{public}d,width:%{public}d,height:%{public}d,displayId:%{public}d,agentWindowId:%{public}d,",
                logicalDisplays_[i].windowsInfo_[j].id, logicalDisplays_[i].windowsInfo_[j].pid,
                logicalDisplays_[i].windowsInfo_[j].uid, logicalDisplays_[i].windowsInfo_[j].topLeftX,
                logicalDisplays_[i].windowsInfo_[j].topLeftY, logicalDisplays_[i].windowsInfo_[j].width,
                logicalDisplays_[i].windowsInfo_[j].height, logicalDisplays_[i].windowsInfo_[j].displayId,
                logicalDisplays_[i].windowsInfo_[j].agentWindowId);
        }
    }
}

int32_t InputManagerImpl::AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor)
{
    if (monitor == nullptr) {
        MMI_LOGE("InputManagerImpl::%{public}s param should not be null!", __func__);
        return OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER;
    }
    int32_t monitorId = IEMManager.AddInputEventMontior(monitor);
    monitorId = monitorId * ADD_MASK_BASE + MASK_KEY;
    return monitorId;
}

int32_t InputManagerImpl::AddMontior(std::function<void(std::shared_ptr<PointerEvent>)> monitor)
{
    if (monitor == nullptr) {
        MMI_LOGE("InputManagerImpl::%{public}s param should not be null!", __func__);
        return InputEventMonitorManager::INVALID_MONITOR_ID;
    }
    int32_t monitorId = IEMManager.AddInputEventTouchpadMontior(monitor);
    monitorId = monitorId * ADD_MASK_BASE + MASK_TOUCHPAD;
    return monitorId;
}

int32_t InputManagerImpl::AddMonitor(std::shared_ptr<IInputEventConsumer> consumer)
{
    int32_t monitorId = InputMonitorManager::GetInstance().AddMonitor(consumer);
    monitorId = monitorId * ADD_MASK_BASE + MASK_TOUCH;
    return monitorId;
}

void InputManagerImpl::RemoveMonitor(int32_t monitorId)
{
    int32_t mask = monitorId % ADD_MASK_BASE;
    monitorId /= ADD_MASK_BASE;

    switch (mask) {
        case MASK_KEY:
            IEMManager.RemoveInputEventMontior(monitorId);
            break;
        case MASK_TOUCH:
            InputMonitorManager::GetInstance().RemoveMonitor(monitorId);
            break;
        case MASK_TOUCHPAD:
            IEMManager.RemoveInputEventTouchpadMontior(monitorId);
            break;
        default:
        MMI_LOGE("Can't find the mask,mask%{public}d", mask);
            break;
    }    
}

void InputManagerImpl::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    InputMonitorManager::GetInstance().MarkConsumed(monitorId, eventId);
}

int32_t InputManagerImpl::AddInterceptor(int32_t sourceType, 
                                         std::function<void(std::shared_ptr<PointerEvent>)> interceptor)
{
    if (interceptor == nullptr) {
        MMI_LOGE("AddInterceptor::%{public}s param should not be null!", __func__);
        return InterceptorManager::INVALID_INTERCEPTOR_ID;
    }
    return INTERCEPTORMANAGER.AddInterceptor(sourceType, interceptor);
}

int32_t InputManagerImpl::AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor)
{
    if (interceptor == nullptr) {
        MMI_LOGE("AddInterceptor::%{public}s param should not be null!", __func__);
        return OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER;
    }
    return INTERCEPTORMANAGER.AddInterceptor(interceptor);
}

void InputManagerImpl::RemoveInterceptor(int32_t interceptorId)
{
    INTERCEPTORMANAGER.RemoveInterceptor(interceptorId);
}

void InputManagerImpl::SimulateInputEvent(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
{
    if (MMIEventHdl.InjectEvent(keyEvent) != RET_OK) {
        MMI_LOGE("Failed to inject keyEvent!");
    }
}
}
}
