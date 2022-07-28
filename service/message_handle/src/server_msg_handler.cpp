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

#include "server_msg_handler.h"

#include <cinttypes>

#include "event_dump.h"
#include "event_package.h"
#include "hos_key_event.h"
#include "interceptor_handler_global.h"
#include "input_device_manager.h"
#include "input_event.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "input_handler_manager_global.h"
#include "input_windows_manager.h"
#include "key_event_subscriber.h"
#include "mmi_func_callback.h"
#include "time_cost_chk.h"
#include "mouse_event_handler.h"
#ifdef OHOS_BUILD_HDF
#include "hdi_inject.h"
#endif

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ServerMsgHandler" };
} // namespace

ServerMsgHandler::ServerMsgHandler() {}

ServerMsgHandler::~ServerMsgHandler() {}

void ServerMsgHandler::Init(UDSServer& udsServer)
{
    udsServer_ = &udsServer;
#ifdef OHOS_BUILD_HDF
    if (!(MMIHdiInject->Init(udsServer))) {
        MMI_HILOGE("Input device initialization failed");
        return;
    }
#endif
    MsgCallback funs[] = {
        {MmiMessageId::MARK_PROCESS, MsgCallbackBind2(&ServerMsgHandler::MarkProcessed, this)},
        {MmiMessageId::DISPLAY_INFO, MsgCallbackBind2(&ServerMsgHandler::OnDisplayInfo, this)},
#ifdef OHOS_BUILD_MMI_DEBUG
        {MmiMessageId::BIGPACKET_TEST, MsgCallbackBind2(&ServerMsgHandler::OnBigPacketTest, this)},
#endif // OHOS_BUILD_MMI_DEBUG
#ifdef OHOS_BUILD_HDF
        {MmiMessageId::HDI_INJECT, MsgCallbackBind2(&ServerMsgHandler::OnHdiInject, this)},
#endif // OHOS_BUILD_HDF
    };
    for (auto& it : funs) {
        if (!RegistrationEvent(it)) {
            MMI_HILOGW("Failed to register event errCode:%{public}d", EVENT_REG_FAIL);
            continue;
        }
    }
}

void ServerMsgHandler::OnMsgHandler(SessionPtr sess, NetPacket& pkt)
{
    CHKPV(sess);
    auto id = pkt.GetMsgId();
    TimeCostChk chk("ServerMsgHandler::OnMsgHandler", "overtime 300(us)", MAX_OVER_TIME, id);
    auto callback = GetMsgCallback(id);
    if (callback == nullptr) {
        MMI_HILOGE("Unknown msg id:%{public}d,errCode:%{public}d", id, UNKNOWN_MSG_ID);
        return;
    }
    auto ret = (*callback)(sess, pkt);
    if (ret < 0) {
        MMI_HILOGE("Msg handling failed. id:%{public}d,errCode:%{public}d", id, ret);
    }
}

#ifdef OHOS_BUILD_HDF
int32_t ServerMsgHandler::OnHdiInject(SessionPtr sess, NetPacket& pkt)
{
    MMI_HILOGI("Hdfinject server access hditools info");
    CHKPR(sess, ERROR_NULL_POINTER);
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    const int32_t processingCode = MMIHdiInject->ManageHdfInject(sess, pkt);
    NetPacket pkt(MmiMessageId::HDI_INJECT);
    pkt << processingCode;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write reply message failed");
        return RET_ERR;
    }
    if (!sess->SendMsg(pkt)) {
        MMI_HILOGE("OnHdiInject reply message error");
        return RET_ERR;
    }
    return RET_OK;
}
#endif // OHOS_BUILD_HDF

int32_t ServerMsgHandler::MarkProcessed(SessionPtr sess, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t eventId = 0;
    int32_t eventType = 0;
    pkt >> eventId >> eventType;
    MMI_HILOGD("event is: %{public}d", eventId);
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read data failed");
        return PACKET_READ_FAIL;
    }
    sess->DelEvents(eventType, eventId);
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t ServerMsgHandler::OnInjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_INFO_TRACE;
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    auto inputEventNormalizeHandler = InputHandler->GetInputEventNormalizeHandler();
    CHKPR(inputEventNormalizeHandler, ERROR_NULL_POINTER);
    inputEventNormalizeHandler->HandleKeyEvent(keyEvent);
    MMI_HILOGD("Inject keyCode:%{public}d, action:%{public}d", keyEvent->GetKeyCode(), keyEvent->GetKeyAction());
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
int32_t ServerMsgHandler::OnInjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_INFO_TRACE;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    pointerEvent->UpdateId();
    int32_t action = pointerEvent->GetPointerAction();
    if ((action == PointerEvent::POINTER_ACTION_MOVE || action == PointerEvent::POINTER_ACTION_UP)
        && targetWindowId_ > 0) {
        pointerEvent->SetTargetWindowId(targetWindowId_);
        PointerEvent::PointerItem pointerItem;
        auto pointerIds = pointerEvent->GetPointerIds();
        auto id = pointerIds.front();
        if (!pointerEvent->GetPointerItem(id, pointerItem)) {
            MMI_HILOGE("Can't find pointer item");
            return RET_ERR;
        }
        pointerItem.SetTargetWindowId(targetWindowId_);
        pointerEvent->UpdatePointerItem(id, pointerItem);
    }
    auto source = pointerEvent->GetSourceType();
    switch (source) {
        case PointerEvent::SOURCE_TYPE_TOUCHSCREEN: {
            auto inputEventNormalizeHandler = InputHandler->GetInputEventNormalizeHandler();
            CHKPR(inputEventNormalizeHandler, ERROR_NULL_POINTER);
            inputEventNormalizeHandler->HandleTouchEvent(pointerEvent);
            break;
        }
        case PointerEvent::SOURCE_TYPE_MOUSE:
        case PointerEvent::SOURCE_TYPE_TOUCHPAD : {
            auto inputEventNormalizeHandler = InputHandler->GetInputEventNormalizeHandler();
            CHKPR(inputEventNormalizeHandler, ERROR_NULL_POINTER);
            inputEventNormalizeHandler->HandlePointerEvent(pointerEvent);
            break;
        }
        default: {
            MMI_HILOGW("Source type is unknown, source:%{public}d", source);
            break;
        }
    }
    if (action == PointerEvent::POINTER_ACTION_DOWN) {
        targetWindowId_ = pointerEvent->GetTargetWindowId();
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

int32_t ServerMsgHandler::OnDisplayInfo(SessionPtr sess, NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    CHKPR(sess, ERROR_NULL_POINTER);
    DisplayGroupInfo displayGroupInfo;
    pkt >> displayGroupInfo.width >> displayGroupInfo.height >> displayGroupInfo.focusWindowId;
    uint32_t num = 0;
    pkt >> num;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read display info failed");
        return RET_ERR;
    }
    for (uint32_t i = 0; i < num; i++) {
        WindowInfo info;
        pkt >> info.id >> info.pid >> info.uid >> info.area >> info.defaultHotAreas
            >> info.pointerHotAreas >> info.agentWindowId >> info.flags;
        displayGroupInfo.windowsInfo.push_back(info);
        if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read display info failed");
        return RET_ERR;
    }
    }
    pkt >> num;
    for (uint32_t i = 0; i < num; i++) {
        DisplayInfo info;
        pkt >> info.id >> info.x >> info.y >> info.width >> info.height
            >> info.name >> info.uniq >> info.direction;
        displayGroupInfo.displaysInfo.push_back(info);
        if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read display info failed");
        return RET_ERR;
    }
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read display info failed");
        return RET_ERR;
    }
    InputWindowsManager::GetInstance()->UpdateDisplayInfo(displayGroupInfo);
    return RET_OK;
}

#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
int32_t ServerMsgHandler::OnAddInputHandler(SessionPtr sess, InputHandlerType handlerType,
    HandleEventType eventType)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    MMI_HILOGD("handlerType:%{public}d", handlerType);
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    if (handlerType == InputHandlerType::INTERCEPTOR) {
        auto interceptorHandler = InputHandler->GetInterceptorHandler();
        CHKPR(interceptorHandler, ERROR_NULL_POINTER);
        return interceptorHandler->AddInputHandler(handlerType, eventType, sess);
    }
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
#ifdef OHOS_BUILD_ENABLE_MONITOR
    if (handlerType == InputHandlerType::MONITOR) {
        auto monitorHandler = InputHandler->GetMonitorHandler();
        CHKPR(monitorHandler, ERROR_NULL_POINTER);
        return monitorHandler->AddInputHandler(handlerType, eventType, sess);
    }
#endif // OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}

int32_t ServerMsgHandler::OnRemoveInputHandler(SessionPtr sess, InputHandlerType handlerType,
                                               HandleEventType eventType)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    MMI_HILOGD("OnRemoveInputHandler handlerType:%{public}d eventType:%{public}u", handlerType, eventType);
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    if (handlerType == InputHandlerType::INTERCEPTOR) {
        auto interceptorHandler = InputHandler->GetInterceptorHandler();
        CHKPR(interceptorHandler, ERROR_NULL_POINTER);
        interceptorHandler->RemoveInputHandler(handlerType, eventType, sess);
    }
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
#ifdef OHOS_BUILD_ENABLE_MONITOR
    if (handlerType == InputHandlerType::MONITOR) {
        auto monitorHandler = InputHandler->GetMonitorHandler();
        CHKPR(monitorHandler, ERROR_NULL_POINTER);
        monitorHandler->RemoveInputHandler(handlerType, eventType, sess);
    }
#endif // OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR

#ifdef OHOS_BUILD_ENABLE_MONITOR
int32_t ServerMsgHandler::OnMarkConsumed(SessionPtr sess, int32_t eventId)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    auto monitorHandler = InputHandler->GetMonitorHandler();
    CHKPR(monitorHandler, ERROR_NULL_POINTER);
    monitorHandler->MarkConsumed(eventId, sess);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_MONITOR

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
int32_t ServerMsgHandler::OnMoveMouse(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
    if (MouseEventHdr->NormalizeMoveMouse(offsetX, offsetY)) {
        auto pointerEvent = MouseEventHdr->GetPointerEvent();
        CHKPR(pointerEvent, ERROR_NULL_POINTER);
        auto inputEventNormalizeHandler = InputHandler->GetInputEventNormalizeHandler();
        CHKPR(inputEventNormalizeHandler, ERROR_NULL_POINTER);
        inputEventNormalizeHandler->HandlePointerEvent(pointerEvent);
        MMI_HILOGD("Mouse movement message processed successfully");
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t ServerMsgHandler::OnSubscribeKeyEvent(IUdsServer *server, int32_t pid,
    int32_t subscribeId, const std::shared_ptr<KeyOption> option)
{
    CALL_DEBUG_ENTER;
    CHKPR(server, ERROR_NULL_POINTER);
    auto sess = server->GetSessionByPid(pid);
    CHKPR(sess, ERROR_NULL_POINTER);
    auto subscriberHandler = InputHandler->GetSubscriberHandler();
    CHKPR(subscriberHandler, ERROR_NULL_POINTER);
    return subscriberHandler->SubscribeKeyEvent(sess, subscribeId, option);
}

int32_t ServerMsgHandler::OnUnsubscribeKeyEvent(IUdsServer *server, int32_t pid, int32_t subscribeId)
{
    CALL_DEBUG_ENTER;
    CHKPR(server, ERROR_NULL_POINTER);
    auto sess = server->GetSessionByPid(pid);
    CHKPR(sess, ERROR_NULL_POINTER);
    auto subscriberHandler = InputHandler->GetSubscriberHandler();
    CHKPR(subscriberHandler, ERROR_NULL_POINTER);
    return subscriberHandler->UnsubscribeKeyEvent(sess, subscribeId);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_MMI_DEBUG
int32_t ServerMsgHandler::OnBigPacketTest(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t width = 0;
    int32_t height = 0;
    int32_t focusWindowId = 0;
    pkt >> width >> height >> focusWindowId;
    MMI_HILOGD("logicalInfo,width:%{public}d,height:%{public}d,focusWindowId:%{public}d",
        width, height, focusWindowId);
    uint32_t num = 0;
    pkt >> num;
    for (uint32_t i = 0; i < num; i++) {
        WindowInfo info;
        pkt >> info.id >> info.pid >> info.uid >> info.area >> info.defaultHotAreas
            >> info.pointerHotAreas >> info.agentWindowId >> info.flags;
        MMI_HILOGD("windowsInfos,id:%{public}d,pid:%{public}d,uid:%{public}d,"
            "area.x:%{public}d,area.y:%{public}d,area.width:%{public}d,area.height:%{public}d,"
            "defaultHotAreas:size:%{public}zu,pointerHotAreas:size:%{public}zu,"
            "agentWindowId:%{public}d,flags:%{public}d",
            info.id, info.pid, info.uid, info.area.x, info.area.y, info.area.width,
            info.area.height, info.defaultHotAreas.size(), info.pointerHotAreas.size(),
            info.agentWindowId, info.flags);
        for (const auto &win : info.defaultHotAreas) {
            MMI_HILOGD("defaultHotAreas,x:%{public}d,y:%{public}d,width:%{public}d,height:%{public}d",
                win.x, win.y, win.width, win.height);
        }
        for (const auto &pointer : info.pointerHotAreas) {
            MMI_HILOGD("pointerHotAreas,x:%{public}d,y:%{public}d,width:%{public}d,height:%{public}d",
                pointer.x, pointer.y, pointer.width, pointer.height);
        }
    }
    pkt >> num;
    for (uint32_t i = 0; i < num; i++) {
        DisplayInfo info;
        pkt >> info.id >> info.x >> info.y >> info.width >> info.height
            >> info.name >> info.uniq >> info.direction;
        MMI_HILOGD("displaysInfos,id:%{public}d,x:%{public}d,y:%{public}d,"
            "width:%{public}d,height:%{public}d,name:%{public}s,"
            "uniq:%{public}s,direction:%{public}d",
            info.id, info.x, info.y, info.width, info.height, info.name.c_str(),
            info.uniq.c_str(), info.direction);
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read data failed");
        return PACKET_READ_FAIL;
    }
    return RET_OK;
}
#endif // OHOS_BUILD_MMI_DEBUG
} // namespace MMI
} // namespace OHOS
