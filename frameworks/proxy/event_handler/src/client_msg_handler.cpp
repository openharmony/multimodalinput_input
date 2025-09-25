/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "anr_handler.h"
#include "bytrace_adapter.h"
#include "event_log_helper.h"
#include "input_active_subscribe_manager.h"
#include "input_event_data_transformation.h"
#include "input_manager_impl.h"
#ifdef OHOS_BUILD_ENABLE_MONITOR
#include "input_monitor_manager.h"
#endif // OHOS_BUILD_ENABLE_MONITOR
#ifdef OHOS_BUILD_ENABLE_KEY_HOOK
#include "key_event_hook_handler.h"
#endif // OHOS_BUILD_ENABLE_KEY_HOOK
#include "long_press_event_subscribe_manager.h"
#include "mmi_client.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"
#include "time_cost_chk.h"
#include "pre_monitor_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ClientMsgHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t PRINT_INTERVAL_COUNT { 50 };
} // namespace

void ClientMsgHandler::Init()
{
    MsgCallback funs[] = {
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
        { MmiMessageId::ON_KEY_EVENT, [this] (const UDSClient& client, NetPacket& pkt) {
            return this->OnKeyEvent(client, pkt); }},
        { MmiMessageId::ON_SUBSCRIBE_KEY, [this] (const UDSClient &client, NetPacket &pkt) {
            return this->OnSubscribeKeyEventCallback(client, pkt); }},
        { MmiMessageId::ON_SUBSCRIBE_KEY_MONITOR, [this] (const UDSClient &client, NetPacket &pkt) {
            return this->OnSubscribeKeyMonitor(client, pkt); }},
        { MmiMessageId::ON_PRE_KEY_EVENT, [this] (const UDSClient &client, NetPacket &pkt) {
            return this->OnPreKeyEvent(client, pkt); }},
#ifdef OHOS_BUILD_ENABLE_KEY_HOOK
        { MmiMessageId::ON_HOOK_KEY_EVENT, [this] (const UDSClient &client, NetPacket &pkt) {
            return this->OnHookKeyEvent(client, pkt); }},
#endif // OHOS_BUILD_ENABLE_KEY_HOOK
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_SWITCH
        { MmiMessageId::ON_SUBSCRIBE_SWITCH, [this] (const UDSClient &client, NetPacket &pkt) {
            return this->OnSubscribeSwitchEventCallback(client, pkt); }},
#endif // OHOS_BUILD_ENABLE_SWITCH
        { MmiMessageId::ON_SUBSCRIBE_TABLET, [this] (const UDSClient &client, NetPacket &pkt) {
            return this->OnSubscribeTabletProximityCallback(client, pkt); }},
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
        { MmiMessageId::ON_POINTER_EVENT, [this] (const UDSClient& client, NetPacket& pkt) {
            return this->OnPointerEvent(client, pkt); }},
        { MmiMessageId::ON_SUBSCRIBE_LONG_PRESS, [this] (const UDSClient& client, NetPacket& pkt) {
            return this->OnSubscribeLongPressEventCallback(client, pkt); }},
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
        { MmiMessageId::ADD_INPUT_DEVICE_LISTENER, [this] (const UDSClient& client, NetPacket& pkt) {
            return this->OnDevListener(client, pkt); }},
        { MmiMessageId::NOTICE_ANR, [this] (const UDSClient& client, NetPacket& pkt) {
            return this->OnAnr(client, pkt); }},
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && (defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || \
    defined(OHOS_BUILD_ENABLE_MONITOR))
        { MmiMessageId::REPORT_KEY_EVENT, [this] (const UDSClient& client, NetPacket& pkt) {
            return this->ReportKeyEvent(client, pkt); }},
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if (defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)) && \
    (defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR))
        { MmiMessageId::REPORT_POINTER_EVENT, [this] (const UDSClient& client, NetPacket& pkt) {
            return this->ReportPointerEvent(client, pkt); }},
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
        { MmiMessageId::NOTIFY_BUNDLE_NAME, [this] (const UDSClient& client, NetPacket& pkt) {
            return this->NotifyBundleName(client, pkt); }},
        { MmiMessageId::WINDOW_STATE_ERROR_NOTIFY, [this] (const UDSClient& client, NetPacket& pkt) {
            return this->NotifyWindowStateError(client, pkt); }},
        { MmiMessageId::SET_INPUT_DEVICE_ENABLED, [this] (const UDSClient& client, NetPacket& pkt) {
            return this->OnSetInputDeviceAck(client, pkt); }},
        { MmiMessageId::DEVICE_CONSUMER_HANDLER_EVENT, [this] (const UDSClient& client, NetPacket& pkt) {
            return this->ReportDeviceConsumer(client, pkt); }},
        { MmiMessageId::ON_SUBSCRIBE_INPUT_ACTIVE, [this] (const UDSClient &client, NetPacket &pkt) {
            return this->OnSubscribeInputActiveCallback(client, pkt); }},
    };
    for (auto &it : funs) {
        if (!RegistrationEvent(it)) {
            MMI_HILOGW("Failed to register event errCode:%{public}d", EVENT_REG_FAIL);
        }
    }
}

void ClientMsgHandler::InitProcessedCallback()
{
    CALL_DEBUG_ENTER;
    int32_t tokenType = MULTIMODAL_INPUT_CONNECT_MGR->GetTokenType();
    if (tokenType == TokenType::TOKEN_HAP || tokenType == TokenType::TOKEN_SYSTEM_HAP) {
        MMI_HILOGD("Current session is hap");
        dispatchCallback_ = [] (int32_t eventId, int64_t actionTime) {
            return ClientMsgHandler::OnDispatchEventProcessed(eventId, actionTime);
        };
    } else if (tokenType == static_cast<int32_t>(TokenType::TOKEN_NATIVE)) {
        MMI_HILOGD("Current session is native");
    } else {
        MMI_HILOGE("Current session is unknown tokenType:%{public}d", tokenType);
    }
}

void ClientMsgHandler::OnMsgHandler(const UDSClient& client, NetPacket& pkt)
{
    auto id = pkt.GetMsgId();
    TimeCostChk chk("ClientMsgHandler::OnMsgHandler", "overtime 300(us)", MAX_OVER_TIME, id);
    auto callback = GetMsgCallback(id);
    CHKPV(callback);
    ResetLogTrace();
    auto ret = (*callback)(client, pkt);
    if (ret < 0) {
        MMI_HILOGE("Msg handling failed. id:%{public}d, ret:%{public}d", id, ret);
        return;
    }
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t ClientMsgHandler::OnKeyEvent(const UDSClient& client, NetPacket& pkt)
{
    auto key = KeyEvent::Create();
    CHKPR(key, ERROR_NULL_POINTER);
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, key);
    if (ret != RET_OK) {
        MMI_HILOG_DISPATCHE("Read netPacket failed");
        return RET_ERR;
    }
    LogTracer lt(key->GetId(), key->GetEventType(), key->GetKeyAction());
    int32_t fd = 0;
    pkt >> fd;
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    if (InputEventDataTransformation::UnmarshallingEnhanceData(pkt, key) != ERR_OK) {
        MMI_HILOG_DISPATCHE("Failed to deserialize enhance data key event");
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    if (pkt.ChkRWError()) {
        MMI_HILOG_DISPATCHE("Packet read fd failed");
        return PACKET_READ_FAIL;
    }
    MMI_HILOG_DISPATCHW("The client receives a key, Fd:%{public}d", fd);
    BytraceAdapter::StartBytrace(key, BytraceAdapter::TRACE_START, BytraceAdapter::KEY_DISPATCH_EVENT);
    key->SetProcessedCallback(dispatchCallback_);
    InputMgrImpl.OnKeyEvent(key);
    key->MarkProcessed();
    return RET_OK;
}

int32_t ClientMsgHandler::OnPreKeyEvent(const UDSClient& client, NetPacket& pkt)
{
    auto keyEvent = KeyEvent::Create();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent);
    if (ret != RET_OK) {
        MMI_HILOG_DISPATCHE("Read netPacket failed");
        return RET_ERR;
    }
    int32_t fd = -1;
    int32_t handlerId = -1;
    pkt >> fd >> handlerId;
    if (pkt.ChkRWError()) {
        MMI_HILOG_ANRDETECTE("Packet read fd failed");
        return PACKET_READ_FAIL;
    }
    MMI_HILOG_DISPATCHD("PRE key event dispathcer of clent, Fd:%{public}d", fd);
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_START, BytraceAdapter::KEY_DISPATCH_EVENT);
    PRE_MONITOR_MGR.OnPreKeyEvent(keyEvent, handlerId);
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_KEY_HOOK
int32_t ClientMsgHandler::OnHookKeyEvent(const UDSClient& client, NetPacket& pkt)
{
    auto keyEvent = KeyEvent::Create();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent);
    if (ret != RET_OK) {
        MMI_HILOG_DISPATCHE("Read netPacket failed");
        return RET_ERR;
    }
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_START, BytraceAdapter::KEY_DISPATCH_EVENT);
    KEY_EVENT_HOOK_HANDLER.OnKeyEvent(keyEvent);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_KEY_HOOK
#endif // OHOS_BUILD_ENABLE_KEYBOARD

int32_t ClientMsgHandler::NotifyBundleName(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    int32_t pid = 0;
    int32_t uid = 0;
    int32_t syncStatus = 0;
    std::string bundleName;
    pkt >> pid >> uid >> bundleName >> syncStatus;
    InputMgrImpl.NotifyBundleName(pid, uid, bundleName, syncStatus);
    MMI_HILOGD("NotifyBundleName pid:%{public}d, uid:%{public}d, bundleName:%{public}s, syncStatus:%{public}d",
        pid, uid, bundleName.c_str(), syncStatus);
    return RET_OK;
}

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
int32_t ClientMsgHandler::OnPointerEvent(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (InputEventDataTransformation::Unmarshalling(pkt, pointerEvent) != ERR_OK) {
        MMI_HILOG_DISPATCHE("Failed to deserialize pointer event");
        return RET_ERR;
    }
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    if (InputEventDataTransformation::UnmarshallingEnhanceData(pkt, pointerEvent) != ERR_OK) {
        MMI_HILOG_DISPATCHE("Failed to deserialize enhance data pointer event");
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    if (false && pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_ROTATE_UPDATE) {
        std::string logInfo = std::string("ac: ") + pointerEvent->DumpPointerAction();
        aggregator_.Record({MMI_LOG_DISPATCH, INPUT_KEY_FLOW, __FUNCTION__, __LINE__}, logInfo.c_str(),
            std::to_string(pointerEvent->GetId()));
    }
    if (PointerEvent::POINTER_ACTION_CANCEL == pointerEvent->GetPointerAction() ||
        PointerEvent::POINTER_ACTION_HOVER_CANCEL == pointerEvent->GetPointerAction() ||
        PointerEvent::POINTER_ACTION_FINGERPRINT_CANCEL == pointerEvent->GetPointerAction()) {
        MMI_HILOG_DISPATCHI("Operation canceled");
    }
    pointerEvent->SetProcessedCallback(dispatchCallback_);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START, BytraceAdapter::POINT_DISPATCH_EVENT);
    processedCount_++;
    if (processedCount_ == PRINT_INTERVAL_COUNT) {
        MMI_HILOGD("Last eventId:%{public}d, current eventId:%{public}d", lastEventId_, pointerEvent->GetId());
        processedCount_ = 0;
        lastEventId_ = pointerEvent->GetId();
    }
    PointerEvent::PointerItem pointerItem {};
    if (pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem)) {
        MMI_HILOGD("Report pointer event, No:%{public}d,PA:%{public}s,DX:%{private}d,DY:%{private}d"
            ",DXP:%{private}f,DYP:%{private}f,WXP:%{private}f,WYP:%{private}f,GX:%{private}f,GY:%{private}f",
            pointerEvent->GetId(), pointerEvent->DumpPointerAction(),
            pointerItem.GetDisplayX(), pointerItem.GetDisplayY(),
            pointerItem.GetDisplayXPos(), pointerItem.GetDisplayYPos(),
            pointerItem.GetWindowXPos(), pointerItem.GetWindowYPos(),
            pointerItem.GetGlobalX(), pointerItem.GetGlobalY());
    }
    InputMgrImpl.OnPointerEvent(pointerEvent);
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_JOYSTICK) {
        pointerEvent->MarkProcessed();
    }
    return RET_OK;
}

int32_t ClientMsgHandler::OnSubscribeLongPressEventCallback(const UDSClient& client, NetPacket& pkt)
{
    LongPressEvent longPressEvent;
    int32_t ret = InputEventDataTransformation::NetPacketToLongPressEvent(pkt, longPressEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("Read net packet failed");
        return RET_ERR;
    }
    int32_t fd = -1;
    int32_t subscribeId = -1;
    pkt >> fd >> subscribeId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read fd failed");
        return PACKET_READ_FAIL;
    }
    return LONG_PRESS_EVENT_SUBSCRIBE_MGR.OnSubscribeLongPressEventCallback(longPressEvent, subscribeId);
}

#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t ClientMsgHandler::OnSubscribeKeyEventCallback(const UDSClient &client, NetPacket &pkt)
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("Read net packet failed");
        return RET_ERR;
    }
    LogTracer lt(keyEvent->GetId(), keyEvent->GetEventType(), keyEvent->GetKeyAction());
    int32_t fd = -1;
    int32_t subscribeId = -1;
    pkt >> fd >> subscribeId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read fd failed");
        return PACKET_READ_FAIL;
    }
    if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER) {
        if (!EventLogHelper::IsBetaVersion()) {
            MMI_HILOGI("Subscribe:%{public}d,Fd:%{public}d,KeyEvent:%{public}d, "
                "Action:%{public}d, KeyAction:%{public}d, EventType:%{public}d,Flag:%{public}u",
                subscribeId, fd, keyEvent->GetId(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                keyEvent->GetEventType(), keyEvent->GetFlag());
        } else {
            MMI_HILOGW("Subscribe:%{public}d,Fd:%{public}d,KeyEvent:%{public}d, "
                "Action:%{public}d, KeyAction:%{public}d, EventType:%{public}d,Flag:%{public}u",
                subscribeId, fd, keyEvent->GetId(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                keyEvent->GetEventType(), keyEvent->GetFlag());
        }
    } else {
        MMI_HILOGD("Subscribe:%{public}d,Fd:%{public}d,KeyEvent:%{public}d,"
            "KeyCode:%{private}d,ActionTime:%{public}" PRId64 ",ActionStartTime:%{public}" PRId64 ","
            "Action:%{public}d,KeyAction:%{public}d,EventType:%{public}d,Flag:%{public}u",
        subscribeId, fd, keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
        keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
        keyEvent->GetEventType(), keyEvent->GetFlag());
    }

    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_START, BytraceAdapter::KEY_SUBSCRIBE_EVENT);
    return KeyEventInputSubscribeMgr.OnSubscribeKeyEventCallback(keyEvent, subscribeId);
}

int32_t ClientMsgHandler::OnSubscribeKeyMonitor(const UDSClient &client, NetPacket &pkt)
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent);
    bool status = false;
    pkt >> status;
    if (ret != RET_OK) {
        MMI_HILOGE("Read net packet failed");
        return RET_ERR;
    }
    MMI_HILOGD("Key monitor(No:%{public}d, KC:%{private}d, KA:%{public}d)",
        keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetKeyAction());
    LogTracer lt(keyEvent->GetId(), keyEvent->GetEventType(), keyEvent->GetKeyAction());
#ifdef OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
    return KeyEventInputSubscribeMgr.OnSubscribeKeyMonitor(keyEvent, status);
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_SWITCH
int32_t ClientMsgHandler::OnSubscribeSwitchEventCallback(const UDSClient &client, NetPacket &pkt)
{
    std::shared_ptr<SwitchEvent> switchEvent = std::make_shared<SwitchEvent>(0);
    int32_t ret = InputEventDataTransformation::NetPacketToSwitchEvent(pkt, switchEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("Read net packet failed");
        return RET_ERR;
    }
    LogTracer lt(switchEvent->GetId(), switchEvent->GetEventType(), switchEvent->GetAction());
    int32_t fd = -1;
    int32_t subscribeId = -1;
    pkt >> fd >> subscribeId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read fd failed");
        return PACKET_READ_FAIL;
    }
    return SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.OnSubscribeSwitchEventCallback(switchEvent, subscribeId);
}
#endif

int32_t ClientMsgHandler::OnSubscribeTabletProximityCallback(const UDSClient &client, NetPacket &pkt)
{
    auto pointerEvent = PointerEvent::Create();
    int32_t ret = InputEventDataTransformation::Unmarshalling(pkt, pointerEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("Read net packet failed");
        return RET_ERR;
    }
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetAction());
    int32_t fd = -1;
    int32_t subscribeId = -1;
    pkt >> fd >> subscribeId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read fd failed");
        return PACKET_READ_FAIL;
    }
    return TABLET_EVENT_INPUT_SUBSCRIBE_MGR.OnSubscribeTabletProximityCallback(pointerEvent, subscribeId);
}

int32_t ClientMsgHandler::OnDevListener(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    std::string type;
    int32_t deviceId = 0;
    pkt >> type >> deviceId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read type failed");
        return RET_ERR;
    }
    INPUT_DEVICE_IMPL.OnDevListener(deviceId, type);
    return RET_OK;
}

#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && (defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || \
    defined(OHOS_BUILD_ENABLE_MONITOR))
int32_t ClientMsgHandler::ReportKeyEvent(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    InputHandlerType handlerType;
    uint32_t deviceTags = 0;
    pkt >> handlerType >> deviceTags;
    if (pkt.ChkRWError()) {
        MMI_HILOG_DISPATCHE("Packet read handler failed");
        return RET_ERR;
    }
    auto keyEvent = KeyEvent::Create();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    if (InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent) != ERR_OK) {
        MMI_HILOG_DISPATCHE("Failed to deserialize key event");
        return RET_ERR;
    }
    LogTracer lt(keyEvent->GetId(), keyEvent->GetEventType(), keyEvent->GetKeyAction());
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_START, BytraceAdapter::KEY_INTERCEPT_EVENT);
    switch (handlerType) {
        case INTERCEPTOR: {
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
            InputInterMgr->OnInputEvent(keyEvent, deviceTags);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
            break;
        }
        case MONITOR: {
#ifdef OHOS_BUILD_ENABLE_MONITOR
            IMonitorMgr.OnInputEvent(keyEvent, deviceTags);
#endif // OHOS_BUILD_ENABLE_MONITOR
            break;
        }
        default: {
            MMI_HILOG_DISPATCHW("Failed to intercept or monitor on the event");
            break;
        }
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR

#if (defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)) && \
    (defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR))
int32_t ClientMsgHandler::ReportPointerEvent(const UDSClient& client, NetPacket& pkt)
{
    InputHandlerType handlerType;
    uint32_t deviceTags = 0;
    pkt >> handlerType >> deviceTags;
    if (pkt.ChkRWError()) {
        MMI_HILOG_DISPATCHE("Packet read Pointer data failed");
        return RET_ERR;
    }
    MMI_HILOG_DISPATCHD("Client handlerType:%{public}d", handlerType);
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (InputEventDataTransformation::Unmarshalling(pkt, pointerEvent) != ERR_OK) {
        MMI_HILOG_DISPATCHW("Failed to deserialize pointer event");
        return RET_ERR;
    }
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START, BytraceAdapter::POINT_INTERCEPT_EVENT);
    switch (handlerType) {
        case INTERCEPTOR: {
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
            InputInterMgr->OnInputEvent(pointerEvent, deviceTags);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
            break;
        }
        case MONITOR: {
#ifdef OHOS_BUILD_ENABLE_MONITOR
            IMonitorMgr.OnInputEvent(pointerEvent, deviceTags);
#endif // OHOS_BUILD_ENABLE_MONITOR
            break;
        }
        default: {
            MMI_HILOG_DISPATCHW("Failed to intercept or monitor on the event");
            break;
        }
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

void ClientMsgHandler::OnDispatchEventProcessed(int32_t eventId, int64_t actionTime)
{
    CALL_DEBUG_ENTER;
    ANRHDL->SetLastProcessedEventId(ANR_DISPATCH, eventId, actionTime);
}

int32_t ClientMsgHandler::OnAnr(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    int32_t pid = 0;
    int32_t eventId = 0;
    pkt >> pid;
    pkt >> eventId;
    if (pkt.ChkRWError()) {
        MMI_HILOG_ANRDETECTE("Packet read data failed");
        return RET_ERR;
    }
    MMI_HILOG_ANRDETECTI("Client pid:%{public}d eventId:%{public}d", pid, eventId);
    InputMgrImpl.OnAnr(pid, eventId);
    return RET_OK;
}

int32_t ClientMsgHandler::NotifyWindowStateError(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    int32_t pid = 0;
    int32_t windowId = 0;
    pkt >> pid;
    pkt >> windowId;
    if (pkt.ChkRWError()) {
        MMI_HILOG_ANRDETECTE("Packet read data failed");
        return RET_ERR;
    }
    MMI_HILOG_ANRDETECTI("Client pid:%{public}d windowId:%{public}d", pid, windowId);
    InputMgrImpl.OnWindowStateError(pid, windowId);
    return RET_OK;
}

int32_t ClientMsgHandler::OnSetInputDeviceAck(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    int32_t index = 0;
    int32_t result = 0;
    pkt >> index >> result;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read type failed");
        return RET_ERR;
    }
    INPUT_DEVICE_IMPL.OnSetInputDeviceAck(index, result);
    return RET_OK;
}

int32_t ClientMsgHandler::ReportDeviceConsumer(const UDSClient& client, NetPacket& pkt)
{
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read Pointer data failed");
        return RET_ERR;
    }
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (InputEventDataTransformation::Unmarshalling(pkt, pointerEvent) != ERR_OK) {
        MMI_HILOGE("Failed to deserialize pointer event");
        return RET_ERR;
    }
    for (const auto &item : pointerEvent->GetPointerIds()) {
        PointerEvent::PointerItem pointerItem;
        if (!pointerEvent->GetPointerItem(item, pointerItem)) {
            MMI_HILOGE("Get pointer item failed");
            return RET_ERR;
        }
        MMI_HILOGD("orientation:%{public}d, blodid:%{public}d, toolType:%{public}d",
            pointerItem.GetOrientation(), pointerItem.GetBlobId(), pointerItem.GetToolType());
    }
    InputMgrImpl.OnDeviceConsumerEvent(pointerEvent);
    return RET_OK;
}

int32_t ClientMsgHandler::OnSubscribeInputActiveCallback(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    HandleEventType handleEventType = HANDLE_EVENT_TYPE_NONE;
    auto keyEvent = KeyEvent::Create();
    auto pointerEvent = PointerEvent::Create();
    CHKPR(keyEvent, RET_ERR);
    CHKPR(pointerEvent, RET_ERR);
    pkt >> handleEventType;
    int32_t ret = RET_ERR;
    if (handleEventType == HANDLE_EVENT_TYPE_KEY) {
        ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent);
    } else if (handleEventType == HANDLE_EVENT_TYPE_POINTER) {
        ret = InputEventDataTransformation::Unmarshalling(pkt, pointerEvent);
    } else {
        MMI_HILOGE("handleEventType(%{public}d) error", handleEventType);
        return RET_ERR;
    }
    if (ret != RET_OK) {
        MMI_HILOGE("Read net packet failed, ret = %{public}d", ret);
        return RET_ERR;
    }
    int32_t subscribeId = -1;
    pkt >> subscribeId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read subscribeId failed");
        return RET_ERR;
    }
    return handleEventType == HANDLE_EVENT_TYPE_KEY ?
        INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(keyEvent, subscribeId) :
        INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(pointerEvent, subscribeId);
}
} // namespace MMI
} // namespace OHOS
