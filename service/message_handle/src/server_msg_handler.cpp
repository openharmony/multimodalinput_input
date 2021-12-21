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

#include "server_msg_handler.h"
#include <inttypes.h>
#include "mmi_func_callback.h"
#include "ai_func_proc.h"
#include "event_dump.h"
#include "event_package.h"
#include "input_device_manager.h"
#include "input_event_data_transformation.h"
#include "input_event_monitor_manager.h"
#include "input_handler_manager_global.h"
#include "input_windows_manager.h"
#include "knuckle_func_proc.h"
#include "mmi_server.h"
#include "server_input_filter_manager.h"
#include "ability_launch_manager.h"
#include "time_cost_chk.h"

#ifdef OHOS_BUILD_HDF
#include "hdi_inject.h"
#endif

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ServerMsgHandler" };
    }
}

OHOS::MMI::ServerMsgHandler::ServerMsgHandler()
{
}

OHOS::MMI::ServerMsgHandler::~ServerMsgHandler()
{
}

bool OHOS::MMI::ServerMsgHandler::Init(UDSServer& udsServer)
{
    udsServer_ = &udsServer;
#ifdef OHOS_BUILD_HDF
    CHKF(hdiInject->Init(udsServer), SENIOR_INPUT_DEV_INIT_FAIL);
#endif
    MsgCallback funs[] = {
        {MmiMessageId::REGISTER_APP_INFO, MsgCallbackBind2(&ServerMsgHandler::OnRegisterAppInfo, this)},
        {MmiMessageId::REGISTER_MSG_HANDLER, MsgCallbackBind2(&ServerMsgHandler::OnRegisterMsgHandler, this)},
        {MmiMessageId::UNREGISTER_MSG_HANDLER, MsgCallbackBind2(&ServerMsgHandler::OnUnregisterMsgHandler, this)},
        {MmiMessageId::ON_WINDOW, MsgCallbackBind2(&ServerMsgHandler::OnWindow, this)},
        {MmiMessageId::ON_VIRTUAL_KEY, MsgCallbackBind2(&ServerMsgHandler::OnVirtualKeyEvent, this)},
        {MmiMessageId::CHECK_REPLY_MESSAGE, MsgCallbackBind2(&ServerMsgHandler::CheckReplyMessageFormClient, this)},
        {MmiMessageId::ON_DUMP, MsgCallbackBind2(&ServerMsgHandler::OnDump, this)},
        {MmiMessageId::ON_LIST, MsgCallbackBind2(&ServerMsgHandler::OnListInject, this)},
        {MmiMessageId::GET_MMI_INFO_REQ, MsgCallbackBind2(&ServerMsgHandler::GetMultimodeInputInfo, this)},
        {MmiMessageId::INJECT_KEY_EVENT, MsgCallbackBind2(&ServerMsgHandler::OnInjectKeyEvent, this) },
        {MmiMessageId::INJECT_POINTER_EVENT, MsgCallbackBind2(&ServerMsgHandler::OnInjectPointerEvent, this) },
        {MmiMessageId::ADD_KEY_EVENT_INTERCEPTOR, MsgCallbackBind2(&ServerMsgHandler::OnAddKeyEventFilter, this)},
        {MmiMessageId::REMOVE_KEY_EVENT_INTERCEPTOR, MsgCallbackBind2(&ServerMsgHandler::OnRemoveKeyEventFilter, this)},
        {MmiMessageId::INPUT_DEVICE_INFO, MsgCallbackBind2(&ServerMsgHandler::OnGetDeviceInfo, this)},
        {MmiMessageId::INPUT_DEVICE_ID_LIST, MsgCallbackBind2(&ServerMsgHandler::OnGetDeviceIdList, this)},
        {MmiMessageId::ADD_TOUCH_EVENT_INTERCEPTOR, MsgCallbackBind2(&ServerMsgHandler::OnAddTouchEventFilter, this)},
        {MmiMessageId::REMOVE_TOUCH_EVENT_INTERCEPTOR, MsgCallbackBind2(&ServerMsgHandler::OnRemoveTouchEventFilter, this)},
        {MmiMessageId::DISPLAY_INFO, MsgCallbackBind2(&ServerMsgHandler::OnDisplayInfo, this)},
        {MmiMessageId::ADD_INPUT_EVENT_MONITOR, MsgCallbackBind2(&ServerMsgHandler::OnAddInputEventMontior, this)},
        {MmiMessageId::REMOVE_INPUT_EVENT_MONITOR, MsgCallbackBind2(&ServerMsgHandler::OnRemoveInputEventMontior, this)},
        {MmiMessageId::ADD_POINTER_INTERCEPTOR, MsgCallbackBind2(&ServerMsgHandler::OnAddEventInterceptor, this)},
        {MmiMessageId::REMOVE_POINTER_INTERCEPTOR, MsgCallbackBind2(&ServerMsgHandler::OnRemoveEventInterceptor, this)},
        {MmiMessageId::ADD_INPUT_HANDLER, MsgCallbackBind2(&ServerMsgHandler::OnAddInputHandler, this)},
        {MmiMessageId::REMOVE_INPUT_HANDLER, MsgCallbackBind2(&ServerMsgHandler::OnRemoveInputHandler, this)},
        {MmiMessageId::MARK_CONSUMED, MsgCallbackBind2(&ServerMsgHandler::OnMarkConsumed, this)},
#ifdef OHOS_BUILD_AI
        {MmiMessageId::SENIOR_INPUT_FUNC, MsgCallbackBind2(&ServerMsgHandler::OnSeniorInputFuncProc, this)},
#endif // OHOS_BUILD_AI
#ifdef OHOS_BUILD_HDF
        {MmiMessageId::HDI_INJECT, MsgCallbackBind2(&ServerMsgHandler::OnHdiInject, this)},
#endif // OHOS_BUILD_HDF
#ifdef OHOS_AUTO_TEST_FRAME
        {MmiMessageId::ST_MESSAGE_BEGIN, MsgCallbackBind2(&ServerMsgHandler::AutoTestFrameRegister, this)},
        {MmiMessageId::ST_MESSAGE_REPLYPKT, MsgCallbackBind2(&ServerMsgHandler::AutoTestReceiveClientPkt, this)},
#endif  // OHOS_AUTO_TEST_FRAME
    };
    for (auto& it : funs) {
        CHKC(RegistrationEvent(it), EVENT_REG_FAIL);
    }
    return true;
}

#ifdef OHOS_BUILD_AI
void OHOS::MMI::ServerMsgHandler::SetSeniorInputHandle(SeniorInputFuncProcBase& seniorInputFuncProc)
{
    seniorInput_ = &seniorInputFuncProc;
}
#endif

void OHOS::MMI::ServerMsgHandler::OnMsgHandler(SessionPtr sess, NetPacket& pkt)
{
    CHK(sess, NULL_POINTER);
    auto id = pkt.GetMsgId();
    OHOS::MMI::TimeCostChk chk("ServerMsgHandler::OnMsgHandler", "overtime 300(us)", MAX_OVER_TIME, id);
    auto fun = GetFun(id);
    if (!fun) {
        MMI_LOGE("ServerMsgHandler::OnMsgHandler Unknown msg id[%{public}d]. errCode:%{public}d", id, UNKNOWN_MSG_ID);
        return;
    }
    auto ret = (*fun)(sess, pkt);
    if (ret < 0) {
        MMI_LOGE("ServerMsgHandler::OnMsgHandler Msg handling failed. id[%{public}d] errCode:%{public}d", id, ret);
    }
}

#ifdef  OHOS_BUILD_AI
int32_t OHOS::MMI::ServerMsgHandler::OnSeniorInputFuncProc(SessionPtr SessionPtr, NetPacket& pkt)
{
    CHKR(SessionPtr, NULL_POINTER, RET_ERR);
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    const int32_t fd = SessionPtr->GetFd();
    seniorInput_->SetSessionFd(fd);

    MSG_TYPE msgType;
    pkt >> msgType;

    bool processResult = false;
    do {
        if (msgType == MSG_TYPE_DEVICE_INIT) {
            int32_t devIndex;
            int32_t devType;
            pkt >> devIndex >> devType;
            sptr<SeniorInputFuncProcBase> ptr;
            if (devType == INPUT_DEVICE_CAP_AISENSOR) {
                ptr = SeniorInputFuncProcBase::Create<AIFuncProc>();
            } else if (devType == INPUT_DEVICE_CAP_KNUCKLE) {
                ptr = SeniorInputFuncProcBase::Create<KnuckleFuncProc>();
            } else {
                MMI_LOGE("unknown devType: %{public}d. replyCode: %{public}d.", devType, processResult);
                break;
            }

            if (ptr == nullptr) {
                MMI_LOGE("ptr is null, devType: %{public}d. replyCode: %{public}d.", devType, processResult);
                break;
            }

            processResult = seniorInput_->DeviceInit(fd, ptr);
        } else if (msgType == MSG_TYPE_DEVICE_INFO) {
            RawInputEvent seniorInputEvent = {};
            pkt >> seniorInputEvent;
            MMI_LOGD("recived data: type = %{public}d,code = %{public}d,value = %{public}d.",
                     seniorInputEvent.ev_type, seniorInputEvent.ev_code, seniorInputEvent.ev_value);
            processResult = seniorInput_->DeviceEventDispatch(fd, seniorInputEvent);
        } else {
            MMI_LOGE("unknown msgType: %{public}d. replyCode: %{public}d.", msgType, processResult);
        }
    } while (0);

    if (processResult) {
        MMI_LOGI("process success");
    } else {
        MMI_LOGE("process fail, fd: %{public}d, msgType: %{public}d, processResult: %{public}d.",
                 fd, msgType, processResult);
    }

    const int responseCode = seniorInput_->ReplyMessage(SessionPtr, processResult);
    if (responseCode == RET_ERR) {
        MMI_LOGW("reply msg to client fail, fd: %{public}d, msgType: %{public}d,"
                 " processResult: %{public}d, replyCode: %{public}d.",
                 fd, msgType, processResult, responseCode);
        return responseCode;
    }

    return RET_OK;
}
#endif // OHOS_BUILD_AI

#ifdef OHOS_BUILD_HDF
int32_t OHOS::MMI::ServerMsgHandler::OnHdiInject(SessionPtr sess, NetPacket& pkt)
{
    MMI_LOGI("hdfinject server access hditools info.");
    CHKR(sess, NULL_POINTER, RET_ERR);
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    const int32_t processingCode = hdiInject->ManageHdfInject(sess, pkt);
    NetPacket newPacket(MmiMessageId::HDI_INJECT);
    newPacket << processingCode;
    if (!sess->SendMsg(newPacket)) {
        MMI_LOGE("OnHdiInject reply messaage error.");
        return RET_ERR;
    }
    return RET_OK;
}
#endif

int32_t OHOS::MMI::ServerMsgHandler::OnRegisterAppInfo(SessionPtr sess, NetPacket& pkt)
{
    CHKR(sess, NULL_POINTER, RET_ERR);
    CHKR(udsServer_, NULL_POINTER, RET_ERR);

    int32_t abilityId = 0;
    int32_t windowId = 0;
    std::string bundlerName;
    std::string appName;
    int32_t fd = sess->GetFd();
    pkt >> abilityId >> windowId >> bundlerName >> appName;
    struct AppInfo appInfo = { abilityId, windowId, fd, bundlerName, appName };

    AppRegs->RegisterAppInfoforServer(appInfo);
#if !defined(OHOS_BUILD) || !defined(OHOS_WESTEN_MODEL)
    WinMgr->SetFocusSurfaceId(windowId);
    WinMgr->SetTouchFocusSurfaceId(windowId);
#endif
    MMI_LOGD("OnRegisterAppInfo fd:%{public}d bundlerName:%{public}s "
        "appName:%{public}s", fd, bundlerName.c_str(), appName.c_str());

#ifdef OHOS_AUTO_TEST_FRAME
    if (!AppRegs->AutoTestGetAutoTestFd()) {
        return RET_OK;
    }
    std::vector<AutoTestClientListPkt> clientListPkt;
    AppRegs->AutoTestGetAllAppInfo(clientListPkt);
    uint32_t sizeOfList = static_cast<uint32_t>(clientListPkt.size());
    NetPacket pktAutoTest(MmiMessageId::ST_MESSAGE_CLISTPKT);
    pktAutoTest << sizeOfList;
    for (auto it = clientListPkt.begin(); it != clientListPkt.end(); it++) {
        pktAutoTest << *it;
    }
    if (!udsServer_->SendMsg(AppRegs->AutoTestGetAutoTestFd(), pktAutoTest)) {
        MMI_LOGE("Send ClientList massage failed to auto-test frame !\n");
    }
#endif  // OHOS_AUTO_TEST_FRAME
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnRegisterMsgHandler(SessionPtr sess, NetPacket& pkt)
{
    CHKR(sess, NULL_POINTER, RET_ERR);
    MmiMessageId eventType = MmiMessageId::INVALID;
    int32_t abilityId = 0;
    int32_t winId = 0;
    std::string bundlerName;
    std::string appName;
    int32_t fd = sess->GetFd();
    pkt >> eventType >> abilityId >> winId >> bundlerName >> appName;
    RegEventHM->RegisterEvent(eventType, fd);
    if (winId > 0) {
        AppRegs->RegisterAppInfoforServer({abilityId, winId, fd, bundlerName, appName});
    }
    MMI_LOGD("OnRegisterMsgHandler fd:%{public}d eventType:%{public}d"
             " bundlerName:%{public}s appName:%{public}s",
             fd, eventType, bundlerName.c_str(), appName.c_str());
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnUnregisterMsgHandler(SessionPtr sess, NetPacket& pkt)
{
    CHKR(sess, NULL_POINTER, RET_ERR);
    MmiMessageId messageId = MmiMessageId::INVALID;
    int32_t fd = sess->GetFd();
    pkt >> messageId;
    RegEventHM->UnregisterEventHandleManager(messageId, fd);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnWindow(SessionPtr sess, NetPacket& pkt)
{
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    TestSurfaceInfo surfaces = {};
    TestSurfaceData mysurfaceInfo = {};
    pkt >> mysurfaceInfo;
    surfaces.opacity = mysurfaceInfo.opacity;
    surfaces.onLayerId = mysurfaceInfo.onLayerId;
    surfaces.visibility = mysurfaceInfo.visibility;
    surfaces.surfaceId = mysurfaceInfo.surfaceId;
    surfaces.srcX = mysurfaceInfo.srcX;
    surfaces.srcY = mysurfaceInfo.srcY;
    surfaces.srcW = mysurfaceInfo.srcW;
    surfaces.srcH = mysurfaceInfo.srcH;
    surfaces.screenId = mysurfaceInfo.screenId;
    WinMgr->InsertSurfaceInfo(surfaces);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnVirtualKeyEvent(SessionPtr sess, NetPacket& pkt)
{
    VirtualKey virtualKeyEvent;
    pkt >> virtualKeyEvent;
    if (virtualKeyEvent.keyCode == HOS_KEY_HOME) {
        MMI_LOGD(" home press");
    } else if (virtualKeyEvent.keyCode == HOS_KEY_BACK) {
        MMI_LOGD(" back press");
    } else if (virtualKeyEvent.keyCode == HOS_KEY_VIRTUAL_MULTITASK) {
        MMI_LOGD(" multitask press");
    }
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnDump(SessionPtr sess, NetPacket& pkt)
{
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    int fd = -1;
    pkt >> fd;
    MMIEventDump->Dump(fd);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::CheckReplyMessageFormClient(SessionPtr sess, NetPacket& pkt)
{
    uint64_t time = 0;
    int32_t fd = 0;
    int32_t idMsg = 0;
    uint64_t serverStartTime = 0;
    uint64_t clientEndTime = 0;
    pkt >> idMsg >> time >> fd >> serverStartTime >> clientEndTime;

    // add msg to dump
    int32_t westonTime = serverStartTime - time;
    int32_t mmiTime = clientEndTime - serverStartTime;
    MMIEventDump->InsertFormat("MsgDump: msgId=%d fd=%d inputTime=%llu(us) westonTime=%d(us) mmiTime=%d(us)",
                               idMsg, fd, time, westonTime, mmiTime);

#ifdef DEBUG_CODE_TEST
    if (AppRegs->ChkTestArg(MULTIMODE_INPUT_ANR_QUEUEBLOCK)) {
        return RET_OK;
    }
#endif // DEBUG_CODE_TEST
    AppRegs->DeleteEventFromWaitQueue(time, fd);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnListInject(SessionPtr sess, NetPacket& pkt)
{
    CHKR(sess, NULL_POINTER, RET_ERR);
    int32_t ret = RET_ERR;
    RawInputEvent list = {};
    pkt >> list;
    if (list.ev_value == 0) {
        WinMgr->PrintAllNormalSurface();
    } else if (list.ev_value == 1) {
        AppRegs->PrintfMap();
    }
    return ret;
}

int32_t OHOS::MMI::ServerMsgHandler::GetMultimodeInputInfo(SessionPtr sess, NetPacket& pkt)
{
    CHKR(sess, NULL_POINTER, RET_ERR);
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    TagPackHead tagPackHead;
    int32_t fd = sess->GetFd();
    pkt >> tagPackHead;

    if (tagPackHead.idMsg != MmiMessageId::INVALID) {
        TagPackHead tagPackHeadAck = { MmiMessageId::INVALID, {fd}};
        NetPacket pktAck(MmiMessageId::GET_MMI_INFO_ACK);
        pktAck << tagPackHeadAck;
        if (!udsServer_->SendMsg(fd, pktAck)) {
            MMI_LOGE("Sending message failed !\n");
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnInjectKeyEvent(SessionPtr sess, NetPacket& pkt)
{
    CHKR(sess, NULL_POINTER, RET_ERR);
    uint64_t preHandlerTime = GetSysClockTime();
    VirtualKey event;
    if (!pkt.Read(event)) {
        MMI_LOGE("read data failed");
        return RET_ERR;
    }
    if (!pkt.IsEmpty()) {
        MMI_LOGE("event is abandoned");
        return RET_ERR;
    }
    if (event.keyDownDuration < 0) {
        MMI_LOGE("keyDownDuration is invalid");
        return RET_ERR;
    }
    if (event.keyCode < 0) {
        MMI_LOGE("keyCode is invalid");
        return RET_ERR;
    }
    MMI_LOGT("time:%{public}u,keycode:%{public}u,state:%{public}u,\
        isIntercepted:%{public}d", event.keyDownDuration, event.keyCode,
        event.isPressed, event.isIntercepted);
    struct EventKeyboard key = {};
    auto packageResult = EventPackage::PackageVirtualKeyEvent(event, key, *udsServer_);
    if (packageResult == RET_ERR) {
        return RET_ERR;
    }

    if (event.isIntercepted) {
        if (ServerKeyFilter->OnKeyEvent(key)) {
            MMI_LOGD("key event filter find a  key event from Original event  keyCode : %{puiblic}d", key.key);
            return RET_OK;
        }
    }
    if (keyEvent == nullptr) {
        keyEvent = OHOS::MMI::KeyEvent::Create();
    }
    EventPackage::KeyboardToKeyEvent(key, keyEvent, *udsServer_);
    if (AbilityMgr->CheckLaunchAbility(keyEvent)) {
        MMI_LOGD("key event start launch an ability, keyCode : %{puiblic}d", key.key);
        return RET_OK;
    }
    auto eventDispatchResult = eventDispatch_.DispatchKeyEventByPid(*udsServer_, keyEvent, preHandlerTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("Key event dispatch failed... ret:%{public}d errCode:%{public}d",
                 eventDispatchResult, KEY_EVENT_DISP_FAIL);
    }

#ifdef DEBUG_CODE_TEST
    if (AppRegs->ChkTestArg(MULTIMODE_INPUT_ANR_NOWINDOW)) {
        WinMgr->SetFocusSurfaceId(RET_ERR);
    }
#endif // DEBUG_CODE_TEST
    int32_t focusId = WinMgr->GetFocusSurfaceId();
    CHKR(!(focusId < 0), FOCUS_ID_OBTAIN_FAIL, FOCUS_ID_OBTAIN_FAIL);
    auto appInfo = AppRegs->FindByWinId(focusId);
    if (appInfo.fd == RET_ERR) {
        return FOCUS_ID_OBTAIN_FAIL;
    }
#ifdef DEBUG_CODE_TEST
    int32_t pid = udsServer_->GetPidByFd(appInfo.fd);
    if (pid != RET_ERR) {
        MMI_LOGT("Inject keyCode = %{public}d,action = %{public}d,focusPid = %{public}d",
            key.key, key.state, pid);
    }
#endif
#ifdef DEBUG_CODE_TEST
    MMI_LOGT("\n4.event dispatcher of server:\neventKeyboard:time=%{public}" PRId64 ";sourceType=%{public}d;key=%{public}u;"
             "seat_key_count=%{public}u;state=%{public}d;fd=%{public}d;abilityId=%{public}d;"
             "windowId=%{public}s(%{public}d).\n*******************************************************\n",
             key.time, LIBINPUT_EVENT_KEYBOARD_KEY, key.key, key.seat_key_count, key.state, appInfo.fd,
             appInfo.abilityId, WinMgr->GetSurfaceIdListString().c_str(), focusId);
#endif

    int32_t testConnectState = 0;
    int32_t testBufferState = 0;
#ifdef DEBUG_CODE_TEST
    if (AppRegs->ChkTestArg(MULTIMODE_INPUT_ANR_NOFD)) {
        appInfo.fd = RET_ERR;
    } else if (AppRegs->ChkTestArg(MULTIMODE_INPUT_ANR_CONNECTDEAD)) {
        testConnectState = RET_ERR;
    } else if (AppRegs->ChkTestArg(MULTIMODE_INPUT_ANR_BUFFERFULL)) {
        testBufferState = RET_ERR;
    }
#endif // DEBUG_CODE_TEST
    if (AppRegs->IsMultimodeInputReady(key.time, MmiMessageId::ON_KEY, appInfo.fd, testConnectState, testBufferState)) {
        NetPacket pkt2(MmiMessageId::ON_KEY);
        pkt2 << key << appInfo.abilityId << focusId << appInfo.fd << key.time;
        if (!udsServer_->SendMsg(appInfo.fd, pkt2)) {
            MMI_LOGE("Sending structure of EventKeyboard failed!\n");
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnInjectPointerEvent(SessionPtr sess, NetPacket& pkt)
{
    MMI_LOGD("Inject-pointer-event received, processing ...");
    auto pointerEvent = OHOS::MMI::PointerEvent::Create();
    CHKR((RET_OK == OHOS::MMI::InputEventDataTransformation::DeserializePointerEvent(false, pointerEvent, pkt)),
        STREAM_BUF_READ_FAIL, RET_ERR);
    int32_t winId { -1 };

    switch (pointerEvent->GetSourceType()) {
        case OHOS::MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN:
        {
            int32_t pointerId { pointerEvent->GetPointerId() };
            OHOS::MMI::PointerEvent::PointerItem pointerItem;
            CHKR(pointerEvent->GetPointerItem(pointerId, pointerItem), PARAM_INPUT_FAIL, RET_ERR);
            std::vector<int32_t> winIds;
            WinMgr->GetTouchSurfaceId(pointerItem.GetGlobalX(), pointerItem.GetGlobalY(), winIds);
            CHKR(!winIds.empty(), FOCUS_ID_OBTAIN_FAIL, RET_ERR);
            winId = winIds[winIds.size() - 1];
            break;
        }
        case OHOS::MMI::PointerEvent::SOURCE_TYPE_MOUSE:
            winId = WinMgr->GetFocusSurfaceId();
            break;
        default:
            MMI_LOGD("Unknown source type!");
            return RET_ERR;
    }

    pointerEvent->SetTargetWindowId(winId);
    pointerEvent->SetAgentWindowId(winId);

    auto appInfo { AppRegs->FindByWinId(winId) };
    CHKR((appInfo.fd != RET_ERR), FOCUS_ID_OBTAIN_FAIL, RET_ERR);

    int32_t connectState {  };
    int32_t bufferState {  };
    InputHandlerManagerGlobal::GetInstance().HandleEvent(pointerEvent);

    if (AppRegs->IsMultimodeInputReady(pointerEvent->GetActionTime(),
        MmiMessageId::ON_POINTER_EVENT, appInfo.fd, connectState, bufferState)) {
        NetPacket rPkt(MmiMessageId::ON_POINTER_EVENT);
        CHKR((RET_OK == OHOS::MMI::InputEventDataTransformation::SerializePointerEvent(pointerEvent, rPkt)),
            STREAM_BUF_WRITE_FAIL, RET_ERR);
        MMI_LOGD("Send pointer event to client!");
        CHKR(udsServer_->SendMsg(appInfo.fd, rPkt), MSG_SEND_FAIL, RET_ERR);
    }
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnAddKeyEventFilter(SessionPtr sess, NetPacket& pkt)
{
    if (sess->GetUid() != SYSTEMUID && sess->GetUid() != 0) {
        MMI_LOGD("Insufficient permissions");
        return RET_ERR;
    }
    int id = 0;
    MMI_LOGD("server add a key event filter");
    std::string name;
    Authority authority;
    pkt>>id>>name>>authority;
    ServerKeyFilter->AddKeyEventFilter(sess, name, id, authority);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnRemoveKeyEventFilter(SessionPtr sess, NetPacket& pkt)
{
    if (sess->GetUid() != SYSTEMUID && sess->GetUid() != 0) {
        MMI_LOGD("Insufficient permissions");
        return RET_ERR;
    }
    int id = 0;
    MMI_LOGD("server remove a key event filter");
    pkt>>id;
    ServerKeyFilter->RemoveKeyEventFilter(sess, id);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnAddTouchEventFilter(SessionPtr sess, NetPacket& pkt)
{
    MMI_LOGD("ServerMsgHandler::OnAddTouchEventFilter");
    if (sess->GetUid() != SYSTEMUID && sess->GetUid() != 0) {
        MMI_LOGD("Insufficient permissions");
        return RET_ERR;
    }
    int32_t id = 0;
    std::string name;
    Authority authority;
    pkt >> id >> name >> authority;
    ServerKeyFilter->AddTouchEventFilter(sess, name, id, authority);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnRemoveTouchEventFilter(SessionPtr sess, NetPacket& pkt)
{
    MMI_LOGD("ServerMsgHandler::OnRemoveTouchEventFilter");
	if (sess->GetUid() != SYSTEMUID && sess->GetUid() != 0) {
        MMI_LOGD("Insufficient permissions");
        return RET_ERR;
    }
    int32_t id = 0;
    pkt >> id;
    ServerKeyFilter->RemoveTouchEventFilter(sess, id);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnDisplayInfo(SessionPtr sess, NetPacket &pkt)
{
    CHKR(sess, NULL_POINTER, RET_ERR);
    MMI_LOGD("ServerMsgHandler::OnDisplayInfo enter");

    std::vector<PhysicalDisplayInfo> physicalDisplays;
    int32_t num = 0;
    pkt.Read(num);
    for (int32_t i = 0; i < num; i++) {
        PhysicalDisplayInfo info;
        pkt.Read(info.id);
        pkt.Read(info.leftDisplayId);
        pkt.Read(info.upDisplayId);
        pkt.Read(info.topLeftX);
        pkt.Read(info.topLeftY);
        pkt.Read(info.width);
        pkt.Read(info.height);
        pkt.Read(info.name);
        pkt.Read(info.seatId);
        pkt.Read(info.seatName);
        pkt.Read(info.logicWidth);
        pkt.Read(info.logicHeight);
        pkt.Read(info.direction);
        physicalDisplays.push_back(info);
    }

    std::vector<LogicalDisplayInfo> logicalDisplays;
    pkt.Read(num);
    for (int32_t i = 0; i < num; i++) {
        LogicalDisplayInfo info;
        pkt.Read(info.id);
        pkt.Read(info.topLeftX);
        pkt.Read(info.topLeftY);
        pkt.Read(info.width);
        pkt.Read(info.height);
        pkt.Read(info.name);
        pkt.Read(info.seatId);
        pkt.Read(info.seatName);
        pkt.Read(info.focusWindowId);

        std::vector<WindowInfo> windowInfos;
        int32_t numWindow = 0;
        pkt.Read(numWindow);
        for (int32_t j = 0; j < numWindow; j++) {
            WindowInfo info;
            pkt.Read(info);
            windowInfos.push_back(info);
        }
        info.windowsInfo_ = windowInfos;
        logicalDisplays.push_back(info);
    }

    OHOS::MMI::InputWindowsManager::GetInstance()->UpdateDisplayInfo(physicalDisplays, logicalDisplays);
    MMI_LOGD("ServerMsgHandler::OnDisplayInfo leave");
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnAddEventInterceptor(SessionPtr sess, NetPacket& pkt)
{
    if (sess->GetUid() != SYSTEMUID && sess->GetUid() != 0) {
        MMI_LOGD("Insufficient permissions");
        return RET_ERR;
    }
    int32_t id = 0;
    MMI_LOGD("server add a pointer event filter");
    std::string name;
    Authority authority;
    pkt >> id >> name >> authority;
    ServerKeyFilter->RegisterEventInterceptorforServer(sess, id, name, authority);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnRemoveEventInterceptor(SessionPtr sess, NetPacket& pkt)
{
    if (sess->GetUid() != SYSTEMUID && sess->GetUid() != 0) {
        MMI_LOGD("Insufficient permissions");
        return RET_ERR;
    }
    int32_t id = 0;
    MMI_LOGD("server remove a pointer event filter");
    pkt >> id;
    ServerKeyFilter->UnregisterEventInterceptorforServer(sess, id);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnAddInputHandler(SessionPtr sess, NetPacket& pkt)
{
    int32_t handlerId { };
    InputHandlerType handlerType { };
    pkt >> handlerId >> handlerType;
    MMI_LOGD("OnAddInputHandler handlerId : %{public}d handlerType : %{public}d", handlerId, handlerType);
    InputHandlerManagerGlobal::GetInstance().AddInputHandler(handlerId, handlerType, sess);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnRemoveInputHandler(SessionPtr sess, NetPacket& pkt)
{
    int32_t handlerId { };
    InputHandlerType handlerType { };
    pkt >> handlerId >> handlerType;
    MMI_LOGD("OnRemoveInputHandler handlerId : %{public}d handlerType : %{public}d", handlerId, handlerType);
    InputHandlerManagerGlobal::GetInstance().RemoveInputHandler(handlerId, handlerType, sess);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnMarkConsumed(SessionPtr sess, NetPacket& pkt)
{
    int32_t monitorId { }, eventId { };
    pkt >> monitorId >> eventId;
    InputHandlerManagerGlobal::GetInstance().MarkConsumed(monitorId, eventId, sess);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnGetDeviceIdList(SessionPtr sess, NetPacket& pkt)
{
    int32_t taskId = 0;
    CHKR(pkt.Read(taskId), STREAM_BUF_READ_FAIL, RET_ERR);

#ifdef OHOS_WESTEN_MODEL
    INPUTDEVMGR->GetDeviceIdListAsync([taskId, sess, this](std::vector<int32_t> idList) {
        CHKR(sess, NULL_POINTER, RET_ERR);
        NetPacket pkt2(MmiMessageId::INPUT_DEVICE_ID_LIST);
        int32_t num = idList.size();
        CHKR(pkt2.Write(taskId), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt2.Write(num), STREAM_BUF_WRITE_FAIL, RET_ERR);
        for (auto it : idList) {
            CHKR(pkt2.Write(it), STREAM_BUF_WRITE_FAIL, RET_ERR);
        }
        if (!sess->SendMsg(pkt2)) {
            MMI_LOGE("Sending structure of OnGetDeviceInfo failed!\n");
        }
        return RET_OK;
    });
#else
    CHKR(sess, NULL_POINTER, RET_ERR);
    std::vector<int32_t> idList = INPUTDEVMGR->GetDeviceIds();
    NetPacket pkt2(MmiMessageId::INPUT_DEVICE_ID_LIST);
    int32_t size = idList.size();
    CHKR(pkt2.Write(taskId), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt2.Write(size), STREAM_BUF_WRITE_FAIL, RET_ERR);
    for (auto it : idList) {
        CHKR(pkt2.Write(it), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    if (!sess->SendMsg(pkt2)) {
        MMI_LOGE("Sending structure of OnGetDeviceInfo failed!\n");
        return MSG_SEND_FAIL;
    }
#endif
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnGetDeviceInfo(SessionPtr sess, NetPacket& pkt)
{
    MMI_LOGE("Sending structure of OnGetDeviceInfo enter!\n");
    int32_t taskId = 0;
    int deviceId = 0;
    CHKR(pkt.Read(taskId), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pkt.Read(deviceId), STREAM_BUF_READ_FAIL, RET_ERR);

#ifdef OHOS_WESTEN_MODEL
    INPUTDEVMGR->FindDeviceByIdAsync(deviceId, [taskId, sess, this](std::shared_ptr<InputDevice> inputDevice) {
        CHKR(sess, NULL_POINTER, RET_ERR);
        NetPacket pkt2(MmiMessageId::INPUT_DEVICE_INFO);
        if (inputDevice == nullptr) {
            int32_t id = -1;
            std::string name = "null";
            int32_t deviceType = -1;

            CHKR(pkt2.Write(taskId), STREAM_BUF_WRITE_FAIL, RET_ERR);
            CHKR(pkt2.Write(id), STREAM_BUF_WRITE_FAIL, RET_ERR);
            CHKR(pkt2.Write(name), STREAM_BUF_WRITE_FAIL, RET_ERR);
            CHKR(pkt2.Write(deviceType), STREAM_BUF_WRITE_FAIL, RET_ERR);
            if (!sess->SendMsg(pkt2)) {
                MMI_LOGE("Sending structure of OnGetDeviceInfo failed!\n");
            }
            return RET_OK;
        }

        int32_t id = inputDevice->GetId();
        std::string name = inputDevice->GetName();
        int32_t deviceType = inputDevice->GetDeviceType();

        CHKR(pkt2.Write(taskId), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt2.Write(id), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt2.Write(name), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt2.Write(deviceType), STREAM_BUF_WRITE_FAIL, RET_ERR);
        if (!sess->SendMsg(pkt2)) {
            MMI_LOGE("Sending structure of OnGetDeviceInfo failed!\n");
        }
        MMI_LOGE("Sending structure of OnGetDeviceInfo success!\n");
        return RET_OK;
    });
#else
    std::shared_ptr<InputDevice> inputDevice = INPUTDEVMGR->GetDevice(deviceId);
    NetPacket pkt2(MmiMessageId::INPUT_DEVICE_INFO);
    if (inputDevice == nullptr) {
        int32_t id = -1;
        std::string name = "null";
        int32_t deviceType = -1;
        CHKR(pkt2.Write(taskId), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt2.Write(id), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt2.Write(name), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt2.Write(deviceType), STREAM_BUF_WRITE_FAIL, RET_ERR);
        if (!sess->SendMsg(pkt2)) {
            MMI_LOGE("Sending structure of OnGetDeviceInfo failed!\n");
            return MSG_SEND_FAIL;
        }
        return RET_OK;
    }
    int32_t id = inputDevice->GetId();
    std::string name = inputDevice->GetName();
    int32_t deviceType = inputDevice->GetDeviceType();
    CHKR(pkt2.Write(taskId), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt2.Write(id), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt2.Write(name), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt2.Write(deviceType), STREAM_BUF_WRITE_FAIL, RET_ERR);
    if (!sess->SendMsg(pkt2)) {
        MMI_LOGE("Sending structure of OnGetDeviceInfo failed!\n");
        return MSG_SEND_FAIL;
    }
#endif
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnAddInputEventMontior(SessionPtr sess, NetPacket& pkt)
{
    CHKR(sess, NULL_POINTER, RET_ERR);
    int32_t eventType = 0;
    pkt >> eventType;
    if (eventType != OHOS::MMI::InputEvent::EVENT_TYPE_KEY) {
        return RET_ERR;
    }
    IEMServiceManager.AddInputEventMontior(eventType, sess);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnRemoveInputEventMontior(SessionPtr sess, NetPacket& pkt)
{
    CHKR(sess, NULL_POINTER, RET_ERR);
    int32_t eventType = 0;
    pkt >> eventType;
    if (eventType != OHOS::MMI::InputEvent::EVENT_TYPE_KEY) {
        return RET_ERR;
    }
    IEMServiceManager.RemoveInputEventMontior(eventType, sess);
    return RET_OK;
}


#ifdef OHOS_AUTO_TEST_FRAME
int32_t OHOS::MMI::ServerMsgHandler::AutoTestFrameRegister(SessionPtr sess, NetPacket& pkt)
{
    CHKR(sess, NULL_POINTER, RET_ERR);
    int32_t fd = sess->GetFd();
    MmiMessageId autoTestRegisterId = MmiMessageId::ST_MESSAGE_BEGIN;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    pkt >> idMsg;

    if (autoTestRegisterId == idMsg) {
        AppRegs->AutoTestSetAutoTestFd(fd);
        MMI_LOGI("AutoTestFrameRegister: Connected succeed! fd is:%{public}d", fd);

        std::vector<AutoTestClientListPkt> clientListPkt;
        AppRegs->AutoTestGetAllAppInfo(clientListPkt);
        uint32_t sizeOfList = static_cast<uint32_t>(clientListPkt.size());
        NetPacket pktAutoTest(MmiMessageId::ST_MESSAGE_CLISTPKT);
        pktAutoTest << sizeOfList;
        for (auto it = clientListPkt.begin(); it != clientListPkt.end(); it++) {
            pktAutoTest << *it;
        }
        if (!udsServer_->SendMsg(AppRegs->AutoTestGetAutoTestFd(), pktAutoTest)) {
            MMI_LOGE("Send ClientList massage failed to auto-test frame !\n");
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::AutoTestReceiveClientPkt(SessionPtr sess, NetPacket& pkt)
{
    if (!AppRegs->AutoTestGetAutoTestFd()) {
        return RET_OK;
    }

    AutoTestClientPkt autoTestClientPkt;
    pkt >> autoTestClientPkt;

    NetPacket pktAutoTest(MmiMessageId::ST_MESSAGE_CLTPKT);
    pktAutoTest << autoTestClientPkt;
    if (!udsServer_->SendMsg(AppRegs->AutoTestGetAutoTestFd(), pktAutoTest)) {
        MMI_LOGE("Send ClientPkt massage failed to auto-test frame !\n");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}
#endif  // OHOS_AUTO_TEST_FRAME
// LCOV_EXCL_STOP
