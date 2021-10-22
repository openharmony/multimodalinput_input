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
#include "time_cost_chk.h"
#include "mmi_server.h"
#include "event_dump.h"
#include "ai_func_proc.h"
#include "knuckle_func_proc.h"

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

template<class MemberFunType, class ClassType>
auto MsgCallbackBind2(MemberFunType func, ClassType* obj)
{
    return std::bind(func, obj, std::placeholders::_1, std::placeholders::_2);
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

    const uint32_t responseCode = seniorInput_->ReplyMessage(SessionPtr, processResult);
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
#endif
    MMI_LOGD("OnRegisterAppInfo abilityId:%{public}d winId:%{public}d fd:%{public}d bundlerName:%{public}s "
             "appName:%{public}s", abilityId, windowId, fd, bundlerName.c_str(), appName.c_str());

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
        AppRegs->RegisterAppInfoforServer({ abilityId, winId, fd, bundlerName, appName });
    }
    MMI_LOGD("OnRegisterMsgHandler abilityId:%{public}d winId:%{public}d fd:%{public}d eventType:%{public}d"
             " bundlerName:%{public}s appName:%{public}s",
             abilityId, winId, fd, eventType, bundlerName.c_str(), appName.c_str());
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
    VirtualKey event;
    pkt >> event;
    MMI_LOGT("time:%{public}u,keycode:%{public}u,maxCode:%{public}u,state:%{public}u",
             event.keyDownDuration, event.keyCode, event.maxKeyCode, event.isPressed);
    struct EventKeyboard key = {};
    key.time = event.keyDownDuration;
    key.key = event.keyCode;
    key.state = (enum KEY_STATE)event.isPressed;

    if (key.key == HOS_KEY_HOME || key.key == HOS_KEY_VIRTUAL_MULTITASK) {
        return RET_OK;
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
        pkt2 << key << appInfo.abilityId << focusId << appInfo.fd;
        if (!udsServer_->SendMsg(appInfo.fd, pkt2)) {
            MMI_LOGE("Sending structure of EventKeyboard failed!\n");
            return MSG_SEND_FAIL;
        }
    }
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
