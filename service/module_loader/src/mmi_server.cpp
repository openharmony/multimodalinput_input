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

#include "mmi_server.h"
#include <inttypes.h>
#include "event_dump.h"
#include "log.h"
#include "multimodal_input_connect_service.h"
#include "util.h"

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MMIServer" };
    }
}

template<class ...Ts>
void CheckDefineOutput(const char* fmt, Ts... args)
{
    using namespace OHOS::MMI;
    if (fmt == nullptr) {
        KMSG_LOGE("in ChkConfigOutput, fmt is nullptr");
        return;
    }
    int32_t ret = 0;

    char buf[MAX_STREAM_BUF_SIZE] = {};
    ret = snprintf_s(buf, MAX_STREAM_BUF_SIZE, MAX_STREAM_BUF_SIZE - 1, fmt, args...);
    if (ret < 0) {
        KMSG_LOGI("call snprintf_s fail.ret = %d", ret);
        return;
    }

    KMSG_LOGI("%s", buf);
    MMI_LOGI("%s", buf);
}

static void CheckDefine()
{
    CheckDefineOutput("ChkDefs:");
#ifdef OHOS_BUILD
    CheckDefineOutput("%-40s", "\tOHOS_BUILD");
#endif
#ifdef OHOS_WESTEN_MODEL
    CheckDefineOutput("%-40s", "\tOHOS_WESTEN_MODEL");
#endif
#ifdef OHOS_AUTO_TEST_FRAME
    CheckDefineOutput("%-40s", "\tOHOS_AUTO_TEST_FRAME");
#endif
#ifdef OHOS_BUILD_LIBINPUT
    CheckDefineOutput("%-40s", "\tOHOS_BUILD_LIBINPUT");
#endif
#ifdef OHOS_BUILD_HDF
    CheckDefineOutput("%-40s", "\tOHOS_BUILD_HDF");
#endif
#ifdef OHOS_BUILD_AI
    CheckDefineOutput("%-40s", "\tOHOS_BUILD_AI");
#endif
#ifdef DEBUG_CODE_TEST
    CheckDefineOutput("%-40s", "\tDEBUG_CODE_TEST");
#endif
#ifdef OHOS_BUILD_MMI_DEBUG
    CheckDefineOutput("%-40s", "\tOHOS_BUILD_MMI_DEBUG");
#endif
}

OHOS::MMI::MMIServer::MMIServer()
{
}

OHOS::MMI::MMIServer::~MMIServer()
{
    MMI_LOGT("enter");
}

int32_t OHOS::MMI::MMIServer::Start()
{
    CheckDefine();
    uint64_t tid = GetThisThreadIdOfLL();
    MMI_LOGD("Main Thread tid:%{public}" PRId64 "", tid);

    int32_t ret = RET_OK;
    ret = SaConnectServiceRegister();
    CHKR((ret == RET_OK), ret, ret);

    ret = InitExpSoLibrary();
    CHKR((ret == RET_OK), ret, ret);

    MMI_LOGD("Screen_Manager Init");
    CHKR(WinMgr->Init(*this), WINDOWS_MSG_INIT_FAIL, WINDOWS_MSG_INIT_FAIL);

    MMI_LOGD("AppRegister Init");
    CHKR(AppRegs->Init(*this), APP_REG_INIT_FAIL, APP_REG_INIT_FAIL);

    MMI_LOGD("DeviceRegister Init");
    CHKR(DevRegister->Init(), DEV_REG_INIT_FAIL, DEV_REG_INIT_FAIL);

    MMI_LOGD("MsgHandler Init");
    CHKR(sMsgHandler_.Init(*this), SVR_MSG_HANDLER_INIT_FAIL, SVR_MSG_HANDLER_INIT_FAIL);
#ifdef  OHOS_BUILD_AI
    MMI_LOGD("SeniorInput Init");
    CHKR(seniorInput_.Init(*this), SENIOR_INPUT_DEV_INIT_FAIL, SENIOR_INPUT_DEV_INIT_FAIL);
    sMsgHandler_.SetSeniorInputHandle(seniorInput_);
#endif // OHOS_BUILD_AI

    MMIEventDump->Init(*this);
    ret = InitLibinput();
    CHKR((ret == RET_OK), ret, ret);
    SetRecvFun(std::bind(&ServerMsgHandler::OnMsgHandler, &sMsgHandler_, std::placeholders::_1, std::placeholders::_2));

    CHKR(StartServer(), LIBMMI_SVR_START_FAIL, LIBMMI_SVR_START_FAIL);

    ret = SaConnectServiceStart();
    CHKR((ret == RET_OK), ret, ret);

#ifdef DEBUG_CODE_TEST
    uint64_t curTime = OHOS::MMI::GetMillisTime();
    uint64_t consumeTime = curTime - GetMmiServerStartTime();
    MMI_LOGW("The server started successfully, the time consumed was %{public}" PRId64
             " Ms curTime:%{public}" PRId64 "", consumeTime, curTime);
#endif
    return RET_OK;
}

int32_t OHOS::MMI::MMIServer::InitExpSoLibrary()
{
    MMI_LOGD("Load Expansibility Operation");
    auto expConf = GetEnv("EXP_CONF");
    if (expConf.empty()) {
        expConf = DEF_EXP_CONFIG;
    }
    auto expSOPath = GetEnv("EXP_SOPATH");
    if (expSOPath.empty()) {
        expSOPath = DEF_EXP_SOPATH;
    }
    expOper_.LoadExteralLibrary(expConf.c_str(), expSOPath.c_str());
    return RET_OK;
}

int32_t OHOS::MMI::MMIServer::InitLibinput()
{
    MMI_LOGD("Libinput event handle init");
    CHKR(InputHandler->Init(*this), INPUT_EVENT_HANDLER_INIT_FAIL, INPUT_EVENT_HANDLER_INIT_FAIL);

#ifdef OHOS_BUILD_HDF
    MMI_LOGD("HDF Init");
    SetLibInputEventListener([](struct multimodal_libinput_event *event) {
        InputHandler->OnEvent(event);
    });
    hdfEventManager.SetupCallback();
#else
    #ifdef OHOS_WESTEN_MODEL
        MMI_LOGD("InitLibinput WestonInit...");
        SetLibInputEventListener([](struct multimodal_libinput_event *event) {
            InputHandler->OnEvent(event);
        });
    #else
        auto seatId = GetEnv("MI_SEATID");
        if (seatId.empty()) {
            seatId = DEF_SEAT_ID;
        }
        MMI_LOGD("MMIServer: seat:%{public}s", seatId.c_str());
        if (!input_.Init(std::bind(&InputEventHandler::OnEvent, InputHandler, std::placeholders::_1),
            seatId)) {
            MMI_LOGE("libinput Init Failed");
            return LIBINPUT_INIT_FAIL;
        }
        MMI_LOGD("libinput start");
    #endif
#endif
    return RET_OK;
}

void OHOS::MMI::MMIServer::OnTimer()
{
    InputHandler->OnCheckEventReport();
}

void OHOS::MMI::MMIServer::StopAll()
{
    MMI_LOGD("enter");
    int32_t ret = SaConnectServiceStop();
    if (ret != RET_OK) {
        MMI_LOGE("call SaConnectServiceStop fail, ret = %{public}d.", ret);
    }
    UdsStop();
    RegEventHM->Clear();
    InputHandler->Clear();
#ifndef OHOS_WESTEN_MODEL
    input_.Stop();
#endif
    MMI_LOGD("leave");
}

int32_t OHOS::MMI::MMIServer::SaConnectServiceRegister()
{
    MMI_LOGT("enter.");

    int32_t ret;

    ret = MultimodalInputConnectServiceSetUdsServer(this);
    if (ret != RET_OK) {
        MMI_LOGE("MultimodalInputConnectServiceSetUdsServer fail, ret = %{public}d.", ret);
        return RET_ERR;
    }

    ret = EpollCreat(MAX_EVENT_SIZE);
    if (ret == -1) {
        MMI_LOGE("call EpollCreat fail");
        return RET_ERR;
    }

    return RET_OK;
}

int32_t OHOS::MMI::MMIServer::SaConnectServiceStart()
{
    MMI_LOGT("enter.");

    int32_t ret = MultimodalInputConnectServiceStart();
    if (ret != RET_OK) {
        MMI_LOGE("call MultimodalInputConnectServiceStart fail, ret = %{public}d.", ret);
        return RET_ERR;
    }

    return RET_OK;
}

int32_t OHOS::MMI::MMIServer::SaConnectServiceStop()
{
    MMI_LOGT("enter.");

    int32_t ret = MultimodalInputConnectServiceStop();
    if (ret != RET_OK) {
        MMI_LOGE("call MultimodalInputConnectServiceStop fail, ret = %{public}d.", ret);
        return RET_ERR;
    }

    return RET_OK;
}

void OHOS::MMI::MMIServer::OnConnected(SessionPtr s)
{
    CHK(s, NULL_POINTER);
    int32_t fd = s->GetFd();
    MMI_LOGI("MMIServer::_OnConnected fd:%{public}d", fd);
    AppRegs->RegisterConnectState(fd);
}

void OHOS::MMI::MMIServer::OnDisconnected(SessionPtr s)
{
    CHK(s, NULL_POINTER);
    MMI_LOGW("MMIServer::OnDisconnected enter, session desc:%{public}s", s->GetDescript().c_str());
    int32_t fd = s->GetFd();

    auto appInfo = AppRegs->FindBySocketFd(fd);
    RegEventHM->UnregisterEventHandleBySocketFd(fd);
    AppRegs->UnregisterAppInfoBySocketFd(fd);
    AppRegs->UnregisterConnectState(fd);
#ifdef  OHOS_BUILD_AI
    seniorInput_.DeviceDisconnect(fd);
#endif // OHOS_BUILD_AI
}

