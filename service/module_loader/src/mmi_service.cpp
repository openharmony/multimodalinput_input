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

#include "mmi_service.h"
#include <cinttypes>
#include "app_register.h"
#include "device_register.h"
#include "event_dump.h"
#include "input_windows_manager.h"
#include "log.h"
#include "multimodal_input_connect_def_parcel.h"
#include "register_eventhandle_manager.h"
#include "safe_keeper.h"
#include "timer_manager.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MMIService" };
static const std::string DEF_INPUT_SEAT = "seat0";
}
const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<MMIService>::GetInstance().get());

struct mmi_epoll_event {
    int32_t fd;
    EpollEventType event_type;
};

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
    MMI_LOGI("%{public}s", buf);
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

MMIService::MMIService() : SystemAbility(MULTIMODAL_INPUT_CONNECT_SERVICE_ID, true)
{
}

MMIService::~MMIService()
{
}

int32_t MMIService::EpollCtlAdd(EpollEventType type, int32_t fd)
{
    CHKR((type >= EPOLL_EVENT_BEGIN && type < EPOLL_EVENT_END), PARAM_INPUT_INVALID, RET_ERR);
    CHKR(fd >= 0, PARAM_INPUT_INVALID, RET_ERR);
    CHKR(mmiFd_ >= 0, PARAM_INPUT_INVALID, RET_ERR);
    auto ed = static_cast<mmi_epoll_event*>(malloc(sizeof(mmi_epoll_event)));
    CHKR(ed, MALLOC_FAIL, RET_ERR);
    ed->fd = fd;
    ed->event_type = type;
    MMI_LOGD("MMIService::EpollCtlAdd userdata:[fd:%{public}d, type:%{public}d]", ed->fd, ed->event_type);

    epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.ptr = ed;
    auto ret = EpollCtl(fd, EPOLL_CTL_ADD, ev, mmiFd_);
    if (ret < 0) {
        free(ed);
        ed = nullptr;
        ev.data.ptr = nullptr;
        return ret;
    }
    authFds_.emplace(fd);
    return RET_OK;
}

bool MMIService::ChkAuthFd(int32_t fd) const
{
    if (authFds_.find(fd) == authFds_.end()) {
        return false;
    }
    return true;
}

bool MMIService::InitLibinputService()
{
#ifdef OHOS_BUILD_HDF
    MMI_LOGD("HDF Init");
    hdfEventManager.SetupCallback();
#endif
    CHKF(input_.Init(std::bind(&InputEventHandler::OnEvent, inputEventHdr_, std::placeholders::_1),
         DEF_INPUT_SEAT), LIBINPUT_INIT_FAIL);
    auto inputFd = input_.GetInputFd();
    auto ret = EpollCtlAdd(EPOLL_EVENT_INPUT, inputFd);
    if (ret <  0) {
        MMI_LOGE("InitLibinputService EpollCtlAdd error ret = %{public}d", ret);
        EpollClose();
        return false;
    }
    MMI_LOGD("MMIService::InitLibinputService EpollCtlAdd, epollfd:%{public}d fd:%{public}d", mmiFd_, inputFd);
    return true;
}

bool MMIService::InitSAService()
{
    CHKF(state_ == ServiceRunningState::STATE_NOT_START, SASERVICE_INIT_FAIL);
    CHKF(Publish(DelayedSingleton<MMIService>::GetInstance().get()), SASERVICE_INIT_FAIL);
    CHKF(EpollCreat(MAX_EVENT_SIZE) >= 0, SASERVICE_INIT_FAIL);
    auto ret = EpollCtlAdd(EPOLL_EVENT_SOCKET, epollFd_);
    if (ret <  0) {
        MMI_LOGE("InitSAService EpollCtlAdd error ret = %{public}d", ret);
        EpollClose();
        return false;
    }
    MMI_LOGD("MMIService::InitLibinputService EpollCtlAdd, epollfd:%{public}d fd:%{public}d", mmiFd_, epollFd_);
    return true;
}

bool MMIService::InitExpSoLibrary()
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
    return true;
}

int32_t MMIService::Init()
{
    CheckDefine();
    CHKR(InitExpSoLibrary(), EXP_SO_LIBY_INIT_FAIL, EXP_SO_LIBY_INIT_FAIL);

#ifdef  OHOS_BUILD_AI
    MMI_LOGD("SeniorInput Init");
    CHKR(seniorInput_.Init(*this), SENIOR_INPUT_DEV_INIT_FAIL, SENIOR_INPUT_DEV_INIT_FAIL);
    sMsgHandler_.SetSeniorInputHandle(seniorInput_);
#endif // OHOS_BUILD_AI

    MMI_LOGD("InputEventHandler Init");
    inputEventHdr_ = OHOS::MMI::InputEventHandler::GetInstance();
    CHKR(inputEventHdr_->Init(*this), INPUT_EVENT_HANDLER_INIT_FAIL, INPUT_EVENT_HANDLER_INIT_FAIL);

    MMI_LOGD("ServerMsgHandler Init");
    CHKR(sMsgHandler_.Init(*this), SVR_MSG_HANDLER_INIT_FAIL, SVR_MSG_HANDLER_INIT_FAIL);

    MMI_LOGD("EventDump Init");
    MMIEventDump->Init(*this);

    MMI_LOGD("WindowsManager Init");
    CHKR(WinMgr->Init(*this), WINDOWS_MSG_INIT_FAIL, WINDOWS_MSG_INIT_FAIL);

    MMI_LOGD("AppRegister Init");
    CHKR(AppRegs->Init(*this), APP_REG_INIT_FAIL, APP_REG_INIT_FAIL);

    MMI_LOGD("DeviceRegister Init");
    CHKR(DevRegister->Init(), DEV_REG_INIT_FAIL, DEV_REG_INIT_FAIL);

    mmiFd_ = EpollCreat(MAX_EVENT_SIZE);
    CHKR(mmiFd_ >= 0, EPOLL_CREATE_FAIL, EPOLL_CREATE_FAIL);
    CHKR(InitSAService(), SASERVICE_INIT_FAIL, SASERVICE_INIT_FAIL);
    CHKR(InitLibinputService(), LIBINPUT_INIT_FAIL, LIBINPUT_INIT_FAIL);
    SetRecvFun(std::bind(&ServerMsgHandler::OnMsgHandler, &sMsgHandler_, std::placeholders::_1, std::placeholders::_2));
    return RET_OK;
}

void MMIService::OnStart()
{
    auto tid = GetThisThreadIdOfLL();
    MMI_LOGD("SA_OnStart Thread tid:%{public}" PRId64 "", tid);

    int32_t ret = 0;
    CHK((RET_OK == (ret = Init())), ret);
    state_ = ServiceRunningState::STATE_RUNNING;
    MMI_LOGD("MMIService Started successfully...");
    t_ = std::thread(std::bind(&MMIService::OnThread, this));
    t_.detach();
}

void MMIService::OnStop()
{
    auto tid = GetThisThreadIdOfLL();
    MMI_LOGD("SA_OnStop Thread tid:%{public}" PRId64 "", tid);

    UdsStop();
    RegEventHM->Clear();
    if (inputEventHdr_ != nullptr) {
        inputEventHdr_->Clear();
    }
    input_.Stop();
    state_ = ServiceRunningState::STATE_NOT_START;
}

void MMIService::OnDump()
{
    auto tid = GetThisThreadIdOfLL();
    MMI_LOGD("SA_OnDump Thread tid:%{public}" PRId64 "", tid);
    MMIEventDump->Dump();
}

void MMIService::OnConnected(SessionPtr s)
{
    CHK(s, NULL_POINTER);
    int32_t fd = s->GetFd();
    MMI_LOGI("MMIService::_OnConnected fd:%{public}d", fd);
    AppRegs->RegisterConnectState(fd);
}

void MMIService::OnDisconnected(SessionPtr s)
{
    CHK(s, NULL_POINTER);
    MMI_LOGW("MMIService::OnDisconnected enter, session desc:%{public}s", s->GetDescript().c_str());
    int32_t fd = s->GetFd();

    auto appInfo = AppRegs->FindBySocketFd(fd);
    AppRegs->UnregisterConnectState(fd);
#ifdef  OHOS_BUILD_AI
    seniorInput_.DeviceDisconnect(fd);
#endif // OHOS_BUILD_AI
}

int32_t MMIService::AllocSocketFd(const std::string &programName, const int moduleType, int &toReturnClientFd)
{
    MMI_LOGI("MMIService::AllocSocketFd enter, programName: %{public}s, moduleType: %{public}d",
             programName.c_str(), moduleType);

    toReturnClientFd = INVALID_SOCKET_FD;
    int serverFd = INVALID_SOCKET_FD;
    int32_t uid = GetCallingUid();
    int32_t pid = GetCallingPid();
    const int32_t ret = AddSocketPairInfo(programName, moduleType, serverFd, toReturnClientFd, uid, pid);
    if (ret != RET_OK) {
        MMI_LOGE("call AddSocketPairInfo return %{public}d.", ret);
        return RET_ERR;
    }

    MMI_LOGIK("leave, programName: %{public}s, moduleType: %{public}d, alloc success.",
        programName.c_str(), moduleType);

    return RET_OK;
}

int32_t MMIService::HandleAllocSocketFd(MessageParcel& data, MessageParcel& reply)
{
    int32_t ret = RET_OK;
    sptr<ConnectDefReqParcel> req = data.ReadParcelable<ConnectDefReqParcel>();
    if (req == nullptr) {
        MMI_LOGE("read data error.");
        return RET_ERR;
    }

    MMI_LOGIK("clientName = %{public}s, moduleId = %{public}d", req->data.clientName.c_str(), req->data.moduleId);
    if (!IsAuthorizedCalling()) {
        MMI_LOGE("permission denied");
        return RET_ERR;
    }

    int clientFd = INVALID_SOCKET_FD;
    ret = AllocSocketFd(req->data.clientName, req->data.moduleId, clientFd);
    if (ret != RET_OK) {
        MMI_LOGE("call AddSocketPairInfo return %{public}d.", ret);
        reply.WriteInt32(RET_ERR);
        return RET_ERR;
    }

    MMI_LOGI("call AllocSocketFd success.");

    reply.WriteInt32(RET_OK);
    reply.WriteFileDescriptor(clientFd);

    MMI_LOGI("send clientFd to client, clientFd = %d", clientFd);
    close(clientFd);
    clientFd = -1;
    MMI_LOGI(" clientFd = %d, has closed in server", clientFd);

    return RET_OK;
}

int32_t MMIService::SetInputEventFilter(sptr<IEventFilter> filter)
{
    if (inputEventHdr_ == nullptr) {
        MMI_LOGE("inputEventHdr_ is nullptr");
        return NULL_POINTER;
    }

    return inputEventHdr_->SetInputEventFilter(filter);
}

void MMIService::OnTimer()
{
    if (inputEventHdr_ != nullptr) {
        inputEventHdr_->OnCheckEventReport();
    }

    TimerMgr->ProcessTimers();
}

void MMIService::OnThread()
{
    OHOS::MMI::SetThreadName(std::string("mmi_service"));
    uint64_t tid = GetThisThreadIdOfLL();
    CHK(tid > 0, VAL_NOT_EXP);
    MMI_LOGI("Main worker thread start... tid:%{public}" PRId64 "", tid);
    SafeKpr->RegisterEvent(tid, "mmi_service");

    int32_t count = 0;
    constexpr int32_t timeOut = 50;
    epoll_event ev[MAX_EVENT_SIZE] = {};
    CLMAP<int32_t, StreamBufData> bufMap;
    while (state_ == ServiceRunningState::STATE_RUNNING) {
        bufMap.clear();
        count = EpollWait(ev[0], MAX_EVENT_SIZE, timeOut, mmiFd_);
        for (int i = 0; i < count; i++) {
            auto mmiEd = reinterpret_cast<mmi_epoll_event*>(ev[i].data.ptr);
            CHKC(mmiEd, NULL_POINTER);
            if (mmiEd->event_type == EPOLL_EVENT_INPUT) {
                input_.EventDispatch(ev[i]);
            } else { // EPOLL_EVENT_SOCKET
                OnEpollEvent(ev[i], bufMap);
            }
        }
        for (auto& it : bufMap) {
            if (it.second.isOverflow) {
                continue;
            }
            OnEpollRecv(it.first, it.second.sBuf.Data(), it.second.sBuf.Size());
        }
        SafeKpr->ReportHealthStatus(tid);
        OnTimer();
    }
    MMI_LOGI("Main worker thread stop... tid:%{public}" PRId64 "", tid);
}

}
}
