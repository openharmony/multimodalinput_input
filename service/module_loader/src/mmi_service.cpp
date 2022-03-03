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

#include "mmi_service.h"
#include <cinttypes>
#include <csignal>
#include <sys/signalfd.h>
#include "event_dump.h"
#include "input_windows_manager.h"
#include "mmi_log.h"
#include "multimodal_input_connect_def_parcel.h"
#include "pointer_drawing_manager.h"
#include "timer_manager.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MMIService" };
const std::string DEF_INPUT_SEAT = "seat0";
} // namespace

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
    CHKPV(fmt);
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
    CheckDefineOutput("%-40s", "OHOS_BUILD");
#endif
#ifdef OHOS_BUILD_LIBINPUT
    CheckDefineOutput("%-40s", "OHOS_BUILD_LIBINPUT");
#endif
#ifdef OHOS_BUILD_HDF
    CheckDefineOutput("%-40s", "OHOS_BUILD_HDF");
#endif
#ifdef OHOS_BUILD_MMI_DEBUG
    CheckDefineOutput("%-40s", "OHOS_BUILD_MMI_DEBUG");
#endif
}

MMIService::MMIService() : SystemAbility(MULTIMODAL_INPUT_CONNECT_SERVICE_ID, true) {}

MMIService::~MMIService() {}

int32_t MMIService::AddEpoll(EpollEventType type, int32_t fd)
{
    CHKR((type >= EPOLL_EVENT_BEGIN && type < EPOLL_EVENT_END), PARAM_INPUT_INVALID, RET_ERR);
    CHKR(fd >= 0, PARAM_INPUT_INVALID, RET_ERR);
    CHKR(mmiFd_ >= 0, PARAM_INPUT_INVALID, RET_ERR);
    auto eventData = static_cast<mmi_epoll_event*>(malloc(sizeof(mmi_epoll_event)));
    CHKR(eventData, MALLOC_FAIL, RET_ERR);
    eventData->fd = fd;
    eventData->event_type = type;
    MMI_LOGD("userdata:[fd:%{public}d,type:%{public}d]", eventData->fd, eventData->event_type);

    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.ptr = eventData;
    auto ret = EpollCtl(fd, EPOLL_CTL_ADD, ev, mmiFd_);
    if (ret < 0) {
        free(eventData);
        eventData = nullptr;
        ev.data.ptr = nullptr;
        return ret;
    }
    auto iter = authFds_.emplace(fd);
    if (!iter.second) {
        MMI_LOGE("Emplace to failed, fd:%{public}d", fd);
        return RET_ERR;
    }
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
    if (!(input_.Init(std::bind(&InputEventHandler::OnEvent, inputEventHdr_, std::placeholders::_1),
        DEF_INPUT_SEAT))) {
        MMI_LOGE("libinput initialization failed");
        return false;
    }
    auto inputFd = input_.GetInputFd();
    auto ret = AddEpoll(EPOLL_EVENT_INPUT, inputFd);
    if (ret <  0) {
        MMI_LOGE("AddEpoll error ret:%{public}d", ret);
        EpollClose();
        return false;
    }
    MMI_LOGD("AddEpoll, epollfd:%{public}d,fd:%{public}d", mmiFd_, inputFd);
    return true;
}

bool MMIService::InitService()
{
    if (state_ != ServiceRunningState::STATE_NOT_START) {
        MMI_LOGE("Service running status is not enabled");
        return false;
    }
    if (!(Publish(this))) {
        MMI_LOGE("Service initialization failed");
        return false;
    }
    if (EpollCreat(MAX_EVENT_SIZE) < 0) {
        MMI_LOGE("epoll create failed");
        return false;
    }
    auto ret = AddEpoll(EPOLL_EVENT_SOCKET, epollFd_);
    if (ret <  0) {
        MMI_LOGE("AddEpoll error ret:%{public}d", ret);
        EpollClose();
        return false;
    }
    MMI_LOGD("AddEpoll, epollfd:%{public}d,fd:%{public}d", mmiFd_, epollFd_);
    return true;
}

int32_t MMIService::Init()
{
    CheckDefine();

    MMI_LOGD("InputEventHandler Init");
    InputHandler->Init(*this);

    MMI_LOGD("ServerMsgHandler Init");
    CHKR(sMsgHandler_.Init(*this), SVR_MSG_HANDLER_INIT_FAIL, SVR_MSG_HANDLER_INIT_FAIL);

    MMI_LOGD("EventDump Init");
    MMIEventDump->Init(*this);

    MMI_LOGD("WindowsManager Init");
    CHKR(WinMgr->Init(*this), WINDOWS_MSG_INIT_FAIL, WINDOWS_MSG_INIT_FAIL);

    MMI_LOGD("PointerDrawingManager Init");
    CHKR(PointerDrawingManager::GetInstance()->Init(), POINTER_DRAW_INIT_FAIL, POINTER_DRAW_INIT_FAIL);

    mmiFd_ = EpollCreat(MAX_EVENT_SIZE);
    CHKR(mmiFd_ >= 0, EPOLL_CREATE_FAIL, EPOLL_CREATE_FAIL);
    CHKR(InitService(), SASERVICE_INIT_FAIL, SASERVICE_INIT_FAIL);
    CHKR(InitLibinputService(), LIBINPUT_INIT_FAIL, LIBINPUT_INIT_FAIL);
    CHKR(InitSignalHandler(), INIT_SIGNAL_HANDLER_FAIL, INIT_SIGNAL_HANDLER_FAIL);
    SetRecvFun(std::bind(&ServerMsgHandler::OnMsgHandler, &sMsgHandler_, std::placeholders::_1, std::placeholders::_2));
    return RET_OK;
}

void MMIService::OnStart()
{
    auto tid = GetThisThreadIdOfLL();
    MMI_LOGD("Thread tid:%{public}" PRId64 "", tid);

    int32_t ret = Init();
    if (RET_OK != ret) {
        MMI_LOGE("Init mmi_service failed");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    MMI_LOGD("Started successfully");
    t_ = std::thread(std::bind(&MMIService::OnThread, this));
    t_.detach();
}

void MMIService::OnStop()
{
    auto tid = GetThisThreadIdOfLL();
    MMI_LOGD("Thread tid:%{public}" PRId64 "", tid);

    UdsStop();
    if (InputHandler != nullptr) {
        InputHandler->Clear();
    }
    input_.Stop();
    state_ = ServiceRunningState::STATE_NOT_START;
}

void MMIService::OnDump()
{
    auto tid = GetThisThreadIdOfLL();
    MMI_LOGD("Thread tid:%{public}" PRId64 "", tid);
    MMIEventDump->Dump();
}

void MMIService::OnConnected(SessionPtr s)
{
    CHKPV(s);
    int32_t fd = s->GetFd();
    MMI_LOGI("fd:%{public}d", fd);
}

void MMIService::OnDisconnected(SessionPtr s)
{
    CHKPV(s);
    int32_t fd = s->GetFd();
    MMI_LOGW("enter, session desc:%{public}s, fd: %{public}d", s->GetDescript().c_str(), fd);
}

int32_t MMIService::AllocSocketFd(const std::string &programName, const int32_t moduleType, int32_t &toReturnClientFd)
{
    MMI_LOGI("enter, programName:%{public}s,moduleType:%{public}d",
             programName.c_str(), moduleType);

    toReturnClientFd = INVALID_SOCKET_FD;
    int32_t serverFd = INVALID_SOCKET_FD;
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t pid = IPCSkeleton::GetCallingPid();
    const int32_t ret = AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd);
    if (ret != RET_OK) {
        MMI_LOGE("call AddSocketPairInfo return %{public}d", ret);
        return RET_ERR;
    }

    MMI_LOGIK("leave, programName:%{public}s,moduleType:%{public}d,alloc success",
        programName.c_str(), moduleType);

    return RET_OK;
}

int32_t MMIService::StubHandleAllocSocketFd(MessageParcel& data, MessageParcel& reply)
{
    sptr<ConnectReqParcel> req = data.ReadParcelable<ConnectReqParcel>();
    if (req == nullptr) {
        MMI_LOGE("read data error.");
        return RET_ERR;
    }
    MMI_LOGIK("clientName:%{public}s,moduleId:%{public}d", req->data.clientName.c_str(), req->data.moduleId);

    int32_t clientFd = INVALID_SOCKET_FD;
    int32_t ret = AllocSocketFd(req->data.clientName, req->data.moduleId, clientFd);
    if (ret != RET_OK) {
        MMI_LOGE("call AddSocketPairInfo return %{public}d", ret);
        reply.WriteInt32(RET_ERR);
        return RET_ERR;
    }

    MMI_LOGI("call AllocSocketFd success");

    reply.WriteInt32(RET_OK);
    reply.WriteFileDescriptor(clientFd);

    MMI_LOGI("send clientFd to client, clientFd = %d", clientFd);
    close(clientFd);
    return RET_OK;
}

int32_t MMIService::AddInputEventFilter(sptr<IEventFilter> filter)
{
    if (InputHandler == nullptr) {
        MMI_LOGE("InputHandler is nullptr");
        return ERROR_NULL_POINTER;
    }
    return InputHandler->AddInputEventFilter(filter);
}

void MMIService::OnTimer()
{
    if (InputHandler != nullptr) {
        InputHandler->OnCheckEventReport();
    }
    TimerMgr->ProcessTimers();
}

void MMIService::OnThread()
{
    OHOS::MMI::SetThreadName(std::string("mmi_service"));
    uint64_t tid = GetThisThreadIdOfLL();
    if (tid <= 0) {
        MMI_LOGE("The tid is error, errCode:%{public}d", VAL_NOT_EXP);
        return;
    }
    MMI_LOGI("Main worker thread start. tid:%{public}" PRId64 "", tid);

    int32_t count = 0;
    constexpr int32_t timeOut = 20;
    struct epoll_event ev[MAX_EVENT_SIZE] = {};
    std::map<int32_t, StreamBufData> bufMap;
    while (state_ == ServiceRunningState::STATE_RUNNING) {
        bufMap.clear();
        count = EpollWait(ev[0], MAX_EVENT_SIZE, timeOut, mmiFd_);
        for (int32_t i = 0; i < count && state_ == ServiceRunningState::STATE_RUNNING; i++) {
            auto mmiEd = reinterpret_cast<mmi_epoll_event*>(ev[i].data.ptr);
            CHKPC(mmiEd);
            if (mmiEd->event_type == EPOLL_EVENT_INPUT) {
                input_.EventDispatch(ev[i]);
            } else if (mmiEd->event_type == EPOLL_EVENT_SOCKET) {
                OnEpollEvent(bufMap, ev[i]);
            } else if (mmiEd->event_type == EPOLL_EVENT_SIGNAL) {
                OnSignalEvent(mmiEd->fd);
            } else {
                MMI_LOGW("unknown epoll event type:%{public}d", mmiEd->event_type);
            }
        }
        if (state_ != ServiceRunningState::STATE_RUNNING) {
            break;
        }
        for (auto& it : bufMap) {
            if (it.second.isOverflow) {
                continue;
            }
            OnEpollRecv(it.first, it.second.sBuf.Data(), it.second.sBuf.Size());
        }
        OnTimer();
    }
    MMI_LOGI("Main worker thread stop. tid:%{public}" PRId64 "", tid);
}

bool MMIService::InitSignalHandler()
{
    MMI_LOGD("enter");
    sigset_t mask = {0};
    int32_t retCode = sigfillset(&mask);
    if (retCode < 0) {
        MMI_LOGE("fill signal set failed:%{public}s", strerror(errno));
        return false;
    }

    retCode = sigprocmask(SIG_SETMASK, &mask, nullptr);
    if (retCode < 0) {
        MMI_LOGE("sigprocmask failed:%{public}s", strerror(errno));
        return false;
    }

    int32_t fdSignal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
    if (fdSignal < 0) {
        MMI_LOGE("signal fd failed:%{public}s", strerror(errno));
        return false;
    }

    retCode = AddEpoll(EPOLL_EVENT_SIGNAL, fdSignal);
    if (retCode < 0) {
        MMI_LOGE("AddEpoll signalFd failed:%{public}d", retCode);
        close(fdSignal);
        return false;
    }

    MMI_LOGD("Leave");
    return true;
}

void MMIService::OnSignalEvent(int32_t signalFd)
{
    MMI_LOGD("enter");
    signalfd_siginfo sigInfo;
    int32_t size = ::read(signalFd, &sigInfo, sizeof(signalfd_siginfo));
    if (size != sizeof(signalfd_siginfo)) {
        const int errnoSaved = errno;
        MMI_LOGE("read signal info faild, invalid size:%{public}d,errno:%{public}d,%{public}s",
            size, errnoSaved, strerror(errnoSaved));
        return;
    }

    int32_t signo = sigInfo.ssi_signo;
    MMI_LOGD("receive signal:%{public}d", signo);
    switch (signo) {
        case SIGINT:
        case SIGQUIT:
        case SIGILL:
        case SIGABRT:
        case SIGBUS:
        case SIGFPE:
        case SIGKILL:
        case SIGSEGV:
        case SIGTERM:
            state_ = ServiceRunningState::STATE_EXIT;
            break;
        default:
            break;
    }
    MMI_LOGD("leave");
}

} // namespace MMI
} // namespace OHOS
