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

#include <cinttypes>
#include <dirent.h>
#include <fstream>
#include <signal.h>
#include <sys/stat.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <unistd.h>

#include "app_register.h"
#include "device_register.h"
#include "event_dump.h"
#include "input_windows_manager.h"
#include "multimodal_input_connect_def_parcel.h"
#include "register_eventhandle_manager.h"
#include "safe_keeper.h"
#include "timer_manager.h"
#include "util.h"
#include "log.h"
#include "mmi_service.h"

namespace OHOS {
namespace MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MMIService" };
static const std::string DEF_INPUT_SEAT = "seat0";

void GetDevInputDirs(std::set<std::string> & dirs)
{
    DIR *dir_p;
    struct  dirent *direntp;
    const char *dirname = "/dev/input/";

    if  ((dir_p = opendir(dirname)) == NULL) {
        MMI_LOGE("opendir fail, dirname: %{public}s", dirname);
        return;
    } else {
        while  ((direntp = readdir (dir_p)) != NULL)
        {
            dirs.insert(std::string(direntp->d_name));
        }
        closedir(dir_p);
    }
}

void GetProcBusInputDevicesInfo(std::set<int> &deviceEventXs)
{
    std::ifstream in("/proc/bus/input/devices"); 
    if (!in) {
        MMI_LOGE("can not open device file");
        return;
    }

    const std::string strHandlerFlag = "H: Handlers=";
    const size_t strHandlerFlagSize = strHandlerFlag.size();

    const std::string strEventFlag = "event";
    const size_t strEventFlagSize = strEventFlag.size();

    std::string line;  
    while (getline(in, line)) {
        size_t pos = line.find(strHandlerFlag);
        if (pos == std::string::npos) {
            continue;
        }

        pos = line.rfind(strEventFlag);
        if (pos == std::string::npos) {
            continue;
        }

        std::string strEventId = line.substr(pos + strEventFlagSize);
        const int eventId = std::atoi(strEventId.c_str());
        if (eventId < 0) {
            continue;
        }

        deviceEventXs.insert(eventId);
    }
}
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
    CHKP(fmt);
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

int32_t MMIService::DelEpoll(EpollEventType type, int32_t fd)
{
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
    auto ret = EpollCtl(fd, EPOLL_CTL_DEL, ev, mmiFd_);
    if (ret < 0) {
        free(ed);
        ed = nullptr;
        ev.data.ptr = nullptr;
        return ret;
    }

    auto it = authFds_.find(fd);
    if (it != authFds_.end()) {
        authFds_.erase(it);
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
    CHKF(input_.Init(std::bind(&InputEventHandler::OnEvent, inputEventHdr_, std::placeholders::_1),
         DEF_INPUT_SEAT), LIBINPUT_INIT_FAIL);
    auto inputFd = input_.GetInputFd();
    auto ret = EpollCtlAdd(EPOLL_EVENT_INPUT, inputFd);
    if (ret <  0) {
        MMI_LOGE("InitLibinputService EpollCtlAdd error ret:%{public}d", ret);
        EpollClose();
        return false;
    }
    MMI_LOGD("MMIService::InitLibinputService EpollCtlAdd, epollfd:%{public}d, fd:%{public}d", mmiFd_, inputFd);
    return true;
}

int32_t MMIService::ChkDeviceNode()
{
    const uint64_t timeInterval = 3L * 1000000L;

    const uint64_t currentTimeMs = GetSysClockTime();
    static uint64_t timeoutTimeMs = currentTimeMs + timeInterval;
    
    bool isTimeout = (currentTimeMs > timeoutTimeMs);

    if (!isTimeout) {
        return RET_OK;
    }

    timeoutTimeMs = currentTimeMs + timeInterval;

    std::set<std::string> dirs;
    GetDevInputDirs(dirs);

    std::set<int> deviceEventXs;
    GetProcBusInputDevicesInfo(deviceEventXs);

    bool hasCreatedNewNode = false;
    static constexpr int32_t NODE_PERM = 0777;

    for (auto eventId : deviceEventXs) {
        std::string eventNode = std::string("event") + std::to_string(eventId);
        if (dirs.find(eventNode) != dirs.end()) {
            continue;
        }

        std::string nodePath = std::string("/dev/input/") + eventNode;
        dev_t dev = makedev(13, 64 + eventId);
        if (mknod(nodePath.c_str(), NODE_PERM | S_IFCHR, dev) < 0) {
            auto errnoSave = errno;
            MMI_LOGE("mknode fail, nodePath: %{public}s, errno: %{public}d", nodePath.c_str(), errnoSave);
            continue;
        }

        if ((chown(nodePath.c_str(), 0, 0) < 0) || (chmod(nodePath.c_str(), NODE_PERM) < 0)) {
            auto errnoSave = errno;
            MMI_LOGE("chown or chmod fail, nodePath: %{public}s, errno: %{public}d", nodePath.c_str(), errnoSave);
            continue;
        }

        MMI_LOGWK("mknode(%s) sucdess", nodePath.c_str());

        hasCreatedNewNode = true;
    }

    if (hasCreatedNewNode) {
        auto inputFd = input_.GetInputFd();
        auto ret = DelEpoll(EPOLL_EVENT_INPUT, inputFd);
        if (ret <  0) {
            MMI_LOGE("DelEpoll error ret = %{public}d", ret);
            return RET_ERR;
        }
        input_.Stop();
        MMI_LOGD("input_.Stop success success, fd:%{public}d", inputFd);

        CHKR(InitLibinputService(), LIBINPUT_INIT_FAIL, LIBINPUT_INIT_FAIL);
        MMI_LOGD("add libinput success");
    }

    return RET_OK;
}

bool MMIService::InitSAService()
{
    CHKF(state_ == ServiceRunningState::STATE_NOT_START, SASERVICE_INIT_FAIL);
    CHKF(Publish(DelayedSingleton<MMIService>::GetInstance().get()), SASERVICE_INIT_FAIL);
    CHKF(EpollCreat(MAX_EVENT_SIZE) >= 0, SASERVICE_INIT_FAIL);
    auto ret = EpollCtlAdd(EPOLL_EVENT_SOCKET, epollFd_);
    if (ret <  0) {
        MMI_LOGE("InitSAService EpollCtlAdd error ret:%{public}d", ret);
        EpollClose();
        return false;
    }
    MMI_LOGD("MMIService::InitLibinputService EpollCtlAdd, epollfd:%{public}d, fd:%{public}d", mmiFd_, epollFd_);
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
    CHKR(InitSignalHandler(), INIT_SIGNAL_HANDLER_FAIL, INIT_SIGNAL_HANDLER_FAIL);
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
    CHKP(s);
    int32_t fd = s->GetFd();
    MMI_LOGI("MMIService::_OnConnected fd:%{public}d", fd);
    AppRegs->RegisterConnectState(fd);
}

void MMIService::OnDisconnected(SessionPtr s)
{
    CHKP(s);
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
    MMI_LOGI("MMIService::AllocSocketFd enter, programName:%{public}s, moduleType:%{public}d",
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

    MMI_LOGIK("leave, programName:%{public}s, moduleType:%{public}d, alloc success.",
        programName.c_str(), moduleType);

    return RET_OK;
}

int32_t MMIService::StubHandleAllocSocketFd(MessageParcel& data, MessageParcel& reply)
{
    int32_t ret = RET_OK;
    sptr<ConnectDefReqParcel> req = data.ReadParcelable<ConnectDefReqParcel>();
    if (req == nullptr) {
        MMI_LOGE("read data error.");
        return RET_ERR;
    }
    MMI_LOGIK("clientName:%{public}s, moduleId:%{public}d", req->data.clientName.c_str(), req->data.moduleId);
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

int32_t MMIService::AddInputEventFilter(sptr<IEventFilter> filter)
{
    if (inputEventHdr_ == nullptr) {
        MMI_LOGE("inputEventHdr_ is nullptr");
        return ERROR_NULL_POINTER;
    }
    return inputEventHdr_->AddInputEventFilter(filter);
}

void MMIService::OnTimer()
{
    if (inputEventHdr_ != nullptr) {
        inputEventHdr_->OnCheckEventReport();
    }
    TimerMgr->ProcessTimers();

    (void)ChkDeviceNode();
}

void MMIService::OnThread()
{
    OHOS::MMI::SetThreadName(std::string("mmi_service"));
    uint64_t tid = GetThisThreadIdOfLL();
    CHK(tid > 0, VAL_NOT_EXP);
    MMI_LOGI("Main worker thread start. tid:%{public}" PRId64 "", tid);
    SafeKpr->RegisterEvent(tid, "mmi_service");

    int32_t count = 0;
    constexpr int32_t timeOut = 20;
    epoll_event ev[MAX_EVENT_SIZE] = {};
    std::map<int32_t, StreamBufData> bufMap;
    while (state_ == ServiceRunningState::STATE_RUNNING) {
        bufMap.clear();
        count = EpollWait(ev[0], MAX_EVENT_SIZE, timeOut, mmiFd_);
        for (int i = 0; i < count && state_ == ServiceRunningState::STATE_RUNNING; i++) {
            auto mmiEd = reinterpret_cast<mmi_epoll_event*>(ev[i].data.ptr);
            CHKPC(mmiEd, ERROR_NULL_POINTER);
            if (mmiEd->event_type == EPOLL_EVENT_INPUT) {
                input_.EventDispatch(ev[i]);
            } else if (mmiEd->event_type == EPOLL_EVENT_SOCKET) {
                OnEpollEvent(ev[i], bufMap);
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
        SafeKpr->ReportHealthStatus(tid);
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

    retCode = EpollCtlAdd(EPOLL_EVENT_SIGNAL, fdSignal);
    if (retCode < 0) {
        MMI_LOGE("EpollCtlAdd signalFd failed:%{public}d", retCode);
        EpollClose();
        return false;
    }

    MMI_LOGD("success");
    return true;
}

void MMIService::OnSignalEvent(int32_t signalFd)
{
    MMI_LOGD("enter");
    signalfd_siginfo sigInfo;
    int32_t size = ::read(signalFd, &sigInfo, sizeof(signalfd_siginfo));
    if (size != sizeof(signalfd_siginfo)) {
        MMI_LOGE("read signal info faild, invalid size:%{public}d", size);
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

}
}
