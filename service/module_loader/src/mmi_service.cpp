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
#include <parameters.h>
#include <sys/signalfd.h>
#ifdef OHOS_RSS_CLIENT
#include <unordered_map>
#endif

#include "event_dump.h"
#include "input_windows_manager.h"
#include "i_pointer_drawing_manager.h"
#include "key_map_manager.h"
#include "mmi_log.h"
#include "string_ex.h"
#include "util_ex.h"
#include "multimodal_input_connect_def_parcel.h"
#ifdef OHOS_RSS_CLIENT
#include "res_sched_client.h"
#include "res_type.h"
#include "system_ability_definition.h"
#endif
#include "timer_manager.h"
#include "input_device_manager.h"
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
    int32_t fd { 0 };
    EpollEventType event_type { EPOLL_EVENT_BEGIN };
};

template<class ...Ts>
void CheckDefineOutput(const char* fmt, Ts... args)
{
    using namespace OHOS::MMI;
    CHKPV(fmt);
    char buf[MAX_PACKET_BUF_SIZE] = {};
    int32_t ret = snprintf_s(buf, MAX_PACKET_BUF_SIZE, MAX_PACKET_BUF_SIZE - 1, fmt, args...);
    if (ret == -1) {
        KMSG_LOGI("call snprintf_s fail.ret = %d", ret);
        return;
    }
    KMSG_LOGI("%s", buf);
    MMI_HILOGI("%{public}s", buf);
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
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    CheckDefineOutput("%-40s", "OHOS_BUILD_ENABLE_POINTER_DRAWING");
#endif
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    CheckDefineOutput("%-40s", "OHOS_BUILD_ENABLE_INTERCEPTOR");
#endif
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    CheckDefineOutput("%-40s", "OHOS_BUILD_ENABLE_KEYBOARD");
#endif
#ifdef OHOS_BUILD_ENABLE_POINTER
    CheckDefineOutput("%-40s", "OHOS_BUILD_ENABLE_POINTER");
#endif
#ifdef OHOS_BUILD_ENABLE_TOUCH
    CheckDefineOutput("%-40s", "OHOS_BUILD_ENABLE_TOUCH");
#endif
#ifdef OHOS_BUILD_ENABLE_MONITOR
    CheckDefineOutput("%-40s", "OHOS_BUILD_ENABLE_MONITOR");
#endif
}

MMIService::MMIService() : SystemAbility(MULTIMODAL_INPUT_CONNECT_SERVICE_ID, true) {}

MMIService::~MMIService() {}

int32_t MMIService::AddEpoll(EpollEventType type, int32_t fd)
{
    if (!(type >= EPOLL_EVENT_BEGIN && type < EPOLL_EVENT_END)) {
        MMI_HILOGE("Invalid param type");
        return RET_ERR;
    }
    if (fd < 0) {
        MMI_HILOGE("Invalid param fd_");
        return RET_ERR;
    }
    if (mmiFd_ < 0) {
        MMI_HILOGE("Invalid param mmiFd_");
        return RET_ERR;
    }
    auto eventData = static_cast<mmi_epoll_event*>(malloc(sizeof(mmi_epoll_event)));
    if (!eventData) {
        MMI_HILOGE("Malloc failed");
        return RET_ERR;
    }
    eventData->fd = fd;
    eventData->event_type = type;
    MMI_HILOGD("userdata:[fd:%{public}d,type:%{public}d]", eventData->fd, eventData->event_type);

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
    return RET_OK;
}

int32_t MMIService::DelEpoll(EpollEventType type, int32_t fd)
{
    if (!(type >= EPOLL_EVENT_BEGIN && type < EPOLL_EVENT_END)) {
        MMI_HILOGE("Invalid param type");
        return RET_ERR;
    }
    if (fd < 0) {
        MMI_HILOGE("Invalid param fd_");
        return RET_ERR;
    }
    if (mmiFd_ < 0) {
        MMI_HILOGE("Invalid param mmiFd_");
        return RET_ERR;
    }
    struct epoll_event ev = {};
    auto ret = EpollCtl(fd, EPOLL_CTL_DEL, ev, mmiFd_);
    if (ret < 0) {
        MMI_HILOGE("DelEpoll failed");
        return ret;
    }
    return RET_OK;
}

bool MMIService::IsRunning() const
{
    return (state_ == ServiceRunningState::STATE_RUNNING);
}

bool MMIService::InitLibinputService()
{
#ifdef OHOS_BUILD_HDF
    MMI_HILOGD("HDF Init");
    hdfEventManager.SetupCallback();
#endif
    if (!(libinputAdapter_.Init(std::bind(&InputEventHandler::OnEvent, InputHandler, std::placeholders::_1),
        DEF_INPUT_SEAT))) {
        MMI_HILOGE("libinput init, bind failed");
        return false;
    }
    auto inputFd = libinputAdapter_.GetInputFd();
    auto ret = AddEpoll(EPOLL_EVENT_INPUT, inputFd);
    if (ret <  0) {
        MMI_HILOGE("AddEpoll error ret: %{public}d", ret);
        EpollClose();
        return false;
    }
    MMI_HILOGD("AddEpoll, epollfd: %{public}d, fd: %{public}d", mmiFd_, inputFd);
    return true;
}

bool MMIService::InitService()
{
    MMI_HILOGD("server msg handler Init");
    sMsgHandler_.Init(*this);
    if (state_ != ServiceRunningState::STATE_NOT_START) {
        MMI_HILOGE("Service running status is not enabled");
        return false;
    }
    if (!(Publish(this))) {
        MMI_HILOGE("Service initialization failed");
        return false;
    }
    if (EpollCreat(MAX_EVENT_SIZE) < 0) {
        MMI_HILOGE("epoll create failed");
        return false;
    }
    auto ret = AddEpoll(EPOLL_EVENT_SOCKET, epollFd_);
    if (ret <  0) {
        MMI_HILOGE("AddEpoll error ret:%{public}d", ret);
        EpollClose();
        return false;
    }
    MMI_HILOGD("AddEpoll, epollfd:%{public}d,fd:%{public}d", mmiFd_, epollFd_);
    return true;
}

bool MMIService::InitDelegateTasks()
{
    CALL_LOG_ENTER;
    if (!delegateTasks_.Init()) {
        MMI_HILOGE("delegate task init failed");
        return false;
    }
    auto ret = AddEpoll(EPOLL_EVENT_ETASK, delegateTasks_.GetReadFd());
    if (ret <  0) {
        MMI_HILOGE("AddEpoll error ret:%{public}d", ret);
        EpollClose();
        return false;
    }
    MMI_HILOGD("AddEpoll, epollfd:%{public}d,fd:%{public}d", mmiFd_, delegateTasks_.GetReadFd());
    return true;
}

int32_t MMIService::Init()
{
    CheckDefine();
    MMI_HILOGD("EventDump Init");
    MMIEventDump->Init(*this);
    MMI_HILOGD("WindowsManager Init");
    WinMgr->Init(*this);
    MMI_HILOGD("PointerDrawingManager Init");
#ifdef OHOS_BUILD_ENABLE_POINTER
    if (!IPointerDrawingManager::GetInstance()->Init()) {
        MMI_HILOGE("Pointer draw init failed");
        return POINTER_DRAW_INIT_FAIL;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    mmiFd_ = EpollCreat(MAX_EVENT_SIZE);
    if (mmiFd_ < 0) {
        MMI_HILOGE("Epoll creat failed");
        return EPOLL_CREATE_FAIL;
    }
    if (!InitService()) {
        MMI_HILOGE("Saservice init failed");
        return SASERVICE_INIT_FAIL;
    }

    MMI_HILOGD("input msg handler Init");
    InputHandler->Init(*this);
    if (!InitLibinputService()) {
        MMI_HILOGE("Libinput init failed");
        return LIBINPUT_INIT_FAIL;
    }
    if (!InitDelegateTasks()) {
        MMI_HILOGE("Delegate tasks init failed");
        return ETASKS_INIT_FAIL;
    }
    SetRecvFun(std::bind(&ServerMsgHandler::OnMsgHandler, &sMsgHandler_, std::placeholders::_1,
        std::placeholders::_2));
    KeyMapMgr->GetConfigKeyValue("default_keymap", KeyMapMgr->GetDefaultKeyId());
    OHOS::system::SetParameter(INPUT_POINTER_DEVICE, "false");
    return RET_OK;
}

void MMIService::OnStart()
{
    int sleepSeconds = 3;
    sleep(sleepSeconds);
    CHK_PID_AND_TID();
    int32_t ret = Init();
    if (RET_OK != ret) {
        MMI_HILOGE("Init mmi_service failed");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    MMI_HILOGD("Started successfully");
    AddReloadDeviceTimer();
    t_ = std::thread(std::bind(&MMIService::OnThread, this));
#ifdef OHOS_RSS_CLIENT
    AddSystemAbilityListener(RES_SCHED_SYS_ABILITY_ID);
#endif
    t_.join();
}

void MMIService::OnStop()
{
    CHK_PID_AND_TID();
    UdsStop();
    InputHandler->Clear();
    libinputAdapter_.Stop();
    state_ = ServiceRunningState::STATE_NOT_START;
#ifdef OHOS_RSS_CLIENT
    RemoveSystemAbilityListener(RES_SCHED_SYS_ABILITY_ID);
#endif
}

int32_t MMIService::AllocSocketFd(const std::string &programName, const int32_t moduleType,
    int32_t &toReturnClientFd)
{
    MMI_HILOGI("enter, programName:%{public}s,moduleType:%{public}d", programName.c_str(), moduleType);
    toReturnClientFd = IMultimodalInputConnect::INVALID_SOCKET_FD;
    int32_t serverFd = IMultimodalInputConnect::INVALID_SOCKET_FD;
    int32_t pid = GetCallingPid();
    int32_t uid = GetCallingUid();
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&UDSServer::AddSocketPairInfo, this,
        programName, moduleType, uid, pid, serverFd, std::ref(toReturnClientFd)));
    if (ret != RET_OK) {
        MMI_HILOGE("call AddSocketPairInfo failed,return %{public}d", ret);
        return RET_ERR;
    }
    MMI_HILOGIK("leave, programName:%{public}s,moduleType:%{public}d,alloc success",
        programName.c_str(), moduleType);
    return RET_OK;
}

int32_t MMIService::AddInputEventFilter(sptr<IEventFilter> filter)
{
    CALL_LOG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    CHKPR(filter, ERROR_NULL_POINTER);
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&InputEventHandler::AddInputEventFilter,
        InputHandler, filter));
    if (ret != RET_OK) {
        MMI_HILOGE("add event filter failed,return %{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    return RET_OK;
}

void MMIService::OnConnected(SessionPtr s)
{
    CHKPV(s);
    MMI_HILOGI("fd:%{public}d", s->GetFd());
}

void MMIService::OnDisconnected(SessionPtr s)
{
    CHKPV(s);
    MMI_HILOGW("enter, session desc:%{public}s, fd: %{public}d", s->GetDescript().c_str(), s->GetFd());
#ifdef OHOS_BUILD_ENABLE_POINTER
    IPointerDrawingManager::GetInstance()->DeletePointerVisible(s->GetPid());
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t MMIService::SetPointerVisible(bool visible)
{
    CALL_LOG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&IPointerDrawingManager::SetPointerVisible,
        IPointerDrawingManager::GetInstance(), GetCallingPid(), visible));
    if (ret != RET_OK) {
        MMI_HILOGE("set pointer visible failed,return %{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
int32_t MMIService::CheckPointerVisible(bool &visible)
{
    visible = IPointerDrawingManager::GetInstance()->IsPointerVisible();
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

int32_t MMIService::IsPointerVisible(bool &visible)
{
    CALL_LOG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&MMIService::CheckPointerVisible, this, std::ref(visible)));
    if (ret != RET_OK) {
        MMI_HILOGE("is pointer visible failed,return %{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}

int32_t MMIService::CheckEventProcessed(int32_t pid, int32_t eventId)
{
    auto sess = GetSessionByPid(pid);
    CHKPR(sess, ERROR_NULL_POINTER);
    return sMsgHandler_.MarkEventProcessed(sess, eventId);
}

int32_t MMIService::MarkEventProcessed(int32_t eventId)
{
    CALL_LOG_ENTER;
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&MMIService::CheckEventProcessed, this, pid, eventId));
    if (ret != RET_OK) {
        MMI_HILOGE("mark event processed failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
int32_t MMIService::CheckAddInput(int32_t pid, int32_t handlerId, InputHandlerType handlerType,
    HandleEventType eventType)
{
    auto sess = GetSessionByPid(pid);
    CHKPR(sess, ERROR_NULL_POINTER);
    return sMsgHandler_.OnAddInputHandler(sess, handlerId, handlerType, eventType);
}
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR

int32_t MMIService::AddInputHandler(int32_t handlerId, InputHandlerType handlerType,
    HandleEventType eventType)
{
    CALL_LOG_ENTER;
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&MMIService::CheckAddInput, this, pid, handlerId, handlerType, eventType));
    if (ret != RET_OK) {
        MMI_HILOGE("add input handler failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}

#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
int32_t MMIService::CheckRemoveInput(int32_t pid, int32_t handlerId, InputHandlerType handlerType)
{
    auto sess = GetSessionByPid(pid);
    CHKPR(sess, ERROR_NULL_POINTER);
    return sMsgHandler_.OnRemoveInputHandler(sess, handlerId, handlerType);
}
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR

int32_t MMIService::RemoveInputHandler(int32_t handlerId, InputHandlerType handlerType)
{
    CALL_LOG_ENTER;
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&MMIService::CheckRemoveInput, this, pid, handlerId, handlerType));
    if (ret != RET_OK) {
        MMI_HILOGE("remove input handler failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_MONITOR
int32_t MMIService::CheckMarkConsumed(int32_t pid, int32_t monitorId, int32_t eventId)
{
    auto sess = GetSessionByPid(pid);
    CHKPR(sess, ERROR_NULL_POINTER);
    return sMsgHandler_.OnMarkConsumed(sess, monitorId, eventId);
}
#endif // OHOS_BUILD_ENABLE_MONITOR

int32_t MMIService::MarkEventConsumed(int32_t monitorId, int32_t eventId)
{
    CALL_LOG_ENTER;
#ifdef OHOS_BUILD_ENABLE_MONITOR
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&MMIService::CheckMarkConsumed, this, pid, monitorId, eventId));
    if (ret != RET_OK) {
        MMI_HILOGE("mark event consumed failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}

int32_t MMIService::MoveMouseEvent(int32_t offsetX, int32_t offsetY)
{
    CALL_LOG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&ServerMsgHandler::OnMoveMouse, &sMsgHandler_, offsetX, offsetY));
    if (ret != RET_OK) {
        MMI_HILOGE("movemouse event processed failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}

int32_t MMIService::InjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_LOG_ENTER;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&MMIService::CheckInjectKeyEvent, this, keyEvent));
    if (ret != RET_OK) {
        MMI_HILOGE("inject key event failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t MMIService::CheckInjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    return sMsgHandler_.OnInjectKeyEvent(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
int32_t MMIService::CheckInjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    return sMsgHandler_.OnInjectPointerEvent(pointerEvent);
}

#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
int32_t MMIService::InjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_LOG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&MMIService::CheckInjectPointerEvent, this, pointerEvent));
    if (ret != RET_OK) {
        MMI_HILOGE("inject pointer event failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    return RET_OK;
}

#ifdef OHOS_RSS_CLIENT
void MMIService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    if (systemAbilityId == RES_SCHED_SYS_ABILITY_ID) {
        int sleepSeconds = 1;
        sleep(sleepSeconds);
        uint64_t tid = tid_.load();
        std::unordered_map<std::string, std::string> payload;
        payload["uid"] = std::to_string(getuid());
        payload["pid"] = std::to_string(getpid());
        ResourceSchedule::ResSchedClient::GetInstance().ReportData(
            ResourceSchedule::ResType::RES_TYPE_REPORT_MMI_PROCESS, tid, payload);
    }
}
#endif

int32_t MMIService::SubscribeKeyEvent(int32_t subscribeId, const std::shared_ptr<KeyOption> option)
{
    CALL_LOG_ENTER;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&ServerMsgHandler::OnSubscribeKeyEvent, &sMsgHandler_, this, pid, subscribeId, option));
    if (ret != RET_OK) {
        MMI_HILOGE("subscribe key event event processed failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::UnsubscribeKeyEvent(int32_t subscribeId)
{
    CALL_LOG_ENTER;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&ServerMsgHandler::OnUnsubscribeKeyEvent, &sMsgHandler_, this, pid, subscribeId));
    if (ret != RET_OK) {
        MMI_HILOGE("unsubscribe key event processed failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

void MMIService::OnDelegateTask(epoll_event& ev)
{
    if ((ev.events & EPOLLIN) == 0) {
        MMI_HILOGW("not epollin");
        return;
    }
    DelegateTasks::TaskData data = {};
    auto res = read(delegateTasks_.GetReadFd(), &data, sizeof(data));
    if (res == -1) {
        MMI_HILOGW("read failed erron:%{public}d", errno);
    }
    MMI_HILOGD("RemoteRequest notify td:%{public}" PRId64 ",std:%{public}" PRId64 ""
        ",taskId:%{public}d", GetThisThreadId(), data.tid, data.taskId);
    delegateTasks_.ProcessTasks();
}

void MMIService::OnThread()
{
    SetThreadName(std::string("mmi_service"));
    uint64_t tid = GetThisThreadId();
    delegateTasks_.SetWorkerThreadId(tid);
    MMI_HILOGI("Main worker thread start. tid:%{public}" PRId64 "", tid);
#ifdef OHOS_RSS_CLIENT
    tid_.store(tid);
#endif
    libinputAdapter_.ProcessPendingEvents();
    while (state_ == ServiceRunningState::STATE_RUNNING) {
        epoll_event ev[MAX_EVENT_SIZE] = {};
        int32_t timeout = TimerMgr->CalcNextDelay();
        MMI_HILOGD("timeout:%{public}d", timeout);
        int32_t count = EpollWait(ev[0], MAX_EVENT_SIZE, timeout, mmiFd_);
        for (int32_t i = 0; i < count && state_ == ServiceRunningState::STATE_RUNNING; i++) {
            auto mmiEd = reinterpret_cast<mmi_epoll_event*>(ev[i].data.ptr);
            CHKPC(mmiEd);
            if (mmiEd->event_type == EPOLL_EVENT_INPUT) {
                libinputAdapter_.EventDispatch(ev[i]);
            } else if (mmiEd->event_type == EPOLL_EVENT_SOCKET) {
                OnEpollEvent(ev[i]);
            } else if (mmiEd->event_type == EPOLL_EVENT_SIGNAL) {
                OnSignalEvent(mmiEd->fd);
            } else if (mmiEd->event_type == EPOLL_EVENT_ETASK) {
                OnDelegateTask(ev[i]);
            } else {
                MMI_HILOGW("unknown epoll event type:%{public}d", mmiEd->event_type);
            }
        }
        TimerMgr->ProcessTimers();
        if (state_ != ServiceRunningState::STATE_RUNNING) {
            break;
        }
    }
    MMI_HILOGI("Main worker thread stop. tid:%{public}" PRId64 "", tid);
}

bool MMIService::InitSignalHandler()
{
    CALL_LOG_ENTER;
    sigset_t mask = {0};
    int32_t retCode = sigfillset(&mask);
    if (retCode < 0) {
        MMI_HILOGE("fill signal set failed:%{public}d", errno);
        return false;
    }

    retCode = sigprocmask(SIG_SETMASK, &mask, nullptr);
    if (retCode < 0) {
        MMI_HILOGE("sigprocmask failed:%{public}d", errno);
        return false;
    }

    int32_t fdSignal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
    if (fdSignal < 0) {
        MMI_HILOGE("signal fd failed:%{public}d", errno);
        return false;
    }

    retCode = AddEpoll(EPOLL_EVENT_SIGNAL, fdSignal);
    if (retCode < 0) {
        MMI_HILOGE("AddEpoll signalFd failed:%{public}d", retCode);
        close(fdSignal);
        return false;
    }
    return true;
}

void MMIService::OnSignalEvent(int32_t signalFd)
{
    CALL_LOG_ENTER;
    signalfd_siginfo sigInfo;
    int32_t size = ::read(signalFd, &sigInfo, sizeof(signalfd_siginfo));
    if (size != static_cast<int32_t>(sizeof(signalfd_siginfo))) {
        MMI_HILOGE("read signal info failed, invalid size:%{public}d,errno:%{public}d", size, errno);
        return;
    }
    int32_t signo = static_cast<int32_t>(sigInfo.ssi_signo);
    MMI_HILOGD("receive signal:%{public}d", signo);
    switch (signo) {
        case SIGINT:
        case SIGQUIT:
        case SIGILL:
        case SIGABRT:
        case SIGBUS:
        case SIGFPE:
        case SIGKILL:
        case SIGSEGV:
        case SIGTERM: {
            state_ = ServiceRunningState::STATE_EXIT;
            break;
        }
        default: {
            break;
        }
    }
}

void MMIService::AddReloadDeviceTimer()
{
    CALL_LOG_ENTER;
    TimerMgr->AddTimer(2000, 2, [this]() {
        auto deviceIds = InputDevMgr->GetInputDeviceIds();
        if (deviceIds.empty()) {
            libinputAdapter_.ReloadDevice();
        }
    });
}

int32_t MMIService::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    CALL_LOG_ENTER;
    if (fd < 0) {
        MMI_HILOGE("fd is invalid");
        return DUMP_PARAM_ERR;
    }
    if (args.empty()) {
        MMI_HILOGE("args cannot be empty");
        mprintf(fd, "args cannot be empty\n");
        MMIEventDump->DumpHelp(fd);
        return DUMP_PARAM_ERR;
    }
    std::vector<std::string> argList = { "" };
    std::transform(args.begin(), args.end(), std::back_inserter(argList),
        [](const std::u16string &arg) {
        return Str16ToStr8(arg);
    });
    MMIEventDump->ParseCommand(fd, argList);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
