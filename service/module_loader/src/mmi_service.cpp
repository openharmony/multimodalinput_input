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
#include "dfx_hisysevent.h"
#ifdef OHOS_RSS_CLIENT
#include <unordered_map>
#endif

#include "anr_manager.h"
#ifdef OHOS_BUILD_ENABLE_COOPERATE
#include "cooperate_event_manager.h"
#endif // OHOS_BUILD_ENABLE_COOPERATE
#include "event_dump.h"
#ifdef OHOS_BUILD_ENABLE_COOPERATE
#include "input_device_cooperate_sm.h"
#endif // OHOS_BUILD_ENABLE_COOPERATE
#include "input_device_manager.h"
#include "input_windows_manager.h"
#include "i_pointer_drawing_manager.h"
#include "key_map_manager.h"
#include "mmi_log.h"
#include "string_ex.h"
#include "util_ex.h"
#include "util_napi_error.h"
#include "multimodal_input_connect_def_parcel.h"
#ifdef OHOS_RSS_CLIENT
#include "res_sched_client.h"
#include "res_type.h"
#include "system_ability_definition.h"
#endif
#include "permission_helper.h"
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
        KMSG_LOGI("Call snprintf_s failed.ret = %d", ret);
        return;
    }
    KMSG_LOGI("%s", buf);
    MMI_HILOGI("%{public}s", buf);
}

static void CheckDefine()
{
    CheckDefineOutput("ChkDefs:");
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
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    CheckDefineOutput("%-40s", "OHOS_BUILD_ENABLE_COOPERATE");
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
    MMI_HILOGI("userdata:[fd:%{public}d,type:%{public}d]", eventData->fd, eventData->event_type);

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
    if (!(libinputAdapter_.Init(std::bind(&InputEventHandler::OnEvent, InputHandler, std::placeholders::_1),
        DEF_INPUT_SEAT))) {
        MMI_HILOGE("Libinput init, bind failed");
        return false;
    }
    auto inputFd = libinputAdapter_.GetInputFd();
    auto ret = AddEpoll(EPOLL_EVENT_INPUT, inputFd);
    if (ret <  0) {
        MMI_HILOGE("AddEpoll error ret:%{public}d", ret);
        EpollClose();
        return false;
    }
    MMI_HILOGI("AddEpoll, epollfd:%{public}d, fd:%{public}d", mmiFd_, inputFd);
    return true;
}

bool MMIService::InitService()
{
    MMI_HILOGD("Server msg handler Init");
    sMsgHandler_.Init(*this);
    if (state_ != ServiceRunningState::STATE_NOT_START) {
        MMI_HILOGE("Service running status is not enabled");
        return false;
    }
    if (EpollCreat(MAX_EVENT_SIZE) < 0) {
        MMI_HILOGE("Create epoll failed");
        return false;
    }
    auto ret = AddEpoll(EPOLL_EVENT_SOCKET, epollFd_);
    if (ret <  0) {
        MMI_HILOGE("AddEpoll error ret:%{public}d", ret);
        EpollClose();
        return false;
    }
    if (!(Publish(this))) {
        MMI_HILOGE("Service initialization failed");
        return false;
    }
    MMI_HILOGI("AddEpoll, epollfd:%{public}d,fd:%{public}d", mmiFd_, epollFd_);
    return true;
}

bool MMIService::InitDelegateTasks()
{
    CALL_DEBUG_ENTER;
    if (!delegateTasks_.Init()) {
        MMI_HILOGE("The delegate task init failed");
        return false;
    }
    auto ret = AddEpoll(EPOLL_EVENT_ETASK, delegateTasks_.GetReadFd());
    if (ret <  0) {
        MMI_HILOGE("AddEpoll error ret:%{public}d", ret);
        EpollClose();
        return false;
    }
    MMI_HILOGI("AddEpoll, epollfd:%{public}d,fd:%{public}d", mmiFd_, delegateTasks_.GetReadFd());
    return true;
}

int32_t MMIService::Init()
{
    CheckDefine();
    MMI_HILOGD("WindowsManager Init");
    WinMgr->Init(*this);
    MMI_HILOGD("ANRManager Init");
    ANRMgr->Init(*this);
    MMI_HILOGD("PointerDrawingManager Init");
#ifdef OHOS_BUILD_ENABLE_POINTER
    if (!IPointerDrawingManager::GetInstance()->Init()) {
        MMI_HILOGE("Pointer draw init failed");
        return POINTER_DRAW_INIT_FAIL;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    mmiFd_ = EpollCreat(MAX_EVENT_SIZE);
    if (mmiFd_ < 0) {
        MMI_HILOGE("Create epoll failed");
        return EPOLL_CREATE_FAIL;
    }
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    InputDevCooSM->Init(std::bind(&DelegateTasks::PostAsyncTask, &delegateTasks_, std::placeholders::_1));
#endif // OHOS_BUILD_ENABLE_COOPERATE
    MMI_HILOGD("Input msg handler init");
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
    if (!InitService()) {
        MMI_HILOGE("Saservice init failed");
        return SASERVICE_INIT_FAIL;
    }
    MMI_HILOGI("Set para input.pointer.device false");
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
    libinputAdapter_.Stop();
    state_ = ServiceRunningState::STATE_NOT_START;
#ifdef OHOS_RSS_CLIENT
    RemoveSystemAbilityListener(RES_SCHED_SYS_ABILITY_ID);
#endif
}

int32_t MMIService::AllocSocketFd(const std::string &programName, const int32_t moduleType,
    int32_t &toReturnClientFd, int32_t &tokenType)
{
    MMI_HILOGI("Enter, programName:%{public}s,moduleType:%{public}d", programName.c_str(), moduleType);

    toReturnClientFd = IMultimodalInputConnect::INVALID_SOCKET_FD;
    int32_t serverFd = IMultimodalInputConnect::INVALID_SOCKET_FD;
    int32_t pid = GetCallingPid();
    int32_t uid = GetCallingUid();
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&UDSServer::AddSocketPairInfo, this,
        programName, moduleType, uid, pid, serverFd, std::ref(toReturnClientFd), tokenType));
    DfxHisysevent::ClientConnectData data = {
        .pid = pid,
        .uid = uid,
        .moduleType = moduleType,
        .programName = programName,
        .serverFd = serverFd
    };
    if (ret != RET_OK) {
        MMI_HILOGE("Call AddSocketPairInfo failed,return %{public}d", ret);
        DfxHisysevent::OnClientConnect(data, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
        return RET_ERR;
    }
    MMI_HILOGIK("Leave, programName:%{public}s,moduleType:%{public}d,alloc success",
        programName.c_str(), moduleType);
    DfxHisysevent::OnClientConnect(data, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
    return RET_OK;
}

int32_t MMIService::AddInputEventFilter(sptr<IEventFilter> filter)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    CHKPR(filter, ERROR_NULL_POINTER);
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&ServerMsgHandler::AddInputEventFilter,
        &sMsgHandler_, filter));
    if (ret != RET_OK) {
        MMI_HILOGE("Add event filter failed,return %{public}d", ret);
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
    MMI_HILOGW("Enter, session desc:%{public}s, fd:%{public}d", s->GetDescript().c_str(), s->GetFd());
#ifdef OHOS_BUILD_ENABLE_POINTER
    IPointerDrawingManager::GetInstance()->DeletePointerVisible(s->GetPid());
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t MMIService::SetPointerVisible(bool visible)
{
    CALL_DEBUG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&IPointerDrawingManager::SetPointerVisible,
        IPointerDrawingManager::GetInstance(), GetCallingPid(), visible));
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer visible failed,return %{public}d", ret);
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
    CALL_DEBUG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&MMIService::CheckPointerVisible, this, std::ref(visible)));
    if (ret != RET_OK) {
        MMI_HILOGE("Is pointer visible failed,return %{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}

int32_t MMIService::SetPointerSpeed(int32_t speed)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&MouseEventNormalize::SetPointerSpeed,
        MouseEventHdr, speed));
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer speed failed,return %{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_POINTER
int32_t MMIService::ReadPointerSpeed(int32_t &speed)
{
    speed = MouseEventHdr->GetPointerSpeed();
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER

int32_t MMIService::GetPointerSpeed(int32_t &speed)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&MMIService::ReadPointerSpeed, this, std::ref(speed)));
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer speed failed,return %{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetPointerStyle(int32_t windowId, int32_t pointerStyle)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&IPointerDrawingManager::SetPointerStyle,
        IPointerDrawingManager::GetInstance(), GetCallingPid(), windowId, pointerStyle));
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer style failed,return %{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::GetPointerStyle(int32_t windowId, int32_t &pointerStyle)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&IPointerDrawingManager::GetPointerStyle,
        IPointerDrawingManager::GetInstance(), GetCallingPid(), windowId, std::ref(pointerStyle)));
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer style failed,return %{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::OnSupportKeys(int32_t pid, int32_t userData, int32_t deviceId, std::vector<int32_t> &keys)
{
    CALL_DEBUG_ENTER;
    auto sess = GetSession(GetClientFd(pid));
    CHKPR(sess, RET_ERR);
    std::vector<bool> keystroke;
    int32_t ret = InputDevMgr->SupportKeys(deviceId, keys, keystroke);
    if (keystroke.size() > MAX_SUPPORT_KEY) {
        MMI_HILOGE("Device exceeds the max range");
        return RET_ERR;
    }
    if (ret != RET_OK) {
        MMI_HILOGE("Device id not support");
        return ret;
    }

    NetPacket pkt(MmiMessageId::INPUT_DEVICE_SUPPORT_KEYS);
    pkt << userData << keystroke.size();
    for (const bool &item : keystroke) {
        pkt << item;
    }

    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write support keys info failed");
        return RET_ERR;
    }
    if (!sess->SendMsg(pkt)) {
        MMI_HILOGE("Sending failed");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t MMIService::SupportKeys(int32_t userData, int32_t deviceId, std::vector<int32_t> &keys)
{
    CALL_DEBUG_ENTER;
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&MMIService::OnSupportKeys, this,
        pid, userData, deviceId, keys));
    if (ret != RET_OK) {
        MMI_HILOGE("Support keys info process failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::OnGetDeviceIds(int32_t pid, int32_t userData)
{
    CALL_DEBUG_ENTER;
    auto sess = GetSession(GetClientFd(pid));
    CHKPR(sess, RET_ERR);
    std::vector<int32_t> ids = InputDevMgr->GetInputDeviceIds();
    if (ids.size() > MAX_INPUT_DEVICE) {
        MMI_HILOGE("Device exceeds the max range");
        return RET_ERR;
    }
    NetPacket pkt(MmiMessageId::INPUT_DEVICE_IDS);
    pkt << userData << ids;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write data failed");
        return RET_ERR;
    }
    if (!sess->SendMsg(pkt)) {
        MMI_HILOGE("Sending failed");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t MMIService::GetDeviceIds(int32_t userData)
{
    CALL_DEBUG_ENTER;
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&MMIService::OnGetDeviceIds, this, pid, userData));
    if (ret != RET_OK) {
        MMI_HILOGE("Get deviceids failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MMIService::OnGetDevice(int32_t pid, int32_t userData, int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    auto sess = GetSession(GetClientFd(pid));
    CHKPR(sess, RET_ERR);
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    if (InputDevMgr->GetInputDevice(deviceId) == nullptr) {
        MMI_HILOGE("Input device not found");
        return COMMON_PARAMETER_ERROR;
    }
    inputDevice = InputDevMgr->GetInputDevice(deviceId);
    NetPacket pkt(MmiMessageId::INPUT_DEVICE);
    pkt << userData << inputDevice->GetId() << inputDevice->GetName() << inputDevice->GetType()
        << inputDevice->GetBus() << inputDevice->GetProduct() << inputDevice->GetVendor()
        << inputDevice->GetVersion() << inputDevice->GetPhys() << inputDevice->GetUniq()
        << inputDevice->GetAxisInfo().size();
    for (auto &axis : inputDevice->GetAxisInfo()) {
        pkt << axis.GetAxisType() << axis.GetMinimum() << axis.GetMaximum()
            << axis.GetFuzz() << axis.GetFlat() << axis.GetResolution();
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write input device info failed");
        return RET_ERR;
    }
    if (!sess->SendMsg(pkt)) {
        MMI_HILOGE("Sending failed");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t MMIService::GetDevice(int32_t userData, int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&MMIService::OnGetDevice, this, pid, userData, deviceId));
    if (ret != RET_OK) {
        MMI_HILOGE("Get input device info failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::OnRegisterDevListener(int32_t pid)
{
    auto sess = GetSession(GetClientFd(pid));
    CHKPR(sess, RET_ERR);
    InputDevMgr->AddDevListener(sess, [sess](int32_t id, const std::string &type) {
        CALL_DEBUG_ENTER;
        CHKPV(sess);
        NetPacket pkt(MmiMessageId::ADD_INPUT_DEVICE_LISTENER);
        pkt << type << id;
        if (pkt.ChkRWError()) {
            MMI_HILOGE("Packet write data failed");
            return;
        }
        if (!sess->SendMsg(pkt)) {
            MMI_HILOGE("Sending failed");
            return;
        }
    });
    return RET_OK;
}

int32_t MMIService::RegisterDevListener()
{
    CALL_DEBUG_ENTER;
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&MMIService::OnRegisterDevListener, this, pid));
    if (ret != RET_OK) {
        MMI_HILOGE("Register device listener failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MMIService::OnUnregisterDevListener(int32_t pid)
{
    auto sess = GetSession(GetClientFd(pid));
    InputDevMgr->RemoveDevListener(sess);
    return RET_OK;
}

int32_t MMIService::UnregisterDevListener()
{
    CALL_DEBUG_ENTER;
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&MMIService::OnUnregisterDevListener, this, pid));
    if (ret != RET_OK) {
        MMI_HILOGE("Unregister device listener failed failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MMIService::OnGetKeyboardType(int32_t pid, int32_t userData, int32_t deviceId)
{
    auto sess = GetSession(GetClientFd(pid));
    CHKPR(sess, RET_ERR);
    int32_t keyboardType = 0;
    int32_t ret = InputDevMgr->GetKeyboardType(deviceId, keyboardType);
    if (ret != RET_OK) {
        MMI_HILOGE("GetKeyboardType call failed");
        return ret;
    }
    NetPacket pkt(MmiMessageId::INPUT_DEVICE_KEYBOARD_TYPE);
    pkt << userData << keyboardType;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write keyboard type failed");
        return RET_ERR;
    }
    if (!sess->SendMsg(pkt)) {
        MMI_HILOGE("Failed to send the keyboard package");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t MMIService::GetKeyboardType(int32_t userData, int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&MMIService::OnGetKeyboardType, this,
        pid, userData, deviceId));
    if (ret != RET_OK) {
        MMI_HILOGE("Get keyboard type failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
int32_t MMIService::CheckAddInput(int32_t pid, InputHandlerType handlerType,
    HandleEventType eventType)
{
    auto sess = GetSessionByPid(pid);
    CHKPR(sess, ERROR_NULL_POINTER);
    return sMsgHandler_.OnAddInputHandler(sess, handlerType, eventType);
}
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR

int32_t MMIService::AddInputHandler(InputHandlerType handlerType, HandleEventType eventType)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&MMIService::CheckAddInput, this, pid, handlerType, eventType));
    if (ret != RET_OK) {
        MMI_HILOGE("Add input handler failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}

#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
int32_t MMIService::CheckRemoveInput(int32_t pid, InputHandlerType handlerType, HandleEventType eventType)
{
    auto sess = GetSessionByPid(pid);
    CHKPR(sess, ERROR_NULL_POINTER);
    return sMsgHandler_.OnRemoveInputHandler(sess, handlerType, eventType);
}
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR

int32_t MMIService::RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&MMIService::CheckRemoveInput, this, pid, handlerType, eventType));
    if (ret != RET_OK) {
        MMI_HILOGE("Remove input handler failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_MONITOR
int32_t MMIService::CheckMarkConsumed(int32_t pid, int32_t eventId)
{
    auto sess = GetSessionByPid(pid);
    CHKPR(sess, ERROR_NULL_POINTER);
    return sMsgHandler_.OnMarkConsumed(sess, eventId);
}
#endif // OHOS_BUILD_ENABLE_MONITOR

int32_t MMIService::MarkEventConsumed(int32_t eventId)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_MONITOR
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&MMIService::CheckMarkConsumed, this, pid, eventId));
    if (ret != RET_OK) {
        MMI_HILOGE("Mark event consumed failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}

int32_t MMIService::MoveMouseEvent(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&ServerMsgHandler::OnMoveMouse, &sMsgHandler_, offsetX, offsetY));
    if (ret != RET_OK) {
        MMI_HILOGE("The movemouse event processed failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}

int32_t MMIService::InjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&MMIService::CheckInjectKeyEvent, this, keyEvent));
    if (ret != RET_OK) {
        MMI_HILOGE("Inject key event failed, ret:%{public}d", ret);
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
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&MMIService::CheckInjectPointerEvent, this, pointerEvent));
    if (ret != RET_OK) {
        MMI_HILOGE("Inject pointer event failed, ret:%{public}d", ret);
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
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&ServerMsgHandler::OnSubscribeKeyEvent, &sMsgHandler_, this, pid, subscribeId, option));
    if (ret != RET_OK) {
        MMI_HILOGE("The subscribe key event processed failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::UnsubscribeKeyEvent(int32_t subscribeId)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&ServerMsgHandler::OnUnsubscribeKeyEvent, &sMsgHandler_, this, pid, subscribeId));
    if (ret != RET_OK) {
        MMI_HILOGE("The unsubscribe key event processed failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::SetAnrObserver()
{
    CALL_DEBUG_ENTER;
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&ANRManager::SetANRNoticedPid, ANRMgr, pid));
    if (ret != RET_OK) {
        MMI_HILOGE("Set ANRNoticed pid failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MMIService::GetFunctionKeyState(int32_t funcKey, bool &state)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&ServerMsgHandler::OnGetFunctionKeyState, &sMsgHandler_, funcKey, std::ref(state)));
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to get the keyboard status, ret:%{public}d", ret);
        return RET_ERR;
    }
#else
    MMI_HILOGD("Function not supported");
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::SetFunctionKeyState(int32_t funcKey, bool enable)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&ServerMsgHandler::OnSetFunctionKeyState, &sMsgHandler_, funcKey, enable));
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to update the keyboard status, ret:%{public}d", ret);
        return RET_ERR;
    }
#else
    MMI_HILOGD("Function not supported");
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

void MMIService::OnDelegateTask(epoll_event& ev)
{
    if ((ev.events & EPOLLIN) == 0) {
        MMI_HILOGW("Not epollin");
        return;
    }
    DelegateTasks::TaskData data = {};
    auto res = read(delegateTasks_.GetReadFd(), &data, sizeof(data));
    if (res == -1) {
        MMI_HILOGW("Read failed erron:%{public}d", errno);
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
    libinputAdapter_.RetriggerHotplugEvents();
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
                MMI_HILOGW("Unknown epoll event type:%{public}d", mmiEd->event_type);
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
    CALL_DEBUG_ENTER;
    sigset_t mask = {0};
    int32_t retCode = sigfillset(&mask);
    if (retCode < 0) {
        MMI_HILOGE("Fill signal set failed:%{public}d", errno);
        return false;
    }

    retCode = sigprocmask(SIG_SETMASK, &mask, nullptr);
    if (retCode < 0) {
        MMI_HILOGE("Sigprocmask failed:%{public}d", errno);
        return false;
    }

    int32_t fdSignal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
    if (fdSignal < 0) {
        MMI_HILOGE("Signal fd failed:%{public}d", errno);
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
    CALL_DEBUG_ENTER;
    signalfd_siginfo sigInfo;
    int32_t size = ::read(signalFd, &sigInfo, sizeof(signalfd_siginfo));
    if (size != static_cast<int32_t>(sizeof(signalfd_siginfo))) {
        MMI_HILOGE("Read signal info failed, invalid size:%{public}d,errno:%{public}d", size, errno);
        return;
    }
    int32_t signo = static_cast<int32_t>(sigInfo.ssi_signo);
    MMI_HILOGD("Receive signal:%{public}d", signo);
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
    CALL_DEBUG_ENTER;
    TimerMgr->AddTimer(2000, 2, [this]() {
        auto deviceIds = InputDevMgr->GetInputDeviceIds();
        if (deviceIds.empty()) {
            libinputAdapter_.ReloadDevice();
        }
    });
}

int32_t MMIService::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    CALL_DEBUG_ENTER;
    if (fd < 0) {
        MMI_HILOGE("The fd is invalid");
        return DUMP_PARAM_ERR;
    }
    if (args.empty()) {
        MMI_HILOGE("The args cannot be empty");
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

int32_t MMIService::RegisterCooperateListener()
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&MMIService::OnRegisterCooperateListener, this, pid));
    if (ret != RET_OK) {
        MMI_HILOGE("OnRegisterCooperateListener failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_COOPERATE
    return RET_OK;
}

int32_t MMIService::UnregisterCooperateListener()
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&MMIService::OnUnregisterCooperateListener, this, pid));
    if (ret != RET_OK) {
        MMI_HILOGE("OnUnregisterCooperateListener failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_COOPERATE
    return RET_OK;
}

int32_t MMIService::EnableInputDeviceCooperate(int32_t userData, bool enabled)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&MMIService::OnEnableInputDeviceCooperate, this, pid, userData, enabled));
    if (ret != RET_OK) {
        MMI_HILOGE("OnEnableInputDeviceCooperate failed, ret:%{public}d", ret);
        return ret;
    }
#else
    (void)(userData);
    (void)(enabled);
#endif // OHOS_BUILD_ENABLE_COOPERATE
    return RET_OK;
}

int32_t MMIService::StartInputDeviceCooperate(int32_t userData, const std::string &sinkDeviceId,
    int32_t srcInputDeviceId)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&MMIService::OnStartInputDeviceCooperate, this, pid, userData, sinkDeviceId, srcInputDeviceId));
    if (ret != RET_OK) {
        MMI_HILOGE("OnStartInputDeviceCooperate failed, ret:%{public}d", ret);
        return ret;
    }
#else
    (void)(userData);
    (void)(sinkDeviceId);
    (void)(srcInputDeviceId);
#endif // OHOS_BUILD_ENABLE_COOPERATE
    return RET_OK;
}

int32_t MMIService::StopDeviceCooperate(int32_t userData)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&MMIService::OnStopDeviceCooperate, this, pid, userData));
    if (ret != RET_OK) {
        MMI_HILOGE("OnStopDeviceCooperate failed, ret:%{public}d", ret);
        return ret;
    }
#else
    (void)(userData);
#endif // OHOS_BUILD_ENABLE_COOPERATE
    return RET_OK;
}

int32_t MMIService::GetInputDeviceCooperateState(int32_t userData, const std::string &deviceId)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&MMIService::OnGetInputDeviceCooperateState, this, pid, userData, deviceId));
    if (ret != RET_OK) {
        MMI_HILOGE("OnGetInputDeviceCooperateState failed, ret:%{public}d", ret);
        return RET_ERR;
    }
#else
    (void)(userData);
    (void)(deviceId);
    MMI_HILOGW("Get input device cooperate state does not support");
#endif // OHOS_BUILD_ENABLE_COOPERATE
    return RET_OK;
}

int32_t MMIService::SetInputDevice(const std::string& dhid, const std::string& screenId)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&InputDeviceManager::SetInputDevice,
        InputDevMgr, dhid, screenId));
    if (ret != RET_OK) {
        MMI_HILOGE("Set input device screen id failed,return %{public}d", ret);
        return ret;
    }
#else
    (void)(dhid);
    (void)(screenId);
    MMI_HILOGW("Enable input device cooperate does not support");
#endif // OHOS_BUILD_ENABLE_COOPERATE
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_COOPERATE
int32_t MMIService::OnRegisterCooperateListener(int32_t pid)
{
    CALL_DEBUG_ENTER;
    auto sess = GetSession(GetClientFd(pid));
    CHKPR(sess, RET_ERR);
    sptr<CooperateEventManager::EventInfo> event = new (std::nothrow) CooperateEventManager::EventInfo();
    CHKPR(event, RET_ERR);
    event->type = CooperateEventManager::EventType::LISTENER;
    event->sess = sess;
    event->msgId = MmiMessageId::COOPERATION_ADD_LISTENER;
    CooperateEventMgr->AddCooperationEvent(event);
    return RET_OK;
}

int32_t MMIService::OnUnregisterCooperateListener(int32_t pid)
{
    CALL_DEBUG_ENTER;
    auto sess = GetSession(GetClientFd(pid));
    sptr<CooperateEventManager::EventInfo> event = new (std::nothrow) CooperateEventManager::EventInfo();
    CHKPR(event, RET_ERR);
    event->type = CooperateEventManager::EventType::LISTENER;
    event->sess = sess;
    CooperateEventMgr->RemoveCooperationEvent(event);
    return RET_OK;
}

int32_t MMIService::OnEnableInputDeviceCooperate(int32_t pid, int32_t userData, bool enabled)
{
    CALL_DEBUG_ENTER;
    InputDevCooSM->EnableInputDeviceCooperate(enabled);
    std::string deviceId =  "";
    CooperationMessage msg =
        enabled ? CooperationMessage::OPEN_SUCCESS : CooperationMessage::CLOSE_SUCCESS;
    NetPacket pkt(MmiMessageId::COOPERATION_MESSAGE);
    pkt << userData << deviceId << static_cast<int32_t>(msg);
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write data failed");
        return RET_ERR;
    }
    auto sess = GetSession(GetClientFd(pid));
    CHKPR(sess, RET_ERR);
    if (!sess->SendMsg(pkt)) {
        MMI_HILOGE("Sending failed");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t MMIService::OnStartInputDeviceCooperate(int32_t pid, int32_t userData, const std::string &sinkDeviceId,
    int32_t srcInputDeviceId)
{
    CALL_DEBUG_ENTER;
    auto sess = GetSession(GetClientFd(pid));
    CHKPR(sess, RET_ERR);
    sptr<CooperateEventManager::EventInfo> event = new (std::nothrow) CooperateEventManager::EventInfo();
    CHKPR(event, RET_ERR);
    event->type = CooperateEventManager::EventType::START;
    event->sess = sess;
    event->msgId = MmiMessageId::COOPERATION_MESSAGE;
    event->userData = userData;
    CooperateEventMgr->AddCooperationEvent(event);
    int32_t ret = InputDevCooSM->StartInputDeviceCooperate(sinkDeviceId, srcInputDeviceId);
    if (ret != RET_OK) {
        MMI_HILOGE("OnStartInputDeviceCooperate failed, ret:%{public}d", ret);
        CooperateEventMgr->OnErrorMessage(event->type, CooperationMessage(ret));
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::OnStopDeviceCooperate(int32_t pid, int32_t userData)
{
    CALL_DEBUG_ENTER;
    auto sess = GetSession(GetClientFd(pid));
    CHKPR(sess, RET_ERR);
    sptr<CooperateEventManager::EventInfo> event = new (std::nothrow) CooperateEventManager::EventInfo();
    CHKPR(event, RET_ERR);
    event->type = CooperateEventManager::EventType::STOP;
    event->sess = sess;
    event->msgId = MmiMessageId::COOPERATION_MESSAGE;
    event->userData = userData;
    CooperateEventMgr->AddCooperationEvent(event);
    int32_t ret = InputDevCooSM->StopInputDeviceCooperate();
    if (ret != RET_OK) {
        MMI_HILOGE("OnStopDeviceCooperate failed, ret:%{public}d", ret);
        CooperateEventMgr->OnErrorMessage(event->type, CooperationMessage(ret));
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::OnGetInputDeviceCooperateState(int32_t pid, int32_t userData, const std::string &deviceId)
{
    CALL_DEBUG_ENTER;
    auto sess = GetSession(GetClientFd(pid));
    CHKPR(sess, RET_ERR);
    sptr<CooperateEventManager::EventInfo> event = new (std::nothrow) CooperateEventManager::EventInfo();
    CHKPR(event, RET_ERR);
    event->type = CooperateEventManager::EventType::STATE;
    event->sess = sess;
    event->msgId = MmiMessageId::COOPERATION_GET_STATE;
    event->userData = userData;
    CooperateEventMgr->AddCooperationEvent(event);
    InputDevCooSM->GetCooperateState(deviceId);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_COOPERATE
} // namespace MMI
} // namespace OHOS
