/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "mmi_service.h"

#include <parameters.h>
#include <sys/signalfd.h>

#include <cinttypes>
#include <csignal>
#include <cstdlib>
#include "string_ex.h"
#ifdef OHOS_RSS_CLIENT
#include <unordered_map>
#endif // OHOS_RSS_CLIENT

#include "ability_manager_client.h"
#include "anr_manager.h"
#include "app_debug_listener.h"
#include "app_state_observer.h"
#include "device_event_monitor.h"
#include "dfx_define.h"
#include "dfx_dump_catcher.h"
#include "dfx_hisysevent.h"
#include "dfx_json_formatter.h"

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
#include "display_event_monitor.h"
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#include "event_dump.h"
#include "event_statistic.h"
#include "event_log_helper.h"
#include "ffrt.h"
#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
#include "fingersense_wrapper.h"
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
#include "gesturesense_wrapper.h"
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
#include "infrared_emitter_controller.h"
#include "input_device_manager.h"
#include "ipc_skeleton.h"
#include "i_input_windows_manager.h"
#include "i_pointer_drawing_manager.h"
#include "i_preference_manager.h"
#include "key_auto_repeat.h"
#include "key_command_handler.h"
#include "key_map_manager.h"
#ifdef SHORTCUT_KEY_MANAGER_ENABLED
#include "key_shortcut_manager.h"
#endif // SHORTCUT_KEY_MANAGER_ENABLED
#include "mmi_log.h"
#include "multimodal_input_connect_def_parcel.h"
#include "permission_helper.h"
#include "timer_manager.h"
#include "tokenid_kit.h"
#include "touch_event_normalize.h"
#include "touch_gesture_adapter.h"
#include "util.h"
#include "util_ex.h"
#include "watchdog_task.h"
#include "xcollie/watchdog.h"
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"

#ifdef OHOS_RSS_CLIENT
#include "res_sched_client.h"
#include "res_type.h"
#include "system_ability_definition.h"
#endif // OHOS_RSS_CLIENT
#include "setting_datashare.h"
#ifdef OHOS_BUILD_ENABLE_ANCO
#include "app_mgr_client.h"
#include "running_process_info.h"
#endif // OHOS_BUILD_ENABLE_ANCO

#ifdef PLAYER_FRAMEWORK_EXISTS
#include "input_screen_capture_agent.h"
#endif // PLAYER_FRAMEWORK_EXISTS

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
#include "vkeyboard.h"
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MMIService"
#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER

namespace OHOS {
namespace MMI {
namespace {
std::mutex g_instanceMutex;
MMIService* g_MMIService;
const std::string DEF_INPUT_SEAT { "seat0" };
const std::string THREAD_NAME { "mmi-service" };
constexpr int32_t WATCHDOG_INTERVAL_TIME { 30000 };
[[ maybe_unused ]] constexpr int32_t WATCHDOG_DELAY_TIME { 40000 };
constexpr int32_t RELOAD_DEVICE_TIME { 2000 };
[[ maybe_unused ]] constexpr int32_t WATCHDOG_WARNTIME { 6000 };
[[ maybe_unused ]] constexpr int32_t WATCHDOG_BLOCKTIME { 3000 };
constexpr int32_t REMOVE_OBSERVER { -2 };
constexpr int32_t REPEAT_COUNT { 2 };
constexpr int32_t UNSUBSCRIBED { -1 };
constexpr int32_t UNOBSERVED { -1 };
constexpr int32_t SUBSCRIBED { 1 };
[[ maybe_unused ]] constexpr int32_t DISTRIBUTE_TIME { 1000 }; // 1000ms
constexpr int32_t COMMON_PARAMETER_ERROR { 401 };
constexpr size_t MAX_FRAME_NUMS { 100 };
constexpr int32_t THREAD_BLOCK_TIMER_SPAN_S { 3 };
constexpr int32_t PRINT_INTERVAL_TIME { 30000 };
const std::set<int32_t> g_keyCodeValueSet = {
    KeyEvent::KEYCODE_FN, KeyEvent::KEYCODE_DPAD_UP, KeyEvent::KEYCODE_DPAD_DOWN, KeyEvent::KEYCODE_DPAD_LEFT,
    KeyEvent::KEYCODE_DPAD_RIGHT, KeyEvent::KEYCODE_ALT_LEFT, KeyEvent::KEYCODE_ALT_RIGHT,
    KeyEvent::KEYCODE_SHIFT_LEFT, KeyEvent::KEYCODE_SHIFT_RIGHT, KeyEvent::KEYCODE_TAB, KeyEvent::KEYCODE_ENTER,
    KeyEvent::KEYCODE_DEL, KeyEvent::KEYCODE_MENU, KeyEvent::KEYCODE_PAGE_UP, KeyEvent::KEYCODE_PAGE_DOWN,
    KeyEvent::KEYCODE_ESCAPE, KeyEvent::KEYCODE_FORWARD_DEL, KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_CTRL_RIGHT,
    KeyEvent::KEYCODE_CAPS_LOCK, KeyEvent::KEYCODE_SCROLL_LOCK, KeyEvent::KEYCODE_META_LEFT,
    KeyEvent::KEYCODE_META_RIGHT, KeyEvent::KEYCODE_SYSRQ, KeyEvent::KEYCODE_BREAK, KeyEvent::KEYCODE_MOVE_HOME,
    KeyEvent::KEYCODE_MOVE_END, KeyEvent::KEYCODE_INSERT, KeyEvent::KEYCODE_F1, KeyEvent::KEYCODE_F2,
    KeyEvent::KEYCODE_F3, KeyEvent::KEYCODE_F4, KeyEvent::KEYCODE_F5, KeyEvent::KEYCODE_F6, KeyEvent::KEYCODE_F7,
    KeyEvent::KEYCODE_F8, KeyEvent::KEYCODE_F9, KeyEvent::KEYCODE_F10, KeyEvent::KEYCODE_F11, KeyEvent::KEYCODE_F12,
    KeyEvent::KEYCODE_NUM_LOCK
};
#ifdef OHOS_BUILD_ENABLE_ANCO
constexpr int32_t DEFAULT_USER_ID { 100 };
#endif // OHOS_BUILD_ENABLE_ANCO
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
const std::string DEVICE_TYPE_HPR { "HPR" };
const std::string PRODUCT_TYPE = OHOS::system::GetParameter("const.build.product", "HYM");
// Define vkeyboard functions from vendor
const std::string VKEYBOARD_PATH { "libvkeyboard.z.so" };
constexpr int32_t VKEY_TP_SM_MSG_SIZE { 4 };
constexpr int32_t VKEY_TP_SM_MSG_TYPE_IDX { 0 };
constexpr int32_t VKEY_TP_SM_MSG_POINTER_ID_IDX { 1 };
constexpr int32_t VKEY_TP_SM_MSG_POS_X_IDX { 2 };
constexpr int32_t VKEY_TP_SM_MSG_POS_Y_IDX { 3 };
void* g_VKeyboardHandle = nullptr;
typedef void (*ALGORITHM_KEYDOWN_TYPE)(
    double screenX, double screenY, int touchId, bool tipDown, string buttonName);
ALGORITHM_KEYDOWN_TYPE algorithm_keydown_ = nullptr;
typedef void (*ALGORITHM_KEYUP_TYPE)(
    double screenX, double screenY, int touchId, bool tipDown, string buttonName);
ALGORITHM_KEYUP_TYPE algorithm_keyup_ = nullptr;
typedef int32_t (*GAUSSIANKEYBOARD_GETKEYCODEBYKEYNAME_TYPE)(string keyName);
GAUSSIANKEYBOARD_GETKEYCODEBYKEYNAME_TYPE gaussiankeyboard_getKeyCodeByKeyName_ = nullptr;
typedef int32_t (*GAUSSIANKEYBOARD_GETKEYCODEBYKEYNAMEANDSHIFT_TYPE)(string keyName, bool& useShift);
GAUSSIANKEYBOARD_GETKEYCODEBYKEYNAMEANDSHIFT_TYPE gaussiankeyboard_getKeyCodeByKeyNameAndShift_ = nullptr;
typedef void (*GAUSSIANKEYBOARD_UPDATEMOTIONSPACE_TYPE)(
    string keyName, bool useShift, std::vector<int32_t>& pattern);
GAUSSIANKEYBOARD_UPDATEMOTIONSPACE_TYPE gaussiankeyboard_updateMotionSpace_ = nullptr;
typedef void (*GAUSSIANKEYBOARD_SETVKEYBOARDAREA_TYPE)(
    double topLeftX, double topLeftY, double bottomRightX, double bottomRightY);
GAUSSIANKEYBOARD_SETVKEYBOARDAREA_TYPE gaussiankeyboard_setVKeyboardArea_ = nullptr;
typedef void (*BAYESIANENGINE_MAPTOUCHTOBUTTON_TYPE)(
    double screenX, double screenY, int touchId, bool tipDown, string& buttonName,
    long long timestamp, bool updateDynamicGaussian, vector<pair<string, double>>& sortedNegLogProb);
BAYESIANENGINE_MAPTOUCHTOBUTTON_TYPE bayesianengine_mapTouchToButton_ = nullptr;
// Return message type.
typedef int32_t (*STATEMACINEMESSAGQUEUE_GETMESSAGE_TYPE)(
    string& buttonName, string& toggleButtonName, int& buttonMode, string& RestList);
STATEMACINEMESSAGQUEUE_GETMESSAGE_TYPE statemachineMessageQueue_getMessage_ = nullptr;
typedef void (*STATEMACINEMESSAGQUEUE_CLEARMESSAGE_TYPE)();
STATEMACINEMESSAGQUEUE_CLEARMESSAGE_TYPE statemachineMessageQueue_clearMessage_ = nullptr;
typedef bool (*GAUSSIANKEYBOARD_ISINSIDEVKEYBOARDAREA_TYPE)(double x, double y);
GAUSSIANKEYBOARD_ISINSIDEVKEYBOARDAREA_TYPE gaussiankeyboard_isInsideVKeyboardArea_ = nullptr;
typedef bool (*GAUSSIANKEYBOARD_ISVKEYBOARDVISIBLE_TYPE)();
GAUSSIANKEYBOARD_ISVKEYBOARDVISIBLE_TYPE gaussiankeyboard_isVKeyboardVisible_ = nullptr;
typedef bool (*ALGORITHM_ISKEYDOWNINKEYBOARD_TYPE)(int touchId);
ALGORITHM_ISKEYDOWNINKEYBOARD_TYPE algorithm_isKeyDownInKeyboard_ = nullptr;
typedef void (*ALGORITHM_INITIALIZE_TYPE)(bool forceReset);
ALGORITHM_INITIALIZE_TYPE algorithm_initialize_ = nullptr;
typedef bool (*TRACKPADENGINE_ISINSIDEVTRACKPADAREA_TYPE)(double x, double y);
TRACKPADENGINE_ISINSIDEVTRACKPADAREA_TYPE trackPadEngine_isInsideVTrackPadArea_ = nullptr;
typedef bool (*TRACKPADENGINE_ISVTRACKPADVISIBLE_TYPE)();
TRACKPADENGINE_ISVTRACKPADVISIBLE_TYPE trackPadEngine_isVTrackPadVisible_ = nullptr;
typedef int32_t (*TRACKPADENGINE_INTERPRETPOINTEREVENT_TYPE)(
    std::vector<int32_t>& pInfo, std::vector<double>& pPos);
TRACKPADENGINE_INTERPRETPOINTEREVENT_TYPE trackPadEngine_interpretPointerEvent_ = nullptr;
typedef void (*TRACKPADENGINE_SETVTRACKPADAREA_TYPE)(
    std::string areaName, std::vector<int32_t>& pattern);
TRACKPADENGINE_SETVTRACKPADAREA_TYPE trackPadEngine_setVTrackPadArea_ = nullptr;
typedef void (*TRACKPADENGINE_SETSCREENAREA_TYPE)(
    int32_t topLeftX, int32_t topLeftY, int32_t width, int32_t height);
TRACKPADENGINE_SETSCREENAREA_TYPE trackPadEngine_setScreenArea_ = nullptr;
typedef void (*TRACKPADENGINE_GETALLTOUCHMESSAGE_TYPE)(
    std::vector<std::vector<int32_t>>& retMsgList);
TRACKPADENGINE_GETALLTOUCHMESSAGE_TYPE trackPadEngine_getAllTouchMessage_ = nullptr;
typedef void (*TRACKPADENGINE_CLEARTOUCHMESSAGE_TYPE)();
TRACKPADENGINE_CLEARTOUCHMESSAGE_TYPE trackPadEngine_clearTouchMessage_ = nullptr;
typedef void (*TRACKPADENGINE_GETALLKEYMESSAGE_TYPE)(
    std::vector<std::vector<int32_t>>& retMsgList);
TRACKPADENGINE_GETALLKEYMESSAGE_TYPE trackPadEngine_getAllKeyMessage_ = nullptr;
typedef void (*TRACKPADENGINE_CLEARKEYMESSAGE_TYPE)();
TRACKPADENGINE_CLEARKEYMESSAGE_TYPE trackPadEngine_clearKeyMessage_ = nullptr;
std::vector<int32_t> g_VKeyDownSet;
std::unordered_set<int32_t> g_VKeyModifiersDownSet;
std::unordered_set<int32_t> g_VKeyVisualsDownSet;
// Shared key event for key injection for printing.
std::shared_ptr<KeyEvent> g_VKeySharedKeyEvent { nullptr };
// Shared key event for UI rendering.
std::shared_ptr<KeyEvent> g_VKeySharedUIKeyEvent { nullptr };
std::unordered_map<int32_t, int32_t> g_VKeyFunctionKeyMapping = {
    {MMI::KeyEvent::KEYCODE_F1, MMI::KeyEvent::KEYCODE_BRIGHTNESS_DOWN},
    {MMI::KeyEvent::KEYCODE_F2, MMI::KeyEvent::KEYCODE_BRIGHTNESS_UP},
    {MMI::KeyEvent::KEYCODE_F4, MMI::KeyEvent::KEYCODE_VOLUME_MUTE},
    {MMI::KeyEvent::KEYCODE_F5, MMI::KeyEvent::KEYCODE_VOLUME_DOWN},
    {MMI::KeyEvent::KEYCODE_F6, MMI::KeyEvent::KEYCODE_VOLUME_UP},
    {MMI::KeyEvent::KEYCODE_F7, MMI::KeyEvent::KEYCODE_MUTE},
    {MMI::KeyEvent::KEYCODE_F8, MMI::KeyEvent::KEYCODE_SWITCHVIDEOMODE},
    {MMI::KeyEvent::KEYCODE_F9, MMI::KeyEvent::KEYCODE_SEARCH},
    {MMI::KeyEvent::KEYCODE_F10, MMI::KeyEvent::KEYCODE_MEDIA_RECORD},
    {MMI::KeyEvent::KEYCODE_F11, MMI::KeyEvent::KEYCODE_SYSRQ},
    {MMI::KeyEvent::KEYCODE_F12, MMI::KeyEvent::KEYCODE_INSERT},
};
bool g_FnKeyState = false;
// special group of keys that need touch down trigger to work with a physical mouse/trackpad.
std::unordered_set<int32_t> g_VKeyTouchDownInjectGroup = {
    MMI::KeyEvent::KEYCODE_CTRL_LEFT,
    MMI::KeyEvent::KEYCODE_CTRL_RIGHT,
    MMI::KeyEvent::KEYCODE_SHIFT_LEFT,
    MMI::KeyEvent::KEYCODE_SHIFT_RIGHT,
};
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
} // namespace

const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(MMIService::GetInstance());

template <class... Ts> void CheckDefineOutput(const char *fmt, Ts... args)
{
    CHKPV(fmt);
    char buf[MAX_PACKET_BUF_SIZE] = {};
    int32_t ret = snprintf_s(buf, MAX_PACKET_BUF_SIZE, MAX_PACKET_BUF_SIZE - 1, fmt, args...);
    if (ret == -1) {
        KMSG_LOGE("Call snprintf_s failed.ret = %d", ret);
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
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    CheckDefineOutput("%-40s", "OHOS_BUILD_ENABLE_INTERCEPTOR");
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    CheckDefineOutput("%-40s", "OHOS_BUILD_ENABLE_KEYBOARD");
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    CheckDefineOutput("%-40s", "OHOS_BUILD_ENABLE_POINTER");
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    CheckDefineOutput("%-40s", "OHOS_BUILD_ENABLE_TOUCH");
#endif // OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_MONITOR
    CheckDefineOutput("%-40s", "OHOS_BUILD_ENABLE_MONITOR");
#endif // OHOS_BUILD_ENABLE_MONITOR
}

MMIService::MMIService() : SystemAbility(MULTIMODAL_INPUT_CONNECT_SERVICE_ID, true) {}

MMIService::~MMIService()
{
    if (g_MMIService != nullptr) {
        g_MMIService = nullptr;
    }
    MMI_HILOGI("~MMIService");
}

MMIService* MMIService::GetInstance()
{
    if (g_MMIService == nullptr) {
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        if (g_MMIService == nullptr) {
            MMI_HILOGI("New MMIService");
            g_MMIService = new MMIService();
        }
    }
    return g_MMIService;
}

int32_t MMIService::AddEpoll(EpollEventType type, int32_t fd)
{
    if (type < EPOLL_EVENT_BEGIN || type >= EPOLL_EVENT_END) {
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
    auto eventData = std::make_shared<mmi_epoll_event>();
    eventData->fd = fd;
    eventData->event_type = type;
    MMI_HILOGI("userdata:[fd:%{public}d, type:%{public}d]", eventData->fd, eventData->event_type);

    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    auto ret = EpollCtl(fd, EPOLL_CTL_ADD, ev, mmiFd_);
    if (ret < 0) {
        eventData = nullptr;
        ev.data.ptr = nullptr;
        return ret;
    }
    AddEpollEvent(fd, eventData);
    return RET_OK;
}

int32_t MMIService::DelEpoll(EpollEventType type, int32_t fd)
{
    if (type < EPOLL_EVENT_BEGIN || type >= EPOLL_EVENT_END) {
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
    if (!(libinputAdapter_.Init([] (void *event, int64_t frameTime) {
        ::OHOS::DelayedSingleton<InputEventHandler>::GetInstance()->OnEvent(event, frameTime);
        }
        ))) {
        MMI_HILOGE("Libinput init, bind failed");
        return false;
    }
    auto inputFds = libinputAdapter_.GetInputFds();
    for (auto fd : inputFds) {
        auto ret = AddEpoll(EPOLL_EVENT_INPUT, fd);
        if (ret < 0) {
            MMI_HILOGE("AddEpoll error ret:%{public}d", ret);
            EpollClose();
            return false;
        }
        MMI_HILOGD("AddEpoll, epollfd:%{public}d, fd:%{public}d", mmiFd_, fd);
    }
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
    if (EpollCreate(MAX_EVENT_SIZE) < 0) {
        MMI_HILOGE("Create epoll failed");
        return false;
    }
    auto ret = AddEpoll(EPOLL_EVENT_SOCKET, epollFd_);
    if (ret < 0) {
        MMI_HILOGE("AddEpoll error ret:%{public}d", ret);
        EpollClose();
        return false;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    if (!(Publish(this))) {
        state_ = ServiceRunningState::STATE_NOT_START;
        MMI_HILOGE("Service initialization failed");
        EpollClose();
        return false;
    }
    MMI_HILOGI("AddEpoll, epollfd:%{public}d, fd:%{public}d", mmiFd_, epollFd_);
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
    if (ret < 0) {
        MMI_HILOGE("AddEpoll error ret:%{public}d", ret);
        EpollClose();
        return false;
    }
    std::function<int32_t(DTaskCallback)> fun = [this](DTaskCallback cb) -> int32_t {
        return delegateTasks_.PostSyncTask(cb);
    };
    delegateInterface_ = std::make_shared<DelegateInterface>(fun);
    delegateInterface_->Init();
    MMI_HILOGI("AddEpoll, epollfd:%{public}d, fd:%{public}d", mmiFd_, delegateTasks_.GetReadFd());
    return true;
}
__attribute__((no_sanitize("cfi")))
int32_t MMIService::Init()
{
    CheckDefine();
    MMI_HILOGD("WindowsManager Init");
    WIN_MGR->Init(*this);
    MMI_HILOGD("NapProcess Init");
    NapProcess::GetInstance()->Init(*this);
    MMI_HILOGD("ANRManager Init");
    ANRMgr->Init(*this);
    MMI_HILOGI("PointerDrawingManager Init");
#ifdef OHOS_BUILD_ENABLE_POINTER
    if (!IPointerDrawingManager::GetInstance()->Init()) {
        MMI_HILOGE("Pointer draw init failed");
        return POINTER_DRAW_INIT_FAIL;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    mmiFd_ = EpollCreate(MAX_EVENT_SIZE);
    if (mmiFd_ < 0) {
        MMI_HILOGE("Create epoll failed");
        return EPOLL_CREATE_FAIL;
    }
    MMI_HILOGD("Input msg handler init");
    InputHandler->Init(*this);
    MMI_HILOGD("Libinput service init");
    if (!InitLibinputService()) {
        MMI_HILOGE("Libinput init failed");
        return LIBINPUT_INIT_FAIL;
    }
    MMI_HILOGD("Init DelegateTasks init");
    if (!InitDelegateTasks()) {
        MMI_HILOGE("Delegate tasks init failed");
        return ETASKS_INIT_FAIL;
    }
    SetRecvFun([this] (SessionPtr sess, NetPacket& pkt) {sMsgHandler_.OnMsgHandler(sess, pkt);});
    KeyMapMgr->GetConfigKeyValue("default_keymap", KeyMapMgr->GetDefaultKeyId());
    OHOS::system::SetParameter(INPUT_POINTER_DEVICES, "false");
    if (!InitService()) {
        MMI_HILOGE("Saservice init failed");
        return SASERVICE_INIT_FAIL;
    }
    MMI_HILOGI("Set para input.pointer.device false");
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
bool IsEightFingersDown(int32_t pointerId, int32_t pointerAction)
{
    if (pointerAction == MMI::PointerEvent::POINTER_ACTION_UP) {
        std::vector<int32_t>::iterator ite = std::find(g_VKeyDownSet.begin(), g_VKeyDownSet.end(), pointerId);
        if (ite != g_VKeyDownSet.end()) {
            g_VKeyDownSet.erase(ite);
        }
    } else if (pointerAction == MMI::PointerEvent::POINTER_ACTION_DOWN) {
        if (std::find(g_VKeyDownSet.begin(), g_VKeyDownSet.end(), pointerId) == g_VKeyDownSet.end()) {
            g_VKeyDownSet.push_back(pointerId);
        }
    }
    const int32_t totalFingerNum = 8;
    return g_VKeyDownSet.size() == totalFingerNum;
}

void HandleKeyActionHelper(int32_t action, int32_t keyCode, OHOS::MMI::KeyEvent::KeyItem &item)
{
    if (action == OHOS::MMI::KeyEvent::KEY_ACTION_DOWN) {
        g_VKeySharedKeyEvent->AddPressedKeyItems(item);
    }
    if (action == OHOS::MMI::KeyEvent::KEY_ACTION_UP) {
        std::optional<OHOS::MMI::KeyEvent::KeyItem> pressedKeyItem = g_VKeySharedKeyEvent->GetKeyItem(keyCode);
        if (pressedKeyItem) {
            item.SetDownTime(pressedKeyItem->GetDownTime());
        } else {
            MMI_HILOGW("VKeyboard find pressed key failed");
        }
        g_VKeySharedKeyEvent->RemoveReleasedKeyItems(item);
        g_VKeySharedKeyEvent->AddPressedKeyItems(item);
    }
}

// Ref: oh_input_manager.
// Receive: action and keyCode.
// send out modified global g_VKeySharedKeyEvent to the event normalizer.
int32_t HandleKeyInjectEventHelper(std::shared_ptr<EventNormalizeHandler> eventNormalizeHandler,
    int32_t action, int32_t keyCode)
{
    MMI_HILOGD("VKeyboard HandleKeyInjectEventHelper, injectEvent, action=%{public}d", action);
    if (keyCode < 0) {
        MMI_HILOGE("VKeyboard keyCode is less 0, can not process");
        return COMMON_PARAMETER_ERROR;
    }
    CHKPR(g_VKeySharedKeyEvent, ERROR_NULL_POINTER);
    g_VKeySharedKeyEvent->ClearFlag();
    if (g_VKeySharedKeyEvent->GetAction() == OHOS::MMI::KeyEvent::KEY_ACTION_UP) {
        std::optional<OHOS::MMI::KeyEvent::KeyItem> preUpKeyItem = g_VKeySharedKeyEvent->GetKeyItem();
        if (preUpKeyItem) {
            g_VKeySharedKeyEvent->RemoveReleasedKeyItems(*preUpKeyItem);
        } else {
            MMI_HILOGE("VKeyboard the preUpKeyItem is nullopt");
        }
    }
    int64_t time = OHOS::MMI::GetSysClockTime();
    g_VKeySharedKeyEvent->SetActionTime(time);
    g_VKeySharedKeyEvent->SetRepeat(false);
    g_VKeySharedKeyEvent->SetKeyCode(keyCode);
    bool isKeyPressed = false;

    // get keyboard CAPS state.
    auto keyEvent = KeyEventHdr->GetKeyEvent();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    bool capsLockState = keyEvent->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY);

    if (action == OHOS::MMI::KeyEvent::KEY_ACTION_DOWN) {
        g_VKeySharedKeyEvent->SetAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
        g_VKeySharedKeyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
        isKeyPressed = true;

        // set the CAPS key.
        if (keyCode == KeyEvent::KEYCODE_CAPS_LOCK) {
            // flip the flag.
            capsLockState = !capsLockState;
            keyEvent->SetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY, static_cast<int32_t>(capsLockState));
        }
    } else if (action == OHOS::MMI::KeyEvent::KEY_ACTION_UP) {
        g_VKeySharedKeyEvent->SetAction(OHOS::MMI::KeyEvent::KEY_ACTION_UP);
        g_VKeySharedKeyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_UP);
        isKeyPressed = false;
    }

    // sync the latest CAPS lock state anyways.
    g_VKeySharedKeyEvent->SetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY, static_cast<int32_t>(capsLockState));

    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetDownTime(time);
    item.SetKeyCode(keyCode);
    item.SetPressed(isKeyPressed);
    HandleKeyActionHelper(action, keyCode, item);
    g_VKeySharedKeyEvent->AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_SIMULATE);
    
    eventNormalizeHandler->HandleKeyEvent(g_VKeySharedKeyEvent);
    return RET_OK;
}

// @brief Send out combination key press.
// Note that toggleBtn may contain more than one modifiers, like Ctrl+Shift.
int32_t SendCombinationKeyPress(std::vector<int32_t>& toggleKeyCodes, int32_t triggerKeyCode)
{
    std::shared_ptr<EventNormalizeHandler> eventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPR(eventNormalizeHandler, ERROR_NULL_POINTER);
    // Trigger all modifier(s), if not done already.
    for (auto& toggleCode: toggleKeyCodes) {
        if (g_VKeyModifiersDownSet.count(toggleCode) == 0) {
            // Not exist, then trigger the modifier.
            HandleKeyInjectEventHelper(eventNormalizeHandler, OHOS::MMI::KeyEvent::KEY_ACTION_DOWN,
                toggleCode);
            g_VKeyModifiersDownSet.insert(toggleCode);
        }
    }
    // Trigger key.
    HandleKeyInjectEventHelper(eventNormalizeHandler, OHOS::MMI::KeyEvent::KEY_ACTION_DOWN,
        triggerKeyCode);
    // Release key.
    HandleKeyInjectEventHelper(eventNormalizeHandler, OHOS::MMI::KeyEvent::KEY_ACTION_UP,
        triggerKeyCode);
    return RET_OK;
}

// @brief Key Down (add to key event handler and modifiers down set).
int32_t SendKeyDown(int32_t keyCode)
{
    std::shared_ptr<EventNormalizeHandler> eventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPR(eventNormalizeHandler, ERROR_NULL_POINTER);
    // Trigger key.
    HandleKeyInjectEventHelper(eventNormalizeHandler, OHOS::MMI::KeyEvent::KEY_ACTION_DOWN,
        keyCode);
    g_VKeyModifiersDownSet.insert(keyCode);
    return RET_OK;
}

// @brief Key Release (remove from key event handler and modifiers down set).
int32_t SendKeyRelease(int32_t keyCode)
{
    std::shared_ptr<EventNormalizeHandler> eventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPR(eventNormalizeHandler, ERROR_NULL_POINTER);
    // Release key.
    if (g_VKeyModifiersDownSet.count(keyCode) > 0) {
        HandleKeyInjectEventHelper(eventNormalizeHandler, OHOS::MMI::KeyEvent::KEY_ACTION_UP, keyCode);
        g_VKeyModifiersDownSet.erase(keyCode);
    } else {
        MMI_HILOGI("Skip key release as it is not added to down set before.");
    }

    return RET_OK;
}

// @brief Print (inject key code), including key down and release.
int32_t SendKeyPress(int32_t keyCode)
{
    std::shared_ptr<EventNormalizeHandler> eventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPR(eventNormalizeHandler, ERROR_NULL_POINTER);
    // Trigger key.
    HandleKeyInjectEventHelper(eventNormalizeHandler, OHOS::MMI::KeyEvent::KEY_ACTION_DOWN,
        keyCode);
    // Release key.
    HandleKeyInjectEventHelper(eventNormalizeHandler, OHOS::MMI::KeyEvent::KEY_ACTION_UP,
        keyCode);
    g_VKeyModifiersDownSet.erase(keyCode);
    return RET_OK;
}

// @brief Only toggle visual state on UI without changing key event handler.
int32_t ToggleKeyVisualState(std::string& keyName, int32_t keyCode, bool visualPressed)
{
    std::shared_ptr<EventNormalizeHandler> eventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPR(eventNormalizeHandler, ERROR_NULL_POINTER);
    g_VKeySharedUIKeyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);
    // If this shared event's previous action is up, it means
    // there is a key up event left in the pressed seq. remove it now.
    if (g_VKeySharedUIKeyEvent->GetVKeyboardAction() == KeyEvent::VKeyboardAction::VKEY_UP) {
        std::optional<OHOS::MMI::KeyEvent::KeyItem> preUpKeyItem = g_VKeySharedUIKeyEvent->GetKeyItem();
        if (preUpKeyItem) {
            g_VKeySharedUIKeyEvent->RemoveReleasedKeyItems(*preUpKeyItem);
        } else {
            MMI_HILOGE("VKeyboard the preUpKeyItem is nullopt");
        }
    }
    int64_t time = OHOS::MMI::GetSysClockTime();
    g_VKeySharedUIKeyEvent->SetActionTime(time);

    // get keyboard CAPS state.
    auto keyEvent = KeyEventHdr->GetKeyEvent();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    bool capsLockState = keyEvent->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY);

    KeyEvent::KeyItem keyItem;
    keyItem.SetDownTime(time);
    keyItem.SetKeyCode(keyCode);
    keyItem.SetPressed(visualPressed);

    g_VKeySharedUIKeyEvent->SetKeyCode(keyCode);
    g_VKeySharedUIKeyEvent->SetKeyName(keyName);

    if (visualPressed) {
        g_VKeySharedUIKeyEvent->SetVKeyboardAction(KeyEvent::VKeyboardAction::VKEY_DOWN);
        g_VKeySharedUIKeyEvent->AddPressedKeyItems(keyItem);
    } else {
        g_VKeySharedUIKeyEvent->SetVKeyboardAction(KeyEvent::VKeyboardAction::VKEY_UP);
        // Get the correct down time from pressed keys (when it is down)
        std::optional<OHOS::MMI::KeyEvent::KeyItem> pressedKeyItem = g_VKeySharedUIKeyEvent->GetKeyItem(keyCode);
        if (pressedKeyItem) {
            keyItem.SetDownTime(pressedKeyItem->GetDownTime());
        } else {
            MMI_HILOGW("VKeyboard find pressed key failed");
        }
        // Remove the old ones (down key item) and add the new one (up key item)
        g_VKeySharedUIKeyEvent->RemoveReleasedKeyItems(keyItem);
        g_VKeySharedUIKeyEvent->AddPressedKeyItems(keyItem);
    }

    // sync the latest CAPS lock state anyways.
    g_VKeySharedUIKeyEvent->SetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY, static_cast<int32_t>(capsLockState));

    eventNormalizeHandler->HandleKeyEvent(g_VKeySharedUIKeyEvent);
    return RET_OK;
}

// Use temporary events for vk-UI related communications.
int32_t SendKeyboardAction(KeyEvent::VKeyboardAction action)
{
    std::shared_ptr<EventNormalizeHandler> eventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPR(eventNormalizeHandler, ERROR_NULL_POINTER);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    int32_t keyEventId = 1234;
    int32_t keyEventDeviceId = 99;
    keyEvent->SetId(keyEventId);
    keyEvent->SetDeviceId(keyEventDeviceId);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);
    keyEvent->SetVKeyboardAction(action);
    KeyEvent::KeyItem keyItem;
    keyEvent->AddKeyItem(keyItem);
    eventNormalizeHandler->HandleKeyEvent(keyEvent);
    return RET_OK;
}

int32_t PointerEventHandler(std::shared_ptr<PointerEvent> pointerEvent)
{
    int32_t pointerAction = pointerEvent->GetPointerAction();
    int32_t sourceType = pointerEvent->GetSourceType();
    if (sourceType != MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN ||
        (pointerAction != MMI::PointerEvent::POINTER_ACTION_UP &&
        pointerAction != MMI::PointerEvent::POINTER_ACTION_DOWN &&
        pointerAction != MMI::PointerEvent::POINTER_ACTION_MOVE)) {
        return 0;
    }
    // Set touch point
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("VKeyboard can't find pointer item");
        return RET_ERR;
    }
    // Note: make sure this logic happens before the range-checking logic.
    // Check if pointer action is not POINTER_ACTION_MOVE and 8 fingers down
    if (pointerAction != MMI::PointerEvent::POINTER_ACTION_MOVE && IsEightFingersDown(pointerId, pointerAction)) {
        SendKeyboardAction(KeyEvent::VKeyboardAction::ACTIVATE_KEYBOARD);
        return RET_OK;
    }
    double physicalX = pointerItem.GetDisplayXPos();
    double physicalY = pointerItem.GetDisplayYPos();
    // Note:
    // for delete gestures, it must begin from the backspace key, but stops when the finger moves out of range.
    // for pinch gestures, we allow out-of-range gestures (e.g., for floating -> full,
    // it's okay if the fingers are moving out of the boundary during the gestures since the kbd is very small)
    bool insideVKeyboardArea = gaussiankeyboard_isInsideVKeyboardArea_(physicalX, physicalY);
    bool isVkeyboardVisible = gaussiankeyboard_isVKeyboardVisible_();
    bool isTouchInVKeyboard = algorithm_isKeyDownInKeyboard_(pointerId);
    // Check the range of trackpad here
    bool isVTrackPadVisible = trackPadEngine_isVTrackPadVisible_();
    bool insideVTrackPadArea = trackPadEngine_isInsideVTrackPadArea_(physicalX, physicalY);
    if (isVTrackPadVisible && isVkeyboardVisible && insideVTrackPadArea) {
        if (pointerEvent == nullptr) {
            MMI_HILOGE("PointerEvent is null");
            return RET_ERR;
        }
        std::vector<int32_t> pointerInfo;
        pointerInfo.push_back(pointerId);
        pointerInfo.push_back(pointerAction);
        std::vector<double> pointerPos;
        pointerPos.push_back(physicalX);
        pointerPos.push_back(physicalY);
        int32_t ret = trackPadEngine_interpretPointerEvent_(pointerInfo, pointerPos);
        // Handle all track pad key messages
        std::vector<std::vector<int32_t>> keyMsgList;
        trackPadEngine_getAllKeyMessage_(keyMsgList);
        trackPadEngine_clearKeyMessage_();
        MMIService::GetInstance()->OnVKeyTrackPadMessage(keyMsgList);
        // Handle all track pad touch messages
        std::vector<std::vector<int32_t>> touchMsgList;
        trackPadEngine_getAllTouchMessage_(touchMsgList);
        trackPadEngine_clearTouchMessage_();
        MMIService::GetInstance()->OnVKeyTrackPadMessage(touchMsgList);
        return ret;
    }
    // Note: during layout switch, it's possible that a continuous movement happens
    // outside of keyboard (e.g., keyboard already switched)
    // or happens when kbd is not visible (e.g., when the prev layout dismissed but new one hasn't shown yet).
    if (!isTouchInVKeyboard && (!isVkeyboardVisible || (!insideVKeyboardArea && !insideVTrackPadArea))) {
        // no unhanded touch points AND (kbd not visible) OR (kbd visible and out of range).
        // i.e., we still want to process the touch move outside of
        // kbd range if at least one point is already on the kbd.
        return RET_OK;
    }

    TOUCHPOINT tp;
    tp.InKeyboard = insideVKeyboardArea;
    tp.InTrackpad = insideVTrackPadArea;
    tp.ScreenX = physicalX;
    tp.ScreenY = physicalY;
    tp.TouchId = pointerId;
    // Note: Down & Move treated as down.
    tp.TipDown = (pointerAction != MMI::PointerEvent::POINTER_ACTION_UP);

    std::vector<pair<string, double>> sortedNegLogProb;
    string buttonName = "";
    // Note: only Down will update dynamic gaussian.
    bool updateDynamicGaussian = (pointerAction == MMI::PointerEvent::POINTER_ACTION_DOWN);

    // NOTE: we don't run MapTouchToButton for all touchpoints -- only if the touchpoints fall within the kbd range.
    // for out-of-range points, we still continue to process potential out-of-range
    // gestures (e.g., fingers move out of range during pinch or move up/down gesture)
    // in such case, isTouchInVKeyboard == true means it origins from inside kbd so a cache has been found.
    if (insideVKeyboardArea || isTouchInVKeyboard) {
        // Need to add valid time here.
        bayesianengine_mapTouchToButton_(tp.ScreenX, tp.ScreenY, tp.TouchId, tp.TipDown, buttonName,
            0, updateDynamicGaussian, sortedNegLogProb);
        tp.ButtonName = buttonName;
        if (!tp.ButtonName.empty()) {
            MMI_HILOGD("VKeyboard touch name %{private}s", buttonName.c_str());
        } else {
            MMI_HILOGE("VKeyboard button name null");
            return RET_ERR;
        }
    }

    int32_t keyCodeToRelease = -1;
    if (pointerAction == MMI::PointerEvent::POINTER_ACTION_DOWN) {
        algorithm_keydown_(tp.ScreenX, tp.ScreenY, tp.TouchId, tp.TipDown, tp.ButtonName);
    } else if (pointerAction == MMI::PointerEvent::POINTER_ACTION_UP) {
        algorithm_keyup_(tp.ScreenX, tp.ScreenY, tp.TouchId, tp.TipDown, tp.ButtonName);
        keyCodeToRelease = gaussiankeyboard_getKeyCodeByKeyName_(buttonName);
        if (keyCodeToRelease >= 0 && g_VKeyVisualsDownSet.count(keyCodeToRelease) > 0) {
            // turn off visuals only when it is still on.
            ToggleKeyVisualState(buttonName, keyCodeToRelease, false);
            g_VKeyVisualsDownSet.erase(keyCodeToRelease);
        } else {
            MMI_HILOGD("VKeyboard PointerEventHandler, skip visual off %{private}s", buttonName.c_str());
        }
    } else {
        // New touch move logic: turn to touch down to support gestures.
        algorithm_keydown_(tp.ScreenX, tp.ScreenY, tp.TouchId, tp.TipDown, tp.ButtonName);
    }

    std::vector<int32_t> toggleKeyCodes;

    while (true) {
        string buttonName;
        string toggleButtonName;
        int buttonMode;
        string restList;
        StateMachineMessageType type = (StateMachineMessageType)statemachineMessageQueue_getMessage_(
            buttonName, toggleButtonName, buttonMode, restList);
        if (type == StateMachineMessageType::NoMessage) {
            break;
        }
        switch (type) {
            case StateMachineMessageType::KeyPressed: {
                // See if this key can be directly printed or not.
                bool useShift = false;
                int32_t code = gaussiankeyboard_getKeyCodeByKeyNameAndShift_(buttonName, useShift);
                if (code < 0) {
                    MMI_HILOGW("VKeyboard key code not found.");
                    break;
                }

                // VKErrorTool: NonToggableKeyPress.
                MMI_HILOGI("NonToggableButtonClick, KeyPress: %{private}s", buttonName.c_str());

                if (!g_FnKeyState && code == KeyEvent::KEYCODE_F4) {
                    // VOLUME_MUTE (F4) needs special touch down trigger logic.
                    SendKeyRelease(KeyEvent::KEYCODE_VOLUME_MUTE);
                } else if (g_VKeyTouchDownInjectGroup.count(code) > 0) {
                    // Ctrl/Shift needs special touch down logic to work with a mouse.
                    g_VKeySharedKeyEvent->SetVKeyboardAction(KeyEvent::VKeyboardAction:VKEY_UP);
                    SendKeyRelease(code);
                } else if (!g_FnKeyState && g_VKeyFunctionKeyMapping.find(code) != g_VKeyFunctionKeyMapping.end()) {
                    // fn key off, and first row hardware switch keys are pressed.
                    int32_t hardwareCode = g_VKeyFunctionKeyMapping.find(code)->second;
                    SendKeyPress(hardwareCode);
                } else if (!useShift) {
                    // regular key press without the need of using Shift to assist key injection.
                    SendKeyPress(code);
                } else {
                    // spefical floating keyboard symbol keys that need Shift to assist key injection.
                    toggleKeyCodes.clear();
                    toggleKeyCodes.push_back(KeyEvent::KEYCODE_SHIFT_LEFT);
                    SendCombinationKeyPress(toggleKeyCodes, code);
                    // If this key is triggered with use shift ON, then it shall be resumed after use.
                    SendKeyRelease(KeyEvent::KEYCODE_SHIFT_LEFT);
                }

                // the keyCodeToRelease has been handled.
                if (code == keyCodeToRelease) {
                    keyCodeToRelease = -1;
                }

                break;
            }
            case StateMachineMessageType::ButtonSound: {
                break;
            }
            case StateMachineMessageType::ResetButtonColor: {
                SendKeyboardAction(KeyEvent::VKeyboardAction::RESET_BUTTON_COLOR);

                g_VKeyVisualsDownSet.clear();
                break;
            }
            case StateMachineMessageType::CombinationKeyPressed: {
                toggleKeyCodes.clear();
                std::string remainStr = toggleButtonName;
                int32_t toggleCode(-1);
                int32_t triggerCode(-1);
                while (remainStr.find(';') != std::string::npos) {
                    // still has more than one 
                    size_t pos = remainStr.find(';');
                    toggleCode = gaussiankeyboard_getKeyCodeByKeyName_(remainStr.substr(0, pos));
                    if (toggleCode >= 0) {
                        toggleKeyCodes.push_back(toggleCode);
                    }
                    remainStr = remainStr.substr(pos + 1);
                }
                // Add the last piece.
                toggleCode = gaussiankeyboard_getKeyCodeByKeyName_(remainStr);
                if (toggleCode >= 0) {
                    toggleKeyCodes.push_back(toggleCode);
                }
                // Trigger code:
                triggerCode = gaussiankeyboard_getKeyCodeByKeyName_(buttonName);
                if (toggleKeyCodes.size() > 0 && triggerCode >= 0) {
                    // valid toggle key code(s) and trigger key code
                    SendCombinationKeyPress(toggleKeyCodes, triggerCode);
                } else {
                    MMI_HILOGW("VKeyboard combination keycodes not found for %{private}s + %{private}s",
                        toggleButtonName.c_str(), buttonName.c_str());
                }

                // this trigger code has been handled.
                if (triggerCode == keyCodeToRelease) {
                    keyCodeToRelease = -1;
                }
                break;
            }
            case StateMachineMessageType::BackSwipeLeft: {
                // Send Shift+Left.
                toggleKeyCodes.clear();
                toggleKeyCodes.push_back(KeyEvent::KEYCODE_SHIFT_LEFT);
                SendCombinationKeyPress(toggleKeyCodes, KeyEvent::KEYCODE_DPAD_LEFT);

                g_VKeyVisualsDownSet.insert(KeyEvent::KEYCODE_DEL);
                break;
            }
            case StateMachineMessageType::BackSwipeRight: {
                // Send Shift+Right
                toggleKeyCodes.clear();
                toggleKeyCodes.push_back(KeyEvent::KEYCODE_SHIFT_LEFT);
                SendCombinationKeyPress(toggleKeyCodes, KeyEvent::KEYCODE_DPAD_RIGHT);

                g_VKeyVisualsDownSet.insert(KeyEvent::KEYCODE_DEL);
                break;
            }
            case StateMachineMessageType::BackspaceSwipeRelease: {
                SendKeyRelease(KeyEvent::KEYCODE_SHIFT_LEFT);
                int swipeCharCounter(buttonMode);
                if (swipeCharCounter < 0) {
                    // Backspace character
                    SendKeyPress(KeyEvent::KEYCODE_DEL);
                } else if (swipeCharCounter > 0) {
                    // del character. (note: actually there is no difference when the text is selected)
                    SendKeyPress(KeyEvent::KEYCODE_FORWARD_DEL);
                } else {
                    // No char deleted. just release the shift if it was pressed down before.
                    MMI_HILOGI("VKeyboard SendSwipeDeleteMsg, swipeCharCounter = %{private}d. Release Shift.",
                        swipeCharCounter);
                }
                break;
            }
            case StateMachineMessageType::SwitchLayout: {
                int gestureId = buttonMode;
                auto gestureType = static_cast<VGestureMode>(gestureId);
                // Note: this LayoutAction is used within backend algorithm,
                // which may be different from the protocol with front end (VKeyboardAction)
                switch (gestureType) {
                    case VGestureMode::TWO_HANDS_UP: {
                        MMI_HILOGI("VKeyboard 8-finger move up to enable trackpad (not linked yet).");
                        // If we are sure that only full keyboard is kept, then we no longer need this move up/down gesture.
                        break;
                    }
                    case VGestureMode::TWO_HANDS_DOWN: {
                        MMI_HILOGI("VKeyboard 8-finger move down to disable trackpad (not linked yet).");
                        // If we are sure that only full keyboard is kept, then we no longer need this move up/down gesture.
                        break;
                    }
                    case VGestureMode::TWO_HANDS_INWARDS: {
                        MMI_HILOGI("VKeyboard 2-finger move inwards to switch to floating kbd.");
                        SendKeyboardAction(KeyEvent::VKeyboardAction::TWO_FINGERS_IN);
                        break;
                    }
                    case VGestureMode::TWO_HANDS_OUTWARDS: {
                        MMI_HILOGI("VKeyboard 2-finger move outwards to switch to standard/full kbd.");
                        // Note: if we have both standard and full kdb, then the front
                        // end shall track and resume user's previous choice of layout.
                        SendKeyboardAction(KeyEvent::VKeyboardAction::TWO_FINGERS_OUT);
                        break;
                    }
                    default: {
                        // other gestures not implemented/supported yet.
                        MMI_HILOGW("VKeyboard gesture not implemented or supported, gestureId: %{private}d", gestureId);
                    }
                }
                SendKeyboardAction(KeyEvent::VKeyboardAction::RESET_BUTTON_COLOR);
                break;
            }
            case StateMachineMessageType::DelayUpdateButtonTouchDownVisual: {
                MMI_HILOGI("VKeyboard key down (delayed): %{private}s, mode: %{public}d",
                    buttonName.c_str(),
                    buttonMode);

                int32_t keyCode = gaussiankeyboard_getKeyCodeByKeyName_(buttonName);
                if (keyCode < 0) {
                    MMI_HILOGW("VKeyboard key code not found for %{private}s", buttonName.c_str());
                    break;
                }

                ToggleKeyVisualState(buttonName, keyCode, true);

                if (buttonMode == 1) {
                    // flag for turning it off now.
                    ToggleKeyVisualState(buttonName, keyCode, false);
                } else {
                    // not turning it off right away, then store this info.
                    g_VKeyVisualsDownSet.insert(keyCode);
                }

                if (keyCode == KeyEvent::KEYCODE_FN) {
                    g_FnKeyState = !g_FnKeyState;
                } else if (!g_FnKeyState && keyCode == KeyEvent::KEYCODE_F4) {
                    // VOLUME_MUTE (F4) needs special touch down logic.
                    SendKeyDown(KeyEvent::KEYCODE_VOLUME_MUTE);
                } else if (g_VKeyTouchDownInjectGroup.count(keyCode) > 0) {
                    // Ctrl/Shift need special touch down logic to work with a mouse.
                    g_VKeySharedKeyEvent->SetVKeyboardAction(KeyEvent::VKeyboardAction::VKEY_DOWN);
                    SendKeyDown(keyCode);
                }

                break;
            }
            default:
                break;
        }
    }

    // all state machine messages are handled, see if the keyCodeToRelease remains unhandled.
    if (keyCodeToRelease >= 0) {
        if (g_VKeyTouchDownInjectGroup.count(keyCodeToRelease) > 0) {
            // Ctrl/Shift need special touch down logic to work with a mouse.
            g_VKeySharedKeyEvent->SetVKeyboardAction(KeyEvent::VKeyboardAction::VKEY_UP);
        }
        SendKeyRelease(keyCodeToRelease);
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

void MMIService::OnStart()
{
    CHK_PID_AND_TID();
    int32_t ret = Init();
    CHKNOKRV(ret, "Init mmi_service failed");
    MMI_HILOGD("Started successfully");
    AddReloadDeviceTimer();
    t_ = std::thread([this] {this->OnThread();});
    pthread_setname_np(t_.native_handle(), THREAD_NAME.c_str());
    eventMonitorThread_ = std::thread(&EventStatistic::WriteEventFile);
    pthread_setname_np(eventMonitorThread_.native_handle(), "event-monitor");
#ifdef OHOS_RSS_CLIENT
    MMI_HILOGI("Add system ability listener start");
    AddSystemAbilityListener(RES_SCHED_SYS_ABILITY_ID);
    MMI_HILOGI("Add system ability listener success");
#endif // OHOS_RSS_CLIENT
#if defined(OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER) && defined(OHOS_BUILD_ENABLE_KEYBOARD)
    FINGERSENSE_WRAPPER->InitFingerSenseWrapper();
    MMI_HILOGI("Add system ability listener start");
    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    MMI_HILOGI("Add system ability listener success");
    AddSystemAbilityListener(RENDER_SERVICE);
    DISPLAY_MONITOR->InitCommonEventSubscriber();
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER && OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    GESTURESENSE_WRAPPER->InitGestureSenseWrapper();
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    MMI_HILOGI("Add app manager service listener start");
    AddSystemAbilityListener(APP_MGR_SERVICE_ID);
    APP_OBSERVER_MGR->InitAppStateObserver();
    MMI_HILOGI("Add app manager service listener end");
    AddAppDebugListener();
    AddSystemAbilityListener(DISPLAY_MANAGER_SERVICE_SA_ID);
#ifdef OHOS_BUILD_ENABLE_ANCO
    InitAncoUds();
#endif // OHOS_BUILD_ENABLE_ANCO
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    isHPR_ = PRODUCT_TYPE == DEVICE_TYPE_HPR;
    if (isHPR_) {
        DelegateInterface::HandlerSummary summary = {};
        summary.handlerName = "VKeyboard";
        summary.eventType = HANDLE_EVENT_TYPE_POINTER;
        summary.mode = HandlerMode::SYNC;
        summary.priority = 0;
        summary.deviceTags = 0;
        summary.cb = PointerEventHandler;
        delegateInterface_->AddHandler(InputHandlerType::MONITOR, summary);

        // Initialize vkeyboard handler
        g_VKeyboardHandle = dlopen(VKEYBOARD_PATH.c_str(), RTLD_NOW);
        if (g_VKeyboardHandle != nullptr) {
            algorithm_keydown_ = (ALGORITHM_KEYDOWN_TYPE)dlsym(g_VKeyboardHandle, "AlgorithmKeyDown");
            algorithm_keyup_ = (ALGORITHM_KEYUP_TYPE)dlsym(g_VKeyboardHandle, "AlgorithmKeyUp");
            gaussiankeyboard_getKeyCodeByKeyName_ = (GAUSSIANKEYBOARD_GETKEYCODEBYKEYNAME_TYPE)dlsym(
                g_VKeyboardHandle, "GaussianKeyboardGetKeyCodeByKeyName");
            gaussiankeyboard_getKeyCodeByKeyNameAndShift_ = (GAUSSIANKEYBOARD_GETKEYCODEBYKEYNAMEANDSHIFT_TYPE)dlsym(
                g_VKeyboardHandle, "GaussianKeyboardGetKeyCodeByKeyNameAndShift");
            gaussiankeyboard_updateMotionSpace_ = (GAUSSIANKEYBOARD_UPDATEMOTIONSPACE_TYPE)dlsym(
                g_VKeyboardHandle, "GaussianKeyboardUpdateMotionSpace");
            gaussiankeyboard_setVKeyboardArea_ = (GAUSSIANKEYBOARD_SETVKEYBOARDAREA_TYPE)dlsym(
                g_VKeyboardHandle, "GaussianKeyboardSetVKeyboardArea");
            bayesianengine_mapTouchToButton_ = (BAYESIANENGINE_MAPTOUCHTOBUTTON_TYPE)dlsym(
                g_VKeyboardHandle, "BayesianEngineMapTouchToButton");
            statemachineMessageQueue_getMessage_ = (STATEMACINEMESSAGQUEUE_GETMESSAGE_TYPE)dlsym(
                g_VKeyboardHandle, "StateMachineMessageQueueGetMessage");
            gaussiankeyboard_isInsideVKeyboardArea_ = (GAUSSIANKEYBOARD_ISINSIDEVKEYBOARDAREA_TYPE)dlsym(
                g_VKeyboardHandle, "GaussianKeyboardIsInsideVKeyboardArea");
            gaussiankeyboard_isVKeyboardVisible_ = (GAUSSIANKEYBOARD_ISVKEYBOARDVISIBLE_TYPE)dlsym(
                g_VKeyboardHandle, "GaussianKeyboardIsVKeyboardVisible");
            algorithm_isKeyDownInKeyboard_ = (ALGORITHM_ISKEYDOWNINKEYBOARD_TYPE)dlsym(
                g_VKeyboardHandle, "AlgorithmIsKeyDownInKeyboard");
            algorithm_initialize_ = (ALGORITHM_INITIALIZE_TYPE)dlsym(
                g_VKeyboardHandle, "AlgorithmInitialize");
            trackPadEngine_isInsideVTrackPadArea_ = (TRACKPADENGINE_ISINSIDEVTRACKPADAREA_TYPE)dlsym(
                g_VKeyboardHandle, "TrackPadEngineIsInsideVTrackPadArea");
            trackPadEngine_isVTrackPadVisible_ = (TRACKPADENGINE_ISVTRACKPADVISIBLE_TYPE)dlsym(
                g_VKeyboardHandle, "TrackPadEngineIsVTrackPadVisible");
            trackPadEngine_interpretPointerEvent_ = (TRACKPADENGINE_INTERPRETPOINTEREVENT_TYPE)dlsym(
                g_VKeyboardHandle, "TrackPadEngineInterpretPointerEvent");
            trackPadEngine_setVTrackPadArea_ = (TRACKPADENGINE_SETVTRACKPADAREA_TYPE)dlsym(
                g_VKeyboardHandle, "TrackPadEngineSetVTrackPadArea");
            trackPadEngine_setScreenArea_ = (TRACKPADENGINE_SETSCREENAREA_TYPE)dlsym(
                g_VKeyboardHandle, "TrackPadEngineSetScreenArea");
            trackPadEngine_getAllTouchMessage_ = (TRACKPADENGINE_GETALLTOUCHMESSAGE_TYPE)dlsym(
                g_VKeyboardHandle, "TrackPadEngineGetAllTouchMessage");
            trackPadEngine_clearTouchMessage_ = (TRACKPADENGINE_CLEARTOUCHMESSAGE_TYPE)dlsym(
                g_VKeyboardHandle, "TrackPadEngineClearTouchMessage");
            trackPadEngine_getAllKeyMessage_ = (TRACKPADENGINE_GETALLKEYMESSAGE_TYPE)dlsym(
                g_VKeyboardHandle, "TrackPadEngineGetAllKeyMessage");
            trackPadEngine_clearKeyMessage_ = (TRACKPADENGINE_CLEARKEYMESSAGE_TYPE)dlsym(
                g_VKeyboardHandle, "TrackPadEngineClearKeyMessage");
        }
    }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    IPointerDrawingManager::GetInstance()->InitPointerObserver();
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    InitPreferences();
    TimerMgr->AddTimer(WATCHDOG_INTERVAL_TIME, -1, [this]() {
        MMI_HILOGI("Set thread status flag to true");
        threadStatusFlag_ = true;
    });
    [[ maybe_unused ]] auto taskFunc = [this]() {
        if (threadStatusFlag_) {
            MMI_HILOGI("Set thread status flag to false");
            threadStatusFlag_ = false;
        } else {
            MMI_HILOGI("Mmi-server Timeout");
        }
    };
    MMI_HILOGI("Run periodical task success");
    InitPrintClientInfo();
}

void MMIService::OnStop()
{
    CHK_PID_AND_TID();
    UdsStop();
    libinputAdapter_.Stop();
    state_ = ServiceRunningState::STATE_NOT_START;
#ifdef OHOS_RSS_CLIENT
    MMI_HILOGI("Remove system ability listener start");
    RemoveSystemAbilityListener(RES_SCHED_SYS_ABILITY_ID);
    MMI_HILOGI("Remove system ability listener success");
#endif // OHOS_RSS_CLIENT
#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    RemoveSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    RemoveSystemAbilityListener(APP_MGR_SERVICE_ID);
    RemoveSystemAbilityListener(RENDER_SERVICE);
    RemoveAppDebugListener();
    RemoveSystemAbilityListener(DISPLAY_MANAGER_SERVICE_SA_ID);
#ifdef OHOS_BUILD_ENABLE_ANCO
    StopAncoUds();
#endif // OHOS_BUILD_ENABLE_ANCO
}

void MMIService::AddAppDebugListener()
{
    CALL_DEBUG_ENTER;
    appDebugListener_ = AppDebugListener::GetInstance();
    auto errCode =
        AAFwk::AbilityManagerClient::GetInstance()->RegisterAppDebugListener(appDebugListener_);
    if (errCode != RET_OK) {
        MMI_HILOGE("Call RegisterAppDebugListener failed, errCode:%{public}d", errCode);
    }
}

void MMIService::RemoveAppDebugListener()
{
    CALL_DEBUG_ENTER;
    CHKPV(appDebugListener_);
    auto errCode =
        AAFwk::AbilityManagerClient::GetInstance()->UnregisterAppDebugListener(appDebugListener_);
    if (errCode != RET_OK) {
        MMI_HILOGE("Call UnregisterAppDebugListener failed, errCode:%{public}d", errCode);
    }
}

int32_t MMIService::AllocSocketFd(const std::string &programName, const int32_t moduleType, int32_t &toReturnClientFd,
    int32_t &tokenType)
{
    toReturnClientFd = IMultimodalInputConnect::INVALID_SOCKET_FD;
    int32_t serverFd = IMultimodalInputConnect::INVALID_SOCKET_FD;
    int32_t pid = GetCallingPid();
    int32_t uid = GetCallingUid();
    MMI_HILOGI("Enter, programName:%{public}s, moduleType:%{public}d, pid:%{public}d",
        programName.c_str(), moduleType, pid);
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &programName, moduleType, uid, pid, &serverFd, &toReturnClientFd, &tokenType] {
            return this->AddSocketPairInfo(programName, moduleType, uid, pid, serverFd, toReturnClientFd, tokenType);
        }
        );
    DfxHisysevent::ClientConnectData data = {
        .pid = pid,
        .uid = uid,
        .moduleType = moduleType,
        .programName = programName,
        .serverFd = serverFd
    };
    if (ret != RET_OK) {
        MMI_HILOGE("Call AddSocketPairInfo failed, return:%{public}d", ret);
        DfxHisysevent::OnClientConnect(data, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
        return ret;
    }
    MMI_HILOGIK("Leave, programName:%{public}s, moduleType:%{public}d, alloc success", programName.c_str(),
                moduleType);
    DfxHisysevent::OnClientConnect(data, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
    return RET_OK;
}

int32_t MMIService::AddInputEventFilter(sptr<IEventFilter> filter, int32_t filterId, int32_t priority,
    uint32_t deviceTags)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH) || defined(OHOS_BUILD_ENABLE_KEYBOARD)
    CHKPR(filter, ERROR_NULL_POINTER);
    int32_t clientPid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, filter, filterId, priority, deviceTags, clientPid] {
            return sMsgHandler_.AddInputEventFilter(filter, filterId, priority, deviceTags, clientPid);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Add event filter failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH || OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::RemoveInputEventFilter(int32_t filterId)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH) || defined(OHOS_BUILD_ENABLE_KEYBOARD)
    int32_t clientPid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, filterId, clientPid] {
            return sMsgHandler_.RemoveInputEventFilter(filterId, clientPid);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Remove event filter failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH || OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

void MMIService::OnConnected(SessionPtr s)
{
    CHKPV(s);
    MMI_HILOGI("fd:%{public}d", s->GetFd());
#ifdef OHOS_BUILD_ENABLE_ANCO
    if (s->GetProgramName() != SHELL_ASSISTANT) {
        return;
    }
    auto appMgrClient = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance();
    if (appMgrClient == nullptr) {
        return;
    }
    int32_t userid = WIN_MGR->GetCurrentUserId();
    if (userid < 0) {
        userid = DEFAULT_USER_ID;
    }
    std::vector<AppExecFwk::RunningProcessInfo> info;
    appMgrClient->GetProcessRunningInfosByUserId(info, userid);
    for (auto &item : info) {
        if (item.bundleNames.empty()) {
            continue;
        }
        if (SHELL_ASSISTANT == item.bundleNames[0].c_str()) {
            MMI_HILOGW("Record client processes pid %{public}d", item.pid_);
            shellAssitentPid_ = item.pid_;
        }
    }
#endif // OHOS_BUILD_ENABLE_ANCO
}

void MMIService::OnDisconnected(SessionPtr s)
{
    CHKPV(s);
    MMI_HILOGW("Enter, session desc:%{public}s, fd:%{public}d", s->GetDescript().c_str(), s->GetFd());
    auto ret = RemoveInputEventFilter(-1);
    if (ret != RET_OK) {
        MMI_HILOGF("Remove all filter failed, ret:%{public}d", ret);
    }
#ifdef OHOS_BUILD_ENABLE_ANCO
    if (s->GetProgramName() == SHELL_ASSISTANT && shellAssitentPid_ == s->GetPid()) {
        MMI_HILOGW("Clean all shell windows pid: %{public}d", s->GetPid());
        shellAssitentPid_ = -1;
        IInputWindowsManager::GetInstance()->CleanShellWindowIds();
    }
#endif // OHOS_BUILD_ENABLE_ANCO
#ifdef OHOS_BUILD_ENABLE_POINTER
    IPointerDrawingManager::GetInstance()->DeletePointerVisible(s->GetPid());
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t MMIService::SetMouseScrollRows(int32_t rows)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [rows] {
            return ::OHOS::DelayedSingleton<MouseEventNormalize>::GetInstance()->SetMouseScrollRows(rows);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set the number of mouse scrolling rows failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetCustomCursor(int32_t pid, int32_t windowId, int32_t focusX, int32_t focusY, void* pixelMap)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t ret = CheckPidPermission(pid);
    if (ret != RET_OK) {
        MMI_HILOGE("Check pid permission failed");
        return ret;
    }
    ret = delegateTasks_.PostSyncTask(std::bind(
        [pixelMap, pid, windowId, focusX, focusY] {
            return IPointerDrawingManager::GetInstance()->SetCustomCursor(pixelMap, pid, windowId, focusX, focusY);
        }
        ));
    if (ret != RET_OK) {
        MMI_HILOGE("Set the custom cursor failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetMouseIcon(int32_t windowId, void* pixelMap)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t pid = GetCallingPid();
    int32_t ret = CheckPidPermission(pid);
    if (ret != RET_OK) {
        MMI_HILOGE("Check pid permission failed");
        return ret;
    }
    ret = delegateTasks_.PostSyncTask(std::bind(
        [pid, windowId, pixelMap] {
            return IPointerDrawingManager::GetInstance()->SetMouseIcon(pid, windowId, pixelMap);
        }
        ));
    if (ret != RET_OK) {
        MMI_HILOGE("Set the mouse icon failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetMouseHotSpot(int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t ret = CheckPidPermission(pid);
    if (ret != RET_OK) {
        MMI_HILOGE("Check pid permission failed");
        return ret;
    }
    ret = delegateTasks_.PostSyncTask(
        [pid, windowId, hotSpotX, hotSpotY] {
            return IPointerDrawingManager::GetInstance()->SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set the mouse hot spot failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetNapStatus(int32_t pid, int32_t uid, std::string bundleName, int32_t napStatus)
{
    CALL_INFO_TRACE;
    int32_t ret = CheckPidPermission(pid);
    if (ret != RET_OK) {
        MMI_HILOGE("Check pid permission failed");
        return ret;
    }
    NapProcess::GetInstance()->SetNapStatus(pid, uid, bundleName, napStatus);
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_POINTER
int32_t MMIService::ReadMouseScrollRows(int32_t &rows)
{
    rows = MouseEventHdr->GetMouseScrollRows();
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER

int32_t MMIService::GetMouseScrollRows(int32_t &rows)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &rows] {
            return this->ReadMouseScrollRows(rows);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get the number of mouse scrolling rows failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetPointerSize(int32_t size)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret = delegateTasks_.PostSyncTask(
        [size] {
            return IPointerDrawingManager::GetInstance()->SetPointerSize(size);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer size failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
int32_t MMIService::ReadPointerSize(int32_t &size)
{
    size = IPointerDrawingManager::GetInstance()->GetPointerSize();
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

int32_t MMIService::GetPointerSize(int32_t &size)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &size] {
            return this->ReadPointerSize(size);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer size failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}

int32_t MMIService::SetMousePrimaryButton(int32_t primaryButton)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [primaryButton] {
            return ::OHOS::DelayedSingleton<MouseEventNormalize>::GetInstance()->SetMousePrimaryButton(primaryButton);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set mouse primary button failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_POINTER
int32_t MMIService::ReadMousePrimaryButton(int32_t &primaryButton)
{
    primaryButton = MouseEventHdr->GetMousePrimaryButton();
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER

int32_t MMIService::GetMousePrimaryButton(int32_t &primaryButton)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &primaryButton] {
            return this->ReadMousePrimaryButton(primaryButton);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get mouse primary button failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetPointerVisible(bool visible, int32_t priority)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    bool isHap = false;
    if (tokenType == OHOS::Security::AccessToken::TOKEN_HAP) {
        isHap = true;
    }
    int32_t clientPid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [clientPid, visible, priority, isHap] {
            return IPointerDrawingManager::GetInstance()->SetPointerVisible(clientPid, visible, priority, isHap);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer visible failed, return:%{public}d", ret);
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
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &visible] {
            return this->CheckPointerVisible(visible);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Is pointer visible failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}

int32_t MMIService::MarkProcessed(int32_t eventType, int32_t eventId)
{
    CALL_DEBUG_ENTER;
    CHKPR(ANRMgr, RET_ERR);
    int32_t clientPid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [clientPid, eventType, eventId] {
            return ::OHOS::DelayedSingleton<ANRManager>::GetInstance()->MarkProcessed(clientPid, eventType, eventId);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGD("Mark event processed failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::SetPointerColor(int32_t color)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret = delegateTasks_.PostSyncTask(
        [color] {
            return IPointerDrawingManager::GetInstance()->SetPointerColor(color);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer color failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
int32_t MMIService::ReadPointerColor(int32_t &color)
{
    color = IPointerDrawingManager::GetInstance()->GetPointerColor();
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

int32_t MMIService::GetPointerColor(int32_t &color)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &color] {
            return this->ReadPointerColor(color);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer color failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}

int32_t MMIService::SetPointerSpeed(int32_t speed)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [speed] {
            return ::OHOS::DelayedSingleton<MouseEventNormalize>::GetInstance()->SetPointerSpeed(speed);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer speed failed, return:%{public}d", ret);
        return ret;
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
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &speed] {
            return this->ReadPointerSpeed(speed);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer speed failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::NotifyNapOnline()
{
    CALL_DEBUG_ENTER;
    NapProcess::GetInstance()->NotifyNapOnline();
    return RET_OK;
}

int32_t MMIService::RemoveInputEventObserver()
{
    CALL_DEBUG_ENTER;
    NapProcess::GetInstance()->RemoveInputEventObserver();
    return RET_OK;
}

int32_t MMIService::SetPointerStyle(int32_t windowId, PointerStyle pointerStyle, bool isUiExtension)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t clientPid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [clientPid, windowId, pointerStyle, isUiExtension] {
            return IPointerDrawingManager::GetInstance()->SetPointerStyle(
                clientPid, windowId, pointerStyle, isUiExtension);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer style failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::ClearWindowPointerStyle(int32_t pid, int32_t windowId)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = CheckPidPermission(pid);
    if (ret != RET_OK) {
        MMI_HILOGE("Check pid permission failed");
        return ret;
    }
    ret = delegateTasks_.PostSyncTask(
        [pid, windowId] {
            return IPointerDrawingManager::GetInstance()->ClearWindowPointerStyle(pid, windowId);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer style failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::GetPointerStyle(int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t clientPid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [clientPid, windowId, &pointerStyle, isUiExtension] {
            return IPointerDrawingManager::GetInstance()->GetPointerStyle(
                clientPid, windowId, pointerStyle, isUiExtension);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer style failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetHoverScrollState(bool state)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [state] {
            return ::OHOS::MMI::IInputWindowsManager::GetInstance()->SetHoverScrollState(state);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set mouse hover scroll state failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_POINTER
int32_t MMIService::ReadHoverScrollState(bool &state)
{
    state = WIN_MGR->GetHoverScrollState();
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER

int32_t MMIService::GetHoverScrollState(bool &state)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &state] {
            return this->ReadHoverScrollState(state);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get mouse hover scroll state, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::OnSupportKeys(int32_t deviceId, std::vector<int32_t> &keys, std::vector<bool> &keystroke)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INPUT_DEV_MGR->SupportKeys(deviceId, keys, keystroke);
    if (ret != RET_OK) {
        MMI_HILOGE("Device id not support");
        return ret;
    }
    if (keystroke.size() > MAX_SUPPORT_KEY) {
        MMI_HILOGE("Device exceeds the max range");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MMIService::SupportKeys(int32_t deviceId, std::vector<int32_t> &keys, std::vector<bool> &keystroke)
{
    CALL_DEBUG_ENTER;
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, deviceId, &keys, &keystroke] {
            return this->OnSupportKeys(deviceId, keys, keystroke);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Support keys info process failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::OnGetDeviceIds(std::vector<int32_t> &ids)
{
    CALL_DEBUG_ENTER;
    ids = INPUT_DEV_MGR->GetInputDeviceIds();
    return RET_OK;
}

int32_t MMIService::GetDeviceIds(std::vector<int32_t> &ids)
{
    CALL_DEBUG_ENTER;
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &ids] {
            return this->OnGetDeviceIds(ids);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get deviceids failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::OnGetDevice(int32_t deviceId, std::shared_ptr<InputDevice> &inputDevice)
{
    CALL_DEBUG_ENTER;
    if (INPUT_DEV_MGR->GetInputDevice(deviceId) == nullptr) {
        MMI_HILOGE("Input device not found");
        return COMMON_PARAMETER_ERROR;
    }
    inputDevice = INPUT_DEV_MGR->GetInputDevice(deviceId);
    return RET_OK;
}

int32_t MMIService::GetDevice(int32_t deviceId, std::shared_ptr<InputDevice> &inputDevice)
{
    CALL_DEBUG_ENTER;
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, deviceId, &inputDevice] {
            return this->OnGetDevice(deviceId, inputDevice);
        }
        );
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
    INPUT_DEV_MGR->AddDevListener(sess);
    return RET_OK;
}

int32_t MMIService::RegisterDevListener()
{
    CALL_DEBUG_ENTER;
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, pid] {
            return this->OnRegisterDevListener(pid);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Register device listener failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::OnUnregisterDevListener(int32_t pid)
{
    auto sess = GetSession(GetClientFd(pid));
    INPUT_DEV_MGR->RemoveDevListener(sess);
    return RET_OK;
}

int32_t MMIService::UnregisterDevListener()
{
    CALL_DEBUG_ENTER;
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, pid] {
            return this->OnUnregisterDevListener(pid);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Unregister device listener failed failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::OnGetKeyboardType(int32_t deviceId, int32_t &keyboardType)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INPUT_DEV_MGR->GetKeyboardType(deviceId, keyboardType);
    if (ret != RET_OK) {
        MMI_HILOGD("GetKeyboardType call failed");
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::GetKeyboardType(int32_t deviceId, int32_t &keyboardType)
{
    CALL_DEBUG_ENTER;
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, deviceId, &keyboardType] {
            return this->OnGetKeyboardType(deviceId, keyboardType);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGD("Get keyboard type failed, ret:%{public}d", ret);
        return ret;
    }
    return ret;
}

int32_t MMIService::SetKeyboardRepeatDelay(int32_t delay)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = delegateTasks_.PostSyncTask(
        [delay] {
            return ::OHOS::DelayedSingleton<KeyAutoRepeat>::GetInstance()->SetKeyboardRepeatDelay(delay);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set keyboard repeat delay failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::SetKeyboardRepeatRate(int32_t rate)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = delegateTasks_.PostSyncTask(
        [rate] {
            return ::OHOS::DelayedSingleton<KeyAutoRepeat>::GetInstance()->SetKeyboardRepeatRate(rate);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set keyboard repeat rate failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::GetKeyboardRepeatDelay(int32_t &delay)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = delegateTasks_.PostSyncTask(
        [&delay] {
            return ::OHOS::DelayedSingleton<KeyAutoRepeat>::GetInstance()->GetKeyboardRepeatDelay(delay);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get keyboard repeat delay failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::GetKeyboardRepeatRate(int32_t &rate)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = delegateTasks_.PostSyncTask(
        [&rate] {
            return ::OHOS::DelayedSingleton<KeyAutoRepeat>::GetInstance()->GetKeyboardRepeatRate(rate);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get keyboard repeat rate failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
int32_t MMIService::CheckAddInput(int32_t pid, InputHandlerType handlerType, HandleEventType eventType,
    int32_t priority, uint32_t deviceTags)
{
    auto sess = GetSessionByPid(pid);
    CHKPR(sess, ERROR_NULL_POINTER);
    return sMsgHandler_.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags);
}

#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR

int32_t MMIService::AddInputHandler(InputHandlerType handlerType, HandleEventType eventType, int32_t priority,
    uint32_t deviceTags, std::vector<int32_t> actionsType)
{
    CALL_INFO_TRACE;
    bool isRegisterCaptureCb = false;
#if defined(OHOS_BUILD_ENABLE_MONITOR) && defined(PLAYER_FRAMEWORK_EXISTS)
    if (!PER_HELPER->VerifySystemApp() && handlerType == InputHandlerType::MONITOR) {
        isRegisterCaptureCb = true;
    }
#endif // OHOS_BUILD_ENABLE_MONITOR && PLAYER_FRAMEWORK_EXISTS
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, pid, handlerType, eventType, priority, deviceTags, isRegisterCaptureCb] {
#if defined(OHOS_BUILD_ENABLE_MONITOR) && defined(PLAYER_FRAMEWORK_EXISTS)
            if (isRegisterCaptureCb) {
                RegisterScreenCaptureCallback();
            }
#endif // OHOS_BUILD_ENABLE_MONITOR && PLAYER_FRAMEWORK_EXISTS
            return this->CheckAddInput(pid, handlerType, eventType, priority, deviceTags);
        });
    if (ret != RET_OK) {
        MMI_HILOGE("Add input handler failed, ret:%{public}d", ret);
        return ret;
    }
    ret = ObserverAddInputHandler(pid);
    if (ret != RET_OK) {
        MMI_HILOGE("AddInputHandler info to observer failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}

#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
int32_t MMIService::CheckRemoveInput(int32_t pid, InputHandlerType handlerType, HandleEventType eventType,
    int32_t priority, uint32_t deviceTags)
{
    auto sess = GetSessionByPid(pid);
    CHKPR(sess, ERROR_NULL_POINTER);
    return sMsgHandler_.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags);
}

int32_t MMIService::ObserverAddInputHandler(int32_t pid)
{
    if (NapProcess::GetInstance()->GetNapClientPid() != REMOVE_OBSERVER) {
        OHOS::MMI::NapProcess::NapStatusData napData;
        napData.pid = GetCallingPid();
        napData.uid = GetCallingUid();
        auto sess = GetSessionByPid(pid);
        CHKPR(sess, ERROR_NULL_POINTER);
        napData.bundleName = sess->GetProgramName();
        int32_t syncState = SUBSCRIBED;
        MMI_HILOGD("AddInputHandler info to observer : pid:%{public}d, uid:%d, bundleName:%{public}s",
            napData.pid, napData.uid, napData.bundleName.c_str());
        NapProcess::GetInstance()->AddMmiSubscribedEventData(napData, syncState);
        if (NapProcess::GetInstance()->GetNapClientPid() != UNOBSERVED) {
            NapProcess::GetInstance()->NotifyBundleName(napData, syncState);
        }
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR

int32_t MMIService::RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType, int32_t priority,
    uint32_t deviceTags, std::vector<int32_t> actionsType)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, pid, handlerType, eventType, priority, deviceTags] {
            return this->CheckRemoveInput(pid, handlerType, eventType, priority, deviceTags);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Remove input handler failed, ret:%{public}d", ret);
        return ret;
    }
    if (NapProcess::GetInstance()->GetNapClientPid() != REMOVE_OBSERVER) {
        OHOS::MMI::NapProcess::NapStatusData napData;
        napData.pid = GetCallingPid();
        napData.uid = GetCallingUid();
        auto sess = GetSessionByPid(pid);
        CHKPR(sess, ERROR_NULL_POINTER);
        napData.bundleName = sess->GetProgramName();
        int32_t syncState = UNSUBSCRIBED;
        MMI_HILOGD("RemoveInputHandler info to observer : pid:%{public}d, uid:%{public}d, bundleName:%{public}s",
            napData.pid, napData.uid, napData.bundleName.c_str());
        NapProcess::GetInstance()->AddMmiSubscribedEventData(napData, syncState);
        if (NapProcess::GetInstance()->GetNapClientPid() != UNOBSERVED) {
            NapProcess::GetInstance()->NotifyBundleName(napData, syncState);
        }
    }
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}

int32_t MMIService::AddGestureMonitor(InputHandlerType handlerType,
    HandleEventType eventType, TouchGestureType gestureType, int32_t fingers)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, pid, handlerType, eventType, gestureType, fingers]() -> int32_t {
            if (((eventType & HANDLE_EVENT_TYPE_TOUCH_GESTURE) != HANDLE_EVENT_TYPE_TOUCH_GESTURE)) {
                MMI_HILOGE("Illegal type:%{public}d", eventType);
                return RET_ERR;
            }
            if (!GestureMonitorHandler::CheckMonitorValid(gestureType, fingers)) {
                MMI_HILOGE("Wrong number of fingers:%{public}d", fingers);
                return RET_ERR;
            }
            if (touchGestureAdapter_ == nullptr) {
                touchGestureAdapter_ = TouchGestureAdapter::GetGestureFactory();
            }
            if (touchGestureAdapter_ != nullptr) {
                touchGestureAdapter_->SetGestureCondition(true, gestureType, fingers);
            }
            if (delegateInterface_ != nullptr && !delegateInterface_->HasHandler("touchGesture")) {
                auto fun = [this](std::shared_ptr<PointerEvent> event) -> int32_t {
                    CHKPR(touchGestureAdapter_, ERROR_NULL_POINTER);
                    touchGestureAdapter_->process(event);
                    return RET_OK;
                };
                int32_t ret = delegateInterface_->AddHandler(InputHandlerType::MONITOR,
                    {"touchGesture", HANDLE_EVENT_TYPE_POINTER, HandlerMode::SYNC, 0, 0, fun});
                if (ret != RET_OK) {
                    MMI_HILOGE("Failed to add gesture recognizer, ret:%{public}d", ret);
                    return ret;
                }
            }
            auto sess = GetSessionByPid(pid);
            CHKPR(sess, ERROR_NULL_POINTER);
            return sMsgHandler_.OnAddGestureMonitor(sess, handlerType, eventType, gestureType, fingers);
        });
    if (ret != RET_OK) {
        MMI_HILOGE("Add gesture handler failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}

int32_t MMIService::RemoveGestureMonitor(InputHandlerType handlerType,
    HandleEventType eventType, TouchGestureType gestureType, int32_t fingers)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, pid, handlerType, eventType, gestureType, fingers]() -> int32_t {
            auto sess = GetSessionByPid(pid);
            CHKPR(sess, ERROR_NULL_POINTER);
            int32_t ret = sMsgHandler_.OnRemoveGestureMonitor(sess, handlerType, eventType, gestureType, fingers);
            if (ret != RET_OK) {
                MMI_HILOGE("Failed to remove gesture recognizer, ret:%{public}d", ret);
                return ret;
            }
            auto monitorHandler = InputHandler->GetMonitorHandler();
            if (monitorHandler && !monitorHandler->CheckHasInputHandler(HANDLE_EVENT_TYPE_TOUCH_GESTURE)) {
                if (delegateInterface_ && delegateInterface_->HasHandler("touchGesture")) {
                    delegateInterface_->RemoveHandler(InputHandlerType::MONITOR, "touchGesture");
                }
            }
            if (touchGestureAdapter_) {
                touchGestureAdapter_->SetGestureCondition(false, gestureType, fingers);
            }
            return RET_OK;
        });
    if (ret != RET_OK) {
        MMI_HILOGE("Remove gesture handler failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
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
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_MONITOR
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, pid, eventId] {
            return this->CheckMarkConsumed(pid, eventId);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Mark event consumed failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}

int32_t MMIService::MoveMouseEvent(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret =
        delegateTasks_.PostSyncTask(
            [this, offsetX, offsetY] {
                return sMsgHandler_.OnMoveMouse(offsetX, offsetY);
            }
            );
    if (ret != RET_OK) {
        MMI_HILOGE("The movemouse event processed failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}

int32_t MMIService::InjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent, bool isNativeInject)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret;
    int32_t pid = GetCallingPid();
#ifdef OHOS_BUILD_ENABLE_ANCO
    ret = InjectKeyEventExt(keyEvent, pid, isNativeInject);
#else
    ret = delegateTasks_.PostSyncTask(
        [this, keyEvent, pid, isNativeInject] {
            return this->CheckInjectKeyEvent(keyEvent, pid, isNativeInject);
        }
        );
#endif // OHOS_BUILD_ENABLE_ANCO
    if (ret != RET_OK) {
        MMI_HILOGE("Inject key event failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::CheckInjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent, int32_t pid, bool isNativeInject)
{
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    LogTracer lt(keyEvent->GetId(), keyEvent->GetEventType(), keyEvent->GetKeyAction());
    return sMsgHandler_.OnInjectKeyEvent(keyEvent, pid, isNativeInject);
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t MMIService::OnGetKeyState(std::vector<int32_t> &pressedKeys, std::map<int32_t, int32_t> &specialKeysState)
{
    auto keyEvent = KeyEventHdr->GetKeyEvent();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    pressedKeys = keyEvent->GetPressedKeys();
    for (auto iter = pressedKeys.begin(); iter != pressedKeys.end();) {
        if (g_keyCodeValueSet.find(*iter) == g_keyCodeValueSet.end()) {
            iter = pressedKeys.erase(iter);
            continue;
        }
        ++iter;
    }
    specialKeysState[KeyEvent::KEYCODE_CAPS_LOCK] =
        static_cast<int32_t>(keyEvent->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY));
    specialKeysState[KeyEvent::KEYCODE_SCROLL_LOCK] =
        static_cast<int32_t>(keyEvent->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY));
    specialKeysState[KeyEvent::KEYCODE_NUM_LOCK] =
        static_cast<int32_t>(keyEvent->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY));
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

int32_t MMIService::CheckInjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent,
    int32_t pid, bool isNativeInject, bool isShell)
{
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    return sMsgHandler_.OnInjectPointerEvent(pointerEvent, pid, isNativeInject, isShell);
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
}

int32_t MMIService::InjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, bool isNativeInject)
{
    CALL_DEBUG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t ret;
    int32_t pid = GetCallingPid();
    bool isShell = PER_HELPER->RequestFromShell();
#ifdef OHOS_BUILD_ENABLE_ANCO
    ret = InjectPointerEventExt(pointerEvent, pid, isNativeInject, isShell);
#else
    ret = delegateTasks_.PostSyncTask(
        [this, pointerEvent, pid, isNativeInject, isShell] {
            return this->CheckInjectPointerEvent(pointerEvent, pid, isNativeInject, isShell);
        }
        );
#endif // OHOS_BUILD_ENABLE_ANCO
    if (ret != RET_OK) {
        MMI_HILOGE("Inject pointer event failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    return RET_OK;
}

#ifdef OHOS_RSS_CLIENT
void MMIService::OnAddResSchedSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    int sleepSeconds = 1;
    sleep(sleepSeconds);
    uint64_t tid = tid_.load();
    int32_t userInteraction = 2;
    std::unordered_map<std::string, std::string> payload;
    payload["uid"] = std::to_string(getuid());
    payload["pid"] = std::to_string(getpid());
    payload["extType"] = "10002";
    payload["tid"] = std::to_string(tid);
    payload["isSa"] = "1";
    payload["cgroupPrio"] = "1";
    payload["threadName"] = "mmi_service";
    ResourceSchedule::ResSchedClient::GetInstance().ReportData(
        ResourceSchedule::ResType::RES_TYPE_KEY_PERF_SCENE, userInteraction, payload);
}
#endif // OHOS_RSS_CLIENT

void MMIService::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    CALL_INFO_TRACE;
    MMI_HILOGI("systemAbilityId is %{public}d", systemAbilityId);
#ifdef OHOS_RSS_CLIENT
    if (systemAbilityId == RES_SCHED_SYS_ABILITY_ID) {
        OnAddResSchedSystemAbility(systemAbilityId, deviceId);
    }
#endif // OHOS_RSS_CLIENT
#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    if (systemAbilityId == COMMON_EVENT_SERVICE_ID) {
        isCesStart_ = true;
    }
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    if (systemAbilityId == APP_MGR_SERVICE_ID) {
        APP_OBSERVER_MGR->InitAppStateObserver();
    }
    if (systemAbilityId == COMMON_EVENT_SERVICE_ID) {
        DEVICE_MONITOR->InitCommonEventSubscriber();
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER)
        DISPLAY_MONITOR->InitCommonEventSubscriber();
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    }
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    if (systemAbilityId == RENDER_SERVICE) {
        IPointerDrawingManager::GetInstance()->InitPointerCallback();
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    if (systemAbilityId == DISPLAY_MANAGER_SERVICE_SA_ID) {
        WIN_MGR->SetFoldState();
    }
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    if (systemAbilityId == DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID) {
        if (SettingDataShare::GetInstance(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID).CheckIfSettingsDataReady()) {
            IPointerDrawingManager::GetInstance()->InitPointerObserver();
            auto keyHandler = InputHandler->GetKeyCommandHandler();
            if (keyHandler != nullptr) {
                keyHandler->InitKeyObserver();
            }
        }
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
}

#if defined(OHOS_BUILD_ENABLE_MONITOR) && defined(PLAYER_FRAMEWORK_EXISTS)
void MMIService::ScreenCaptureCallback(int32_t pid, bool isStart)
{
    auto service = MMIService::GetInstance();
    CHKPV(service);
    int32_t ret = service->delegateTasks_.PostSyncTask(
        [pid, isStart] {
            auto monitorHandler = InputHandler->GetMonitorHandler();
            CHKPR(monitorHandler, RET_ERR);
            monitorHandler->ProcessScreenCapture(pid, isStart);
            return RET_OK;
        });
}

void MMIService::RegisterScreenCaptureCallback()
{
    if (hasRegisterListener_) {
        return;
    }
    InputScreenCaptureAgent::GetInstance().RegisterListener(ScreenCaptureCallback);
    hasRegisterListener_ = true;
}
#endif // OHOS_BUILD_ENABLE_MONITOR && PLAYER_FRAMEWORK_EXISTS

int32_t MMIService::SubscribeKeyEvent(int32_t subscribeId, const std::shared_ptr<KeyOption> option)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, pid, subscribeId, option] {
            return sMsgHandler_.OnSubscribeKeyEvent(this, pid, subscribeId, option);
        });
    if (ret != RET_OK) {
        MMI_HILOGE("The subscribe key event processed failed, ret:%{public}d", ret);
        return ret;
    }
    if (NapProcess::GetInstance()->GetNapClientPid() != REMOVE_OBSERVER) {
        OHOS::MMI::NapProcess::NapStatusData napData;
        napData.pid = GetCallingPid();
        napData.uid = GetCallingUid();
        auto sess = GetSessionByPid(pid);
        CHKPR(sess, ERROR_NULL_POINTER);
        napData.bundleName = sess->GetProgramName();
        int32_t syncState = SUBSCRIBED;
        MMI_HILOGD("SubscribeKeyEvent info to observer : pid:%{public}d, uid:%{public}d, bundleName:%{public}s",
            napData.pid, napData.uid, napData.bundleName.c_str());
        NapProcess::GetInstance()->AddMmiSubscribedEventData(napData, syncState);
        if (NapProcess::GetInstance()->GetNapClientPid() != UNOBSERVED) {
            NapProcess::GetInstance()->NotifyBundleName(napData, syncState);
        }
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
        [this, pid, subscribeId] {
            return sMsgHandler_.OnUnsubscribeKeyEvent(this, pid, subscribeId);
        });
    if (ret != RET_OK) {
        MMI_HILOGE("The unsubscribe key event processed failed, ret:%{public}d", ret);
        return ret;
    }
    if (NapProcess::GetInstance()->GetNapClientPid() != REMOVE_OBSERVER) {
        OHOS::MMI::NapProcess::NapStatusData napData;
        napData.pid = GetCallingPid();
        napData.uid = GetCallingUid();
        auto sess = GetSessionByPid(pid);
        CHKPR(sess, ERROR_NULL_POINTER);
        napData.bundleName = sess->GetProgramName();
        int32_t syncState = UNSUBSCRIBED;
        MMI_HILOGD("UnsubscribeKeyEvent info to observer : pid:%{public}d, uid:%{public}d, bundleName:%{public}s",
            napData.pid, napData.uid, napData.bundleName.c_str());
        NapProcess::GetInstance()->AddMmiSubscribedEventData(napData, syncState);
        if (NapProcess::GetInstance()->GetNapClientPid() != UNOBSERVED) {
            NapProcess::GetInstance()->NotifyBundleName(napData, syncState);
        }
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::SubscribeHotkey(int32_t subscribeId, const std::shared_ptr<KeyOption> option)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, pid, subscribeId, option] {
            return sMsgHandler_.OnSubscribeHotkey(this, pid, subscribeId, option);
        });
    if (ret != RET_OK) {
        MMI_HILOGE("ServerMsgHandler::OnSubscribeHotkey fail, error:%{public}d", ret);
        return ret;
    }
    if (NapProcess::GetInstance()->GetNapClientPid() != REMOVE_OBSERVER) {
        OHOS::MMI::NapProcess::NapStatusData napData;
        napData.pid = GetCallingPid();
        napData.uid = GetCallingUid();
        auto sess = GetSessionByPid(pid);
        CHKPR(sess, ERROR_NULL_POINTER);
        napData.bundleName = sess->GetProgramName();
        int32_t syncState = SUBSCRIBED;
        MMI_HILOGD("SubscribeHotkey info to observer : pid:%{public}d, bundleName:%{public}s",
            napData.pid, napData.bundleName.c_str());
        NapProcess::GetInstance()->AddMmiSubscribedEventData(napData, syncState);
        if (NapProcess::GetInstance()->GetNapClientPid() != UNOBSERVED) {
            NapProcess::GetInstance()->NotifyBundleName(napData, syncState);
        }
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::UnsubscribeHotkey(int32_t subscribeId)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, pid, subscribeId] {
            return sMsgHandler_.OnUnsubscribeHotkey(this, pid, subscribeId);
        });
    if (ret != RET_OK) {
        MMI_HILOGE("ServerMsgHandler::OnUnsubscribeHotkey fail, error:%{public}d", ret);
        return ret;
    }
    if (NapProcess::GetInstance()->GetNapClientPid() != REMOVE_OBSERVER) {
        OHOS::MMI::NapProcess::NapStatusData napData;
        napData.pid = GetCallingPid();
        napData.uid = GetCallingUid();
        auto sess = GetSessionByPid(pid);
        CHKPR(sess, ERROR_NULL_POINTER);
        napData.bundleName = sess->GetProgramName();
        int32_t syncState = UNSUBSCRIBED;
        MMI_HILOGD("UnsubscribeHotkey info to observer : pid:%{public}d, bundleName:%{public}s",
            napData.pid, napData.bundleName.c_str());
        NapProcess::GetInstance()->AddMmiSubscribedEventData(napData, syncState);
        if (NapProcess::GetInstance()->GetNapClientPid() != UNOBSERVED) {
            NapProcess::GetInstance()->NotifyBundleName(napData, syncState);
        }
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::SubscribeSwitchEvent(int32_t subscribeId, int32_t switchType)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_SWITCH
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, pid, subscribeId, switchType] {
            return sMsgHandler_.OnSubscribeSwitchEvent(this, pid, subscribeId, switchType);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("The subscribe switch event processed failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_SWITCH
    return RET_OK;
}

int32_t MMIService::UnsubscribeSwitchEvent(int32_t subscribeId)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_SWITCH
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, pid, subscribeId] {
            return sMsgHandler_.OnUnsubscribeSwitchEvent(this, pid, subscribeId);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("The unsubscribe switch event processed failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_SWITCH
    return RET_OK;
}

int32_t MMIService::SetAnrObserver()
{
    CALL_INFO_TRACE;
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [pid] {
            return ::OHOS::DelayedSingleton<ANRManager>::GetInstance()->SetANRNoticedPid(pid);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set ANRNoticed pid failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::GetDisplayBindInfo(DisplayBindInfos &infos)
{
    CALL_INFO_TRACE;
    int32_t ret = delegateTasks_.PostSyncTask(
        [&infos] {
            return ::OHOS::MMI::IInputWindowsManager::GetInstance()->GetDisplayBindInfo(infos);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("GetDisplayBindInfo pid failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> &datas)
{
    CALL_INFO_TRACE;
    NapProcess::GetInstance()->GetAllMmiSubscribedEvents(datas);
    return RET_OK;
}

int32_t MMIService::SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg)
{
    CALL_INFO_TRACE;
    int32_t ret = delegateTasks_.PostSyncTask(
        [deviceId, displayId, &msg] {
            return ::OHOS::MMI::IInputWindowsManager::GetInstance()->SetDisplayBind(deviceId, displayId, msg);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("SetDisplayBind pid failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::GetFunctionKeyState(int32_t funcKey, bool &state)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, funcKey, &state] {
            return sMsgHandler_.OnGetFunctionKeyState(funcKey, state);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to get the keyboard status, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::SetFunctionKeyState(int32_t funcKey, bool enable)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, funcKey, enable] {
            return sMsgHandler_.OnSetFunctionKeyState(funcKey, enable);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to update the keyboard status, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::SetPointerLocation(int32_t x, int32_t y)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret = delegateTasks_.PostSyncTask(
        [x, y] {
            return ::OHOS::DelayedSingleton<MouseEventNormalize>::GetInstance()->SetPointerLocation(x, y);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer location failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}

void MMIService::OnDelegateTask(epoll_event &ev)
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
        ",taskId:%{public}d",
        GetThisThreadId(), data.tid, data.taskId);
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
#endif // OHOS_RSS_CLIENT
    libinputAdapter_.ProcessPendingEvents();
    while (state_ == ServiceRunningState::STATE_RUNNING) {
#if defined(OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER) && defined(OHOS_BUILD_ENABLE_KEYBOARD)
        if (isCesStart_ && !DISPLAY_MONITOR->IsCommonEventSubscriberInit()) {
            DISPLAY_MONITOR->InitCommonEventSubscriber();
        }
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER && OHOS_BUILD_ENABLE_KEYBOARD
        epoll_event ev[MAX_EVENT_SIZE] = {};
        int32_t timeout = TimerMgr->CalcNextDelay();
        MMI_HILOGD("timeout:%{public}d", timeout);
        int32_t count = EpollWait(ev[0], MAX_EVENT_SIZE, timeout, mmiFd_);
        for (int32_t i = 0; i < count && state_ == ServiceRunningState::STATE_RUNNING; i++) {
            auto mmiEdIter = epollEventMap_.find(ev[i].data.fd);
            if (mmiEdIter == epollEventMap_.end()) {
                MMI_HILOGW("Invalid event %{public}d %{public}d", ev[i].data.fd, count);
                continue;
            }
            std::shared_ptr<mmi_epoll_event> mmiEd = mmiEdIter->second;
            CHKPC(mmiEd);
            epoll_event event = ev[i];
            if (mmiEd->event_type == EPOLL_EVENT_INPUT) {
                CalculateFuntionRunningTime([this, &mmiEd] () { libinputAdapter_.EventDispatch(mmiEd->fd); },
                    "EPOLL_EVENT_INPUT");
            } else if (mmiEd->event_type == EPOLL_EVENT_SOCKET) {
                CalculateFuntionRunningTime([this, &event]() { this->OnEpollEvent(event); }, "MMI:EPOLL_EVENT_SOCKET");
            } else if (mmiEd->event_type == EPOLL_EVENT_SIGNAL) {
                OnSignalEvent(mmiEd->fd);
            } else if (mmiEd->event_type == EPOLL_EVENT_ETASK) {
                CalculateFuntionRunningTime([this, &event]() { this->OnDelegateTask(event); }, "MMI:EPOLL_EVENT_ETASK");
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
    sigset_t mask = { 0 };
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

    int32_t fdSignal = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
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
        MMI_HILOGE("Read signal info failed, invalid size:%{public}d, errno:%{public}d", size, errno);
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
    TimerMgr->AddTimer(RELOAD_DEVICE_TIME, REPEAT_COUNT, [this]() {
        auto deviceIds = INPUT_DEV_MGR->GetInputDeviceIds();
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
        [](const std::u16string &arg) { return Str16ToStr8(arg); });
    MMIEventDump->ParseCommand(fd, argList);
    return RET_OK;
}

int32_t MMIService::SetMouseCaptureMode(int32_t windowId, bool isCaptureMode)
{
    CALL_INFO_TRACE;
    int32_t ret = delegateTasks_.PostSyncTask(
        [windowId, isCaptureMode] {
            return ::OHOS::MMI::IInputWindowsManager::GetInstance()->SetMouseCaptureMode(windowId, isCaptureMode);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set capture failed, return:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::OnGetWindowPid(int32_t windowId, int32_t &windowPid)
{
    CALL_DEBUG_ENTER;
    windowPid = WIN_MGR->GetWindowPid(windowId);
    if (windowPid == RET_ERR) {
        MMI_HILOGE("Get window pid failed");
        return RET_ERR;
    }
    MMI_HILOGD("windowpid is %{public}d", windowPid);
    return RET_OK;
}

int32_t MMIService::GetWindowPid(int32_t windowId)
{
    CALL_INFO_TRACE;
    int32_t windowPid = INVALID_PID;
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, windowId, &windowPid] {
            return this->OnGetWindowPid(windowId, windowPid);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("OnGetWindowPid failed, ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("windowpid is %{public}d", windowPid);
    return windowPid;
}

int32_t MMIService::AppendExtraData(const ExtraData &extraData)
{
    CALL_DEBUG_ENTER;
    int32_t ret = delegateTasks_.PostSyncTask(
        [extraData] {
            return ::OHOS::MMI::IInputWindowsManager::GetInstance()->AppendExtraData(extraData);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Append extra data failed:%{public}d", ret);
    }
    return ret;
}

int32_t MMIService::EnableInputDevice(bool enable)
{
    CALL_DEBUG_ENTER;
    int32_t ret = delegateTasks_.PostSyncTask(
        [enable] {
            return ::OHOS::MMI::InputDeviceManager::GetInstance()->OnEnableInputDevice(enable);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("OnEnableInputDevice failed:%{public}d", ret);
    }
    return ret;
}

#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_COMBINATION_KEY)
int32_t MMIService::UpdateCombineKeyState(bool enable)
{
    auto eventSubscriberHandler = InputHandler->GetSubscriberHandler();
    CHKPR(eventSubscriberHandler, RET_ERR);
    int32_t ret = eventSubscriberHandler->EnableCombineKey(enable);
    if (ret != RET_OK) {
        MMI_HILOGE("EnableCombineKey is failed in key command:%{public}d", ret);
    }

    auto eventKeyCommandHandler = InputHandler->GetKeyCommandHandler();
    CHKPR(eventKeyCommandHandler, RET_ERR);
    ret = eventKeyCommandHandler->EnableCombineKey(enable);
    if (ret != RET_OK) {
        MMI_HILOGE("EnableCombineKey is failed in key command:%{public}d", ret);
    }
    return ret;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_COMBINATION_KEY

int32_t MMIService::CheckPidPermission(int32_t pid)
{
    CALL_DEBUG_ENTER;
    int32_t checkingPid = GetCallingPid();
    if (checkingPid != pid) {
        MMI_HILOGE("check pid failed, input pid:%{public}d, but checking pid:%{public}d", pid, checkingPid);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MMIService::EnableCombineKey(bool enable)
{
    CALL_DEBUG_ENTER;
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_COMBINATION_KEY)
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, enable] {
            return this->UpdateCombineKeyState(enable);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set key down duration failed:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_COMBINATION_KEY
    return RET_OK;
}

#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_COMBINATION_KEY)
int32_t MMIService::UpdateSettingsXml(const std::string &businessId, int32_t delay)
{
    std::shared_ptr<KeyCommandHandler> eventKeyCommandHandler = InputHandler->GetKeyCommandHandler();
    CHKPR(eventKeyCommandHandler, RET_ERR);
    return eventKeyCommandHandler->UpdateSettingsXml(businessId, delay);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_COMBINATION_KEY

int32_t MMIService::SetKeyDownDuration(const std::string &businessId, int32_t delay)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_COMBINATION_KEY)
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, businessId, delay] {
            return this->UpdateSettingsXml(businessId, delay);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set key down duration failed:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_COMBINATION_KEY
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_POINTER
int32_t MMIService::ReadTouchpadScrollSwich(bool &switchFlag)
{
    MouseEventHdr->GetTouchpadScrollSwitch(switchFlag);
    return RET_OK;
}

int32_t MMIService::ReadTouchpadScrollDirection(bool &switchFlag)
{
    MouseEventHdr->GetTouchpadScrollDirection(switchFlag);
    return RET_OK;
}

int32_t MMIService::ReadTouchpadTapSwitch(bool &switchFlag)
{
    MouseEventHdr->GetTouchpadTapSwitch(switchFlag);
    return RET_OK;
}

int32_t MMIService::ReadTouchpadPointerSpeed(int32_t &speed)
{
    MouseEventHdr->GetTouchpadPointerSpeed(speed);
    return RET_OK;
}

int32_t MMIService::ReadTouchpadPinchSwitch(bool &switchFlag)
{
    TOUCH_EVENT_HDR->GetTouchpadPinchSwitch(switchFlag);
    return RET_OK;
}

int32_t MMIService::ReadTouchpadSwipeSwitch(bool &switchFlag)
{
    TOUCH_EVENT_HDR->GetTouchpadSwipeSwitch(switchFlag);
    return RET_OK;
}

int32_t MMIService::ReadTouchpadRightMenuType(int32_t &type)
{
    MouseEventHdr->GetTouchpadRightClickType(type);
    return RET_OK;
}

int32_t MMIService::ReadTouchpadRotateSwitch(bool &rotateSwitch)
{
    TOUCH_EVENT_HDR->GetTouchpadRotateSwitch(rotateSwitch);
    return RET_OK;
}

#endif // OHOS_BUILD_ENABLE_POINTER

int32_t MMIService::SetTouchpadScrollSwitch(bool switchFlag)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t clientPid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [clientPid, switchFlag] {
            return ::OHOS::DelayedSingleton<MouseEventNormalize>::GetInstance()->SetTouchpadScrollSwitch(clientPid,
                switchFlag);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad scroll switch failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::GetTouchpadScrollSwitch(bool &switchFlag)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &switchFlag] {
            return this->ReadTouchpadScrollSwich(switchFlag);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get touchpad scroll switch failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetTouchpadScrollDirection(bool state)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [state] {
            return ::OHOS::DelayedSingleton<MouseEventNormalize>::GetInstance()->SetTouchpadScrollDirection(state);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad scroll direction switch failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::GetTouchpadScrollDirection(bool &state)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &state] {
            return this->ReadTouchpadScrollDirection(state);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get touchpad scroll direction switch failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetTouchpadTapSwitch(bool switchFlag)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [switchFlag] {
            return ::OHOS::DelayedSingleton<MouseEventNormalize>::GetInstance()->SetTouchpadTapSwitch(switchFlag);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad tap switch failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::GetTouchpadTapSwitch(bool &switchFlag)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &switchFlag] {
            return this->ReadTouchpadTapSwitch(switchFlag);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get touchpad tap switch failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetTouchpadPointerSpeed(int32_t speed)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [speed] {
            return ::OHOS::DelayedSingleton<MouseEventNormalize>::GetInstance()->SetTouchpadPointerSpeed(speed);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad speed failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::GetTouchpadPointerSpeed(int32_t &speed)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &speed] {
            return this->ReadTouchpadPointerSpeed(speed);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get touchpad speed failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetTouchpadPinchSwitch(bool switchFlag)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [switchFlag] {
            return ::OHOS::DelayedSingleton<TouchEventNormalize>::GetInstance()->SetTouchpadPinchSwitch(switchFlag);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set touch pad pinch switch failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::GetTouchpadPinchSwitch(bool &switchFlag)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &switchFlag] {
            return this->ReadTouchpadPinchSwitch(switchFlag);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get touch pad pinch switch failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetTouchpadSwipeSwitch(bool switchFlag)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [switchFlag] {
            return ::OHOS::DelayedSingleton<TouchEventNormalize>::GetInstance()->SetTouchpadSwipeSwitch(switchFlag);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad swipe switch failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::GetTouchpadSwipeSwitch(bool &switchFlag)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &switchFlag] {
            return this->ReadTouchpadSwipeSwitch(switchFlag);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get touchpad swipe switch failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetTouchpadRightClickType(int32_t type)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [type] {
            return ::OHOS::DelayedSingleton<MouseEventNormalize>::GetInstance()->SetTouchpadRightClickType(type);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad right button menu type failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::GetTouchpadRightClickType(int32_t &type)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &type] {
            return this->ReadTouchpadRightMenuType(type);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get touchpad right button menu type failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetTouchpadRotateSwitch(bool rotateSwitch)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [rotateSwitch] {
            return ::OHOS::DelayedSingleton<TouchEventNormalize>::GetInstance()->SetTouchpadRotateSwitch(rotateSwitch);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad rotate switch failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::GetTouchpadRotateSwitch(bool &rotateSwitch)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &rotateSwitch] {
            return this->ReadTouchpadRotateSwitch(rotateSwitch);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get touchpad rotate switch failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::SetShieldStatus(int32_t shieldMode, bool isShield)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, shieldMode, isShield] {
            return sMsgHandler_.SetShieldStatus(shieldMode, isShield);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set shield event interception state failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::GetShieldStatus(int32_t shieldMode, bool &isShield)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, shieldMode, &isShield] {
            return sMsgHandler_.GetShieldStatus(shieldMode, isShield);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to set shield event interception status, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::GetKeyState(std::vector<int32_t> &pressedKeys, std::map<int32_t, int32_t> &specialKeysState)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &pressedKeys, &specialKeysState] {
            return this->OnGetKeyState(pressedKeys, specialKeysState);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get pressed keys failed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t MMIService::Authorize(bool isAuthorize)
{
    CALL_DEBUG_ENTER;
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, isAuthorize] {
            return this->OnAuthorize(isAuthorize);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("OnAuthorize failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::OnAuthorize(bool isAuthorize)
{
    return sMsgHandler_.OnAuthorize(isAuthorize);
}

int32_t MMIService::CancelInjection()
{
    CALL_DEBUG_ENTER;
    int32_t ret = delegateTasks_.PostSyncTask(
        [this] {
            return this->OnCancelInjection();
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("OnCancelInjection failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::OnCancelInjection()
{
    return sMsgHandler_.OnCancelInjection();
}

int32_t MMIService::HasIrEmitter(bool &hasIrEmitter)
{
    CALL_DEBUG_ENTER;
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &hasIrEmitter] {
            return this->OnHasIrEmitter(hasIrEmitter);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("OnHasIrEmitter failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::GetInfraredFrequencies(std::vector<InfraredFrequency>& frequencies)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("Start get infrared frequency");
    std::vector<InfraredFrequencyInfo> infos;
    if (!InfraredEmitterController::GetInstance()->GetFrequencies(infos)) {
        MMI_HILOGE("Failed to get frequencies");
        return RET_ERR;
    }
    for (auto &item : infos) {
        InfraredFrequency info;
        info.min_ = item.min_;
        info.max_ = item.max_;
        frequencies.push_back(info);
    }
    std::string context = "";
    int32_t size = static_cast<int32_t>(frequencies.size());
    for (int32_t i = 0; i < size; i++) {
        context = context + "frequencies[" + std::to_string(i) + "]. max=" + std::to_string(frequencies[i].max_) +
        ",min=" + std::to_string(frequencies[i].min_) + ";";
    }
    MMI_HILOGD("Data from hdf context:%{public}s", context.c_str());
    return RET_OK;
}

int32_t MMIService::TransmitInfrared(int64_t number, std::vector<int64_t>& pattern)
{
    CALL_DEBUG_ENTER;
    std::string context = "infraredFrequency:" + std::to_string(number) + ";";
    int32_t size = static_cast<int32_t>(pattern.size());
    for (int32_t i = 0; i < size; i++) {
        context = context + "index:" + std::to_string(i) + ": pattern:" + std::to_string(pattern[i]) + ";";
    }
    MMI_HILOGI("TransmitInfrared para context:%{public}s", context.c_str());
    if (!InfraredEmitterController::GetInstance()->Transmit(number, pattern)) {
        MMI_HILOGE("Failed to transmit");
        return RET_ERR;
    }
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
int32_t MMIService::SetVKeyboardArea(double topLeftX, double topLeftY, double bottomRightX, double bottomRightY)
{
    CALL_INFO_TRACE;
    if (!isHPR_) {
        MMI_HILOGE("Failed to set virtual keyboard area, feature not supported");
        return RET_ERR;
    }
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, topLeftX, topLeftY, bottomRightX, bottomRightY] {
            return this->OnSetVKeyboardArea(topLeftX, topLeftY, bottomRightX, bottomRightY);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to set virtual keyboard area, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MMIService::OnSetVKeyboardArea(double topLeftX, double topLeftY, double bottomRightX, double bottomRightY)
{
    algorithm_initialize_(false);
    gaussiankeyboard_setVKeyboardArea_(topLeftX, topLeftY, bottomRightX, bottomRightY);
    int32_t sKeyEventID = 1234;
    int32_t sKeyEventDeviceId = 99;
    // Init the shared key event used by later key injection module and set common fields.
    g_VKeySharedKeyEvent = KeyEvent::Create();
    CHKPR(g_VKeySharedKeyEvent, ERROR_NULL_POINTER);
    g_VKeySharedKeyEvent->SetId(sKeyEventID);
    g_VKeySharedKeyEvent->SetDeviceId(sKeyEventDeviceId);
    // Init the shared UI key event for UI rendering.
    g_VKeySharedUIKeyEvent = KeyEvent::Create();
    CHKPR(g_VKeySharedUIKeyEvent, ERROR_NULL_POINTER);
    g_VKeySharedUIKeyEvent->SetId(sKeyEventID);
    g_VKeySharedUIKeyEvent->SetDeviceId(sKeyEventDeviceId);

    auto defaultDisplay = WIN_MGR->GetDefaultDisplayInfo();
    CHKPR(defaultDisplay, ERROR_NULL_POINTER);
    int32_t width = defaultDisplay->width;
    int32_t height = defaultDisplay->height;
    // Use this information to estimate the valid range of cursor, assuming single display.
    trackPadEngine_setScreenArea_(0, 0, width, height);
    return RET_OK;
}

int32_t MMIService::SetMotionSpace(std::string& keyName, bool useShift, std::vector<int32_t>& pattern)
{
    CALL_INFO_TRACE;
    if (!isHPR_) {
        MMI_HILOGE("Failed to set motion space, feature not supported");
        return RET_ERR;
    }
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &keyName, useShift, &pattern] {
            return this->OnSetMotionSpace(keyName, useShift, pattern);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to set motion space, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MMIService::OnSetMotionSpace(std::string& keyName, bool useShift, std::vector<int32_t>& pattern)
{
    if (pattern.size() == MotionSpacePatternIndex::PATTERN_SIZE) {
        auto motionSpaceType = static_cast<MotionSpaceType>(pattern[MotionSpacePatternIndex::PATTERN_MST_ID]);
        if (motionSpaceType != MotionSpaceType::TRACKPAD) {
            gaussiankeyboard_updateMotionSpace_(keyName, useShift, pattern);
        } else {
            trackPadEngine_setVTrackPadArea_(keyName, pattern);
        }
        return RET_OK;
    } else {
        return COMMON_PARAMETER_ERROR;
    }
}

void MMIService::OnVKeyTrackPadMessage(const std::vector<std::vector<int32_t>>& msgList)
{
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    CHKPRV(pointerEvent, "Virtual TrackPad not able to create pointer event");
    for (auto msgItem : msgList) {
        if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
            MMI_HILOGE("Virtual TrackPad state machine message size: %{public}d is not correct",
                static_cast<int32_t>(msgItem.size()));
            continue;
        }
        auto msgType = static_cast<VTPStateMachineMessageType>(msgItem[VKEY_TP_SM_MSG_TYPE_IDX]);
        switch (msgType) {
            case VTPStateMachineMessageType::POINTER_MOVE:
                if (!HandleVKeyTrackPadPointerMove(pointerEvent, msgItem)) {
                    MMI_HILOGE("Virtual TrackPad pointer move event cannot be handled");
                }
                break;
            case VTPStateMachineMessageType::LEFT_CLICK_DOWN:
                if (!HandleVKeyTrackPadLeftBtnDown(pointerEvent, msgItem)) {
                    MMI_HILOGE("Virtual TrackPad left button down event cannot be handled");
                }
                break;
            case VTPStateMachineMessageType::LEFT_CLICK_UP:
                if (!HandleVKeyTrackPadLeftBtnUp(pointerEvent, msgItem)) {
                    MMI_HILOGE("Virtual TrackPad left button up event cannot be handled");
                }
                break;
            case VTPStateMachineMessageType::RIGHT_CLICK_DOWN:
                if (!HandleVKeyTrackPadRightBtnDown(pointerEvent, msgItem)) {
                    MMI_HILOGE("Virtual TrackPad right button down event cannot be handled");
                }
                break;
            case VTPStateMachineMessageType::RIGHT_CLICK_UP:
                if (!HandleVKeyTrackPadRightBtnUp(pointerEvent, msgItem)) {
                    MMI_HILOGE("Virtual TrackPad right button up event cannot be handled");
                }
                break;
            default:
                break;
        }
    }
}

bool MMIService::HandleVKeyTrackPadPointerMove(
    std::shared_ptr<PointerEvent> pointerEvent, const std::vector<int32_t>& msgItem)
{
    CHKPF(pointerEvent);
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size: %{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    int32_t pDeviceId = 99;
    PointerEvent::PointerItem item;
    item.SetPointerId(msgPId);
    item.SetDisplayX(msgPPosX);
    item.SetDisplayY(msgPPosY);
    item.SetPressure(0);
    item.SetDeviceId(pDeviceId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(msgPId);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetButtonId(PointerEvent::BUTTON_NONE);
    pointerEvent->SetButtonPressed(PointerEvent::BUTTON_NONE);
    auto eventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPF(eventNormalizeHandler);
    eventNormalizeHandler->HandlePointerEvent(pointerEvent);
    return true;
}

bool MMIService::HandleVKeyTrackPadLeftBtnDown(
    std::shared_ptr<PointerEvent> pointerEvent, const std::vector<int32_t>& msgItem)
{
    CHKPF(pointerEvent);
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size: %{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    int32_t pDeviceId = 99;
    PointerEvent::PointerItem item;
    item.SetPointerId(msgPId);
    item.SetDisplayX(msgPPosX);
    item.SetDisplayY(msgPPosY);
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressed(true);
    item.SetPressure(0);
    item.SetDeviceId(pDeviceId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetPointerId(msgPId);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    auto eventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPF(eventNormalizeHandler);
    eventNormalizeHandler->HandlePointerEvent(pointerEvent);
    return true;
}

bool MMIService::HandleVKeyTrackPadLeftBtnUp(
    std::shared_ptr<PointerEvent> pointerEvent, const std::vector<int32_t>& msgItem)
{
    CHKPF(pointerEvent);
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size: %{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    int32_t pDeviceId = 99;
    PointerEvent::PointerItem item;
    item.SetPointerId(msgPId);
    item.SetDisplayX(msgPPosX);
    item.SetDisplayY(msgPPosY);
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressed(false);
    item.SetPressure(0);
    item.SetDeviceId(pDeviceId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    pointerEvent->SetPointerId(msgPId);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    auto eventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPF(eventNormalizeHandler);
    eventNormalizeHandler->HandlePointerEvent(pointerEvent);
    return true;
}

bool MMIService::HandleVKeyTrackPadRightBtnDown(
    std::shared_ptr<PointerEvent> pointerEvent, const std::vector<int32_t>& msgItem)
{
    CHKPF(pointerEvent);
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size: %{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    int32_t pDeviceId = 99;
    PointerEvent::PointerItem item;
    item.SetPointerId(msgPId);
    item.SetDisplayX(msgPPosX);
    item.SetDisplayY(msgPPosY);
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressed(true);
    item.SetPressure(0);
    item.SetDeviceId(pDeviceId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetPointerId(msgPId);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_RIGHT);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_RIGHT);
    auto eventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPF(eventNormalizeHandler);
    eventNormalizeHandler->HandlePointerEvent(pointerEvent);
    return true;
}

bool MMIService::HandleVKeyTrackPadRightBtnUp(
    std::shared_ptr<PointerEvent> pointerEvent, const std::vector<int32_t>& msgItem)
{
    CHKPF(pointerEvent);
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size: %{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    int32_t pDeviceId = 99;
    PointerEvent::PointerItem item;
    item.SetPointerId(msgPId);
    item.SetDisplayX(msgPPosX);
    item.SetDisplayY(msgPPosY);
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressed(false);
    item.SetPressure(0);
    item.SetDeviceId(pDeviceId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    pointerEvent->SetPointerId(msgPId);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_RIGHT);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_RIGHT);
    auto eventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPF(eventNormalizeHandler);
    eventNormalizeHandler->HandlePointerEvent(pointerEvent);
    return true;
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

int32_t MMIService::OnHasIrEmitter(bool &hasIrEmitter)
{
    hasIrEmitter = false;
    return RET_OK;
}

int32_t MMIService::SetPixelMapData(int32_t infoId, void* pixelMap)
{
    CALL_DEBUG_ENTER;
    CHKPR(pixelMap, ERROR_NULL_POINTER);
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, infoId, pixelMap] {
            return sMsgHandler_.SetPixelMapData(infoId, pixelMap);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to set pixelmap, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

void MMIService::InitPreferences()
{
    PREFERENCES_MGR->InitPreferences();
#ifdef OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    int32_t ret = SetMoveEventFilters(PREFERENCES_MGR->GetBoolValue("moveEventFilterFlag", false));
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to read moveEventFilterFlag, ret:%{public}d", ret);
    }
#endif // OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
}

int32_t MMIService::SetMoveEventFilters(bool flag)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    int32_t ret = delegateTasks_.PostSyncTask(
        std::bind(&InputEventHandler::SetMoveEventFilters, InputHandler, flag));
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to set move event filter flag, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    return RET_OK;
}

int32_t MMIService::SetCurrentUser(int32_t userId)
{
    CALL_DEBUG_ENTER;
    int32_t ret = delegateTasks_.PostSyncTask(
        [userId] {
            return ::OHOS::MMI::IInputWindowsManager::GetInstance()->SetCurrentUser(userId);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to set current user, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::SetTouchpadThreeFingersTapSwitch(bool switchFlag)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [switchFlag] {
            return ::OHOS::DelayedSingleton<TouchEventNormalize>::GetInstance()->SetTouchpadThreeFingersTapSwitch(
                switchFlag);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to SetTouchpadThreeFingersTapSwitch status, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::GetTouchpadThreeFingersTapSwitch(bool &switchFlag)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [&switchFlag] {
            return ::OHOS::DelayedSingleton<TouchEventNormalize>::GetInstance()->GetTouchpadThreeFingersTapSwitch(
                switchFlag);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to GetTouchpadThreeFingersTapSwitch status, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t MMIService::AddVirtualInputDevice(std::shared_ptr<InputDevice> device, int32_t &deviceId)
{
    CALL_DEBUG_ENTER;
    CHKPR(device, ERROR_NULL_POINTER);
    int32_t ret = delegateTasks_.PostSyncTask(
        [device, &deviceId] {
            return ::OHOS::MMI::InputDeviceManager::GetInstance()->AddVirtualInputDevice(device, deviceId);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("AddVirtualInputDevice failed:%{public}d", ret);
    }
    return ret;
}

int32_t MMIService::RemoveVirtualInputDevice(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    int32_t ret = delegateTasks_.PostSyncTask(
        [deviceId] {
            return ::OHOS::MMI::InputDeviceManager::GetInstance()->RemoveVirtualInputDevice(deviceId);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("RemoveVirtualInputDevice failed:%{public}d", ret);
    }
    return ret;
}

int32_t MMIService::EnableHardwareCursorStats(bool enable)
{
    CALL_DEBUG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [pid, enable] {
            return IPointerDrawingManager::GetInstance()->EnableHardwareCursorStats(pid, enable);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Enable hardware cursor stats failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}

int32_t MMIService::GetHardwareCursorStats(uint32_t &frameCount, uint32_t &vsyncCount)
{
    CALL_DEBUG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t pid = GetCallingPid();
    int32_t ret = delegateTasks_.PostSyncTask(
        [pid, &frameCount, &vsyncCount] {
            return IPointerDrawingManager::GetInstance()->GetHardwareCursorStats(pid, frameCount, vsyncCount);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get hardware cursor stats failed, ret:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
int32_t MMIService::GetPointerSnapshot(void *pixelMapPtr)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    MMI_HILOGI("Get pointer snapshot from process(%{public}d)", GetCallingPid());
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(
        std::bind(&IPointerDrawingManager::GetPointerSnapshot, IPointerDrawingManager::GetInstance(), pixelMapPtr)));
    if (ret != RET_OK) {
        MMI_HILOGE("Get the pointer snapshot failed, ret: %{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR

int32_t MMIService::SetTouchpadScrollRows(int32_t rows)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [rows] {
            return ::OHOS::DelayedSingleton<TouchEventNormalize>::GetInstance()->SetTouchpadScrollRows(rows);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Set the number of touchpad scrolling rows failed, return %{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_POINTER
int32_t MMIService::ReadTouchpadScrollRows(int32_t &rows)
{
    rows = TOUCH_EVENT_HDR->GetTouchpadScrollRows();
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER

int32_t MMIService::GetTouchpadScrollRows(int32_t &rows)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &rows] {
            return this->ReadTouchpadScrollRows(rows);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Get the number of touchpad scrolling rows failed, return %{public}d, pid:%{public}d", ret,
            GetCallingPid());
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_ANCO
int32_t MMIService::AncoAddChannel(sptr<IAncoChannel> channel)
{
    int32_t ret = delegateTasks_.PostSyncTask([channel]() {
        return WIN_MGR->AncoAddChannel(channel);
    });
    if (ret != RET_OK) {
        MMI_HILOGE("AncoAddChannel fail, error:%{public}d", ret);
    }
    return ret;
}

int32_t MMIService::AncoRemoveChannel(sptr<IAncoChannel> channel)
{
    int32_t ret = delegateTasks_.PostSyncTask([channel]() {
        return WIN_MGR->AncoRemoveChannel(channel);
    });
    if (ret != RET_OK) {
        MMI_HILOGE("AncoRemoveChannel fail, error:%{public}d", ret);
    }
    return ret;
}
#endif // OHOS_BUILD_ENABLE_ANCO

int32_t MMIService::TransferBinderClientSrv(const sptr<IRemoteObject> &binderClientObject)
{
    CALL_DEBUG_ENTER;
    int32_t pid = GetCallingPid();
    int32_t ret =
        delegateTasks_.PostSyncTask(
            [this, pid, binderClientObject] {
                return sMsgHandler_.OnTransferBinderClientSrv(binderClientObject, pid);
            }
        );
    MMI_HILOGI("TransferBinderClientSrv result:%{public}d", ret);
    return ret;
}

void MMIService::CalculateFuntionRunningTime(std::function<void()> func, const std::string &flag)
{
    std::function<void (void *)> printLog = std::bind(&MMIService::PrintLog, this, flag, THREAD_BLOCK_TIMER_SPAN_S,
        getpid(), gettid());
    int32_t id = HiviewDFX::XCollie::GetInstance().SetTimer(flag, THREAD_BLOCK_TIMER_SPAN_S, printLog, nullptr,
        HiviewDFX::XCOLLIE_FLAG_NOOP);
    func();
    HiviewDFX::XCollie::GetInstance().CancelTimer(id);
}

void MMIService::PrintLog(const std::string &flag, int32_t duration, int32_t pid, int32_t tid)
{
    std::string dfxThreadBlockMsg { "MMIBlockTask name:" };
    dfxThreadBlockMsg += flag;
    dfxThreadBlockMsg += ", duration time:";
    dfxThreadBlockMsg += std::to_string(duration);
    dfxThreadBlockMsg += ", pid:";
    dfxThreadBlockMsg += std::to_string(pid);
    dfxThreadBlockMsg += ", tid:";
    dfxThreadBlockMsg += std::to_string(tid);
    MMI_HILOGW("DfxThreadBlockMsg:%{public}s", dfxThreadBlockMsg.c_str());
    OHOS::HiviewDFX::DfxDumpCatcher dumpCatcher;
    dumpCatcher.DumpCatch(pid, tid, dfxThreadBlockMsg, MAX_FRAME_NUMS, false);
    MMI_HILOGW("BlockMsg:%{public}s", dfxThreadBlockMsg.c_str());
}

int32_t MMIService::SkipPointerLayer(bool isSkip)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret = delegateTasks_.PostSyncTask(
        [isSkip] {
            return IPointerDrawingManager::GetInstance()->SkipPointerLayer(isSkip);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGE("Skip pointer layerfailed, return:%{public}d", ret);
        return ret;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return RET_OK;
}

void MMIService::OnSessionDelete(SessionPtr session)
{
    CALL_DEBUG_ENTER;
    CHKPV(session);
    std::string programName = session->GetProgramName();
    std::lock_guard<std::mutex> guard(mutex_);
    auto it = clientInfos_.find(programName);
    if (it != clientInfos_.end()) {
        clientInfos_.erase(it);
        MMI_HILOGD("Clear the client info, programName:%{public}s", programName.c_str());
    }
}

int32_t MMIService::SetClientInfo(int32_t pid, uint64_t readThreadId)
{
    CALL_DEBUG_ENTER;
    auto sess = GetSessionByPid(pid);
    CHKPR(sess, ERROR_NULL_POINTER);
    std::string programName = sess->GetProgramName();
    std::lock_guard<std::mutex> guard(mutex_);
    if (clientInfos_.find(programName) != clientInfos_.end()) {
        clientInfos_[programName].pid = pid;
        clientInfos_[programName].readThreadId = readThreadId;
        return RET_OK;
    }
    ClientInfo clientInfo {
        .pid = pid,
        .readThreadId = readThreadId
    };
    clientInfos_[programName] = clientInfo;
    return RET_OK;
}

void MMIService::InitPrintClientInfo()
{
    CALL_DEBUG_ENTER;
    TimerMgr->AddLongTimer(PRINT_INTERVAL_TIME, -1, [this]() {
        ffrt::submit([this] {
            std::lock_guard<std::mutex> guard(mutex_);
            for (const auto &info : clientInfos_) {
                if (static_cast<uint64_t>(info.second.pid) == info.second.readThreadId) {
                    MMI_HILOGW("The application main thread and event reading thread are combined, such as:"
                    "programName:%{public}s, pid:%{public}d, mainThreadId:%{public}d, readThreadId:%{public}" PRIu64,
                    info.first.c_str(), info.second.pid, info.second.pid, info.second.readThreadId);
                    return;
                }
            }
            if (!clientInfos_.empty()) {
                auto it = clientInfos_.begin();
                MMI_HILOGI("The application main thread and event reading thread are separated, such as:"
                "programName:%{public}s, pid:%{public}d, mainThreadId:%{public}d, readThreadId:%{public}" PRIu64,
                it->first.c_str(), it->second.pid, it->second.pid, it->second.readThreadId);
            }
        });
    });
    std::function<void(SessionPtr)> callback = [this](SessionPtr sess) {
        return this->OnSessionDelete(sess);
    };
    AddSessionDeletedCallback(callback);
}

int32_t MMIService::GetIntervalSinceLastInput(int64_t &timeInterval)
{
    CALL_INFO_TRACE;
    int32_t ret = delegateTasks_.PostSyncTask(std::bind(&InputEventHandler::GetIntervalSinceLastInput,
        InputHandler, std::ref(timeInterval)));
    MMI_HILOGD("timeInterval:%{public}" PRId64, timeInterval);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to GetIntervalSinceLastInput, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MMIService::GetAllSystemHotkeys(std::vector<std::unique_ptr<KeyOption>> &keyOptions)
{
    CALL_DEBUG_ENTER;
    int32_t ret = delegateTasks_.PostSyncTask(
        [this, &keyOptions] {
            return this->OnGetAllSystemHotkey(keyOptions);
        }
        );
    if (ret != RET_OK) {
        MMI_HILOGD("Get all system hot key, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MMIService::OnGetAllSystemHotkey(std::vector<std::unique_ptr<KeyOption>> &keyOptions)
{
    CALL_DEBUG_ENTER;
    #ifdef SHORTCUT_KEY_MANAGER_ENABLED
    return KEY_SHORTCUT_MGR->GetAllSystemHotkeys(keyOptions);
    #endif // SHORTCUT_KEY_MANAGER_ENABLED
    MMI_HILOGI("OnGetAllSystemHotkey function does not support");
    return ERROR_UNSUPPORT;
}
} // namespace MMI
} // namespace OHOS
