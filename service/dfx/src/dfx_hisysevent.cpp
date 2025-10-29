/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "dfx_hisysevent.h"

#include <fstream>

#include "bundle_name_parser.h"
#include "i_input_windows_manager.h"
#include "parameters.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DfxHisysevent"

namespace OHOS {
namespace MMI {
namespace {
constexpr uint32_t REPORT_DISPATCH_TIMES { 100 };
constexpr uint32_t REPORT_COMBO_START_TIMES { 100 };
constexpr uint32_t POINTER_CLEAR_TIMES { 10 };
constexpr int32_t CONVERSION_US_TO_MS { 1000 };
constexpr int32_t TIMES_LEVEL1 { 10 };
constexpr int32_t TIMES_LEVEL2 { 25 };
constexpr int32_t TIMES_LEVEL3 { 30 };
constexpr int32_t TIMES_LEVEL4 { 50 };
constexpr int32_t FINGERSENSE_EVENT_TIMES { 1 };
constexpr size_t SINGLE_KNUCKLE_SIZE { 1 };
constexpr size_t DOUBLE_KNUCKLE_SIZE { 2 };
constexpr int32_t FAIL_SUCC_TIME_DIFF { 3 * 60 * 1000 };
constexpr int32_t MIN_GESTURE_TIMESTAMPS_SIZE { 2 };
constexpr int32_t DOWN_TO_PREV_UP_MAX_TIME_THRESHOLD { 1000 * 1000 };
constexpr int32_t FOLDABLE_DEVICE { 2 };
constexpr int32_t REPORT_MAX_KEY_EVENT_TIMES { 1000 };
const int32_t ROTATE_POLICY = system::GetIntParameter("const.window.device.rotate_policy", 0);
const std::string EMPTY_STRING { "" };
const char* LCD_PATH { "/sys/class/graphics/fb0/lcd_model" };
const char* ACC_PATH { "/sys/devices/platform/_sensor/acc_info" };
const char* ACC0_PATH { "/sys/class/sensors/acc_sensor/info" };
const char* TP_PATH { "/sys/touchscreen/touch_chip_info" };
const char* TP0_PATH { "/sys/touchscreen0/touch_chip_info" };
const char* TP1_PATH { "/sys/touchscreen1/touch_chip_info" };
const std::string NAME_DISPATCH { "dispatch" };
const std::string NAME_FILTER { "filter" };
const std::string NAME_INTERCEPT { "intercept" };
const std::string NAME_SUBCRIBER { "subcriber" };
const std::string NAME_FINGERPRINT { "fingerprint" };
const std::string NAME_STYLUS { "stylus" };
const std::string NAME_CANCEL { "cancel" };
const std::string TOUCH_SCREEN_ON { "screen on" };
static constexpr char WATCH_CROWN_MUTE[] { "WATCH_CROWN_MUTE" };
} // namespace

static std::string GetVendorInfo(const char* nodePath)
{
    char realPath[PATH_MAX] = {};
    if (realpath(nodePath, realPath) == nullptr) {
        MMI_HILOGE("The realpath return nullptr");
        return "";
    }
    std::ifstream file(realPath);
    if (!file.is_open()) {
        MMI_HILOGE("Unable to open file:%{private}s, error:%{public}d", nodePath, errno);
        return "";
    }
    std::string vendorInfo;
    file >> vendorInfo;
    file.close();
    return vendorInfo;
}

void DfxHisysevent::OnClientConnect(const ClientConnectData &data, OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "CLIENT_CONNECTION_SUCCESS",
            type,
            "PID", data.pid,
            "UID", data.uid,
            "MODULE_TYPE", data.moduleType,
            "SERVER_FD", data.serverFd,
            "PROGRAMNAME", data.programName,
            "MSG", "The client successfully connected to the server");
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    } else {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "CLIENT_CONNECTION_FAILURE",
            type,
            "PID", data.pid,
            "UID", data.uid,
            "MODULE_TYPE", data.moduleType,
            "PROGRAMNAME", data.programName,
            "MSG", "The client failed to connect to the server");
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    }
}

void DfxHisysevent::OnClientDisconnect(const SessionPtr& secPtr, int32_t fd,
    OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    CHKPV(secPtr);
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "CLIENT_DISCONNECTION_SUCCESS",
            type,
            "PID", secPtr->GetPid(),
            "UID", secPtr->GetUid(),
            "MODULE_TYPE", secPtr->GetModuleType(),
            "FD", fd,
            "PROGRAMNAME", secPtr->GetProgramName(),
            "MSG", "The client successfully disconnected to the server");
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    } else {
        if (secPtr == nullptr) {
            int32_t ret = HiSysEventWrite(
                OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
                "CLIENT_DISCONNECTION_FAILURE",
                type,
                "MSG", "The client failed to disconnect to the server because secPtr is nullptr");
            if (ret != 0) {
                MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
            }
        } else {
            int32_t ret = HiSysEventWrite(
                OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
                "CLIENT_DISCONNECTION_FAILURE",
                type,
                "MSG", "The client failed to disconnect to the server because close(fd) return error");
            if (ret != 0) {
                MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
            }
        }
    }
}

void DfxHisysevent::OnUpdateTargetPointer(std::shared_ptr<PointerEvent> pointer, int32_t fd,
    OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    CHKPV(pointer);
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "TARGET_POINTER_EVENT_SUCCESS",
            type,
            "EVENTTYPE", pointer->GetEventType(),
            "AGENT_WINDOWID", pointer->GetAgentWindowId(),
            "TARGET_WINDOWID", pointer->GetTargetWindowId(),
            "PID", WIN_MGR->GetWindowPid(pointer->GetTargetWindowId()),
            "FD", fd,
            "MSG", "The window manager successfully update target pointer");
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    } else {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "TARGET_POINTER_EVENT_FAILURE",
            OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
            "EVENTTYPE", pointer->GetEventType(),
            "MSG", "The window manager failed to update target pointer");
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    }
}

void DfxHisysevent::OnUpdateTargetKey(std::shared_ptr<KeyEvent> key, int32_t fd,
    OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    CHKPV(key);
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "TARGET_KEY_EVENT_SUCCESS",
            type,
            "EVENTTYPE", key->GetEventType(),
            "KEYCODE", key->GetKeyCode(),
            "ACTION", key->GetAction(),
            "ACTION_TIME", key->GetActionTime(),
            "ACTION_STARTTIME", key->GetActionStartTime(),
            "FLAG", key->GetFlag(),
            "KEYACTION", key->GetKeyAction(),
            "FD", fd,
            "AGENT_WINDOWID", key->GetAgentWindowId(),
            "TARGET_WINDOWID", key->GetTargetWindowId(),
            "PID", WIN_MGR->GetWindowPid(key->GetTargetWindowId()),
            "MSG", "The window manager successfully update target key");
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    } else {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "TARGET_KEY_EVENT_FAILURE",
            type,
            "EVENTTYPE", key->GetEventType(),
            "KEYCODE", key->GetKeyCode(),
            "ACTION", key->GetAction(),
            "ACTION_TIME", key->GetActionTime(),
            "ACTION_STARTTIME", key->GetActionStartTime(),
            "FLAG", key->GetFlag(),
            "KEYACTION", key->GetKeyAction(),
            "MSG", "The window manager failed to update target key");
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    }
}

void DfxHisysevent::OnFocusWindowChanged(int32_t oldFocusWindowId, int32_t newFocusWindowId,
    int32_t oldFocusWindowPid, int32_t newFocusWindowPid)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FOCUS_WINDOW_CHANGE",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "OLD_FOCUS_WINDOWID", oldFocusWindowId,
        "NEW_FOCUS_WINDOWID", newFocusWindowId,
        "OLD_FOCUS_WINDOWPID", oldFocusWindowPid,
        "NEW_FOCUS_WINDOWPID", newFocusWindowPid,
        "MSG", "The focusWindowId changing succeeded");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::OnZorderWindowChanged(int32_t oldZorderFirstWindowId, int32_t newZorderFirstWindowId,
    int32_t oldZorderFirstWindowPid, int32_t newZorderFirstWindowPid)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "Z_ORDER_WINDOW_CHANGE",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "OLD_ZORDER_FIRST_WINDOWID", oldZorderFirstWindowId,
        "NEW_ZORDER_FIRST_WINDOWID", newZorderFirstWindowId,
        "OLD_ZORDER_FIRST_WINDOWPID", oldZorderFirstWindowPid,
        "NEW_ZORDER_FIRST_WINDOWPID", newZorderFirstWindowPid,
        "MSG", "The ZorderFirstWindow changing succeeded");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::OnLidSwitchChanged(int32_t lidSwitch)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "LID_SWITCH",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "SWITCH", lidSwitch);
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ApplicationBlockInput(const SessionPtr& sess)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "APPLICATION_BLOCK_INPUT",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "PID", sess->GetPid(),
        "UID", sess->GetUid(),
        "PACKAGE_NAME", sess->GetProgramName(),
        "PROCESS_NAME", sess->GetProgramName(),
        "MSG", "User input does not respond");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::CalcKeyDispTimes()
{
    int64_t endTime = GetSysClockTime();
    dispCastTime_.totalTimes++;
    int64_t castTime = (endTime - dispatchStartTime_) / CONVERSION_US_TO_MS;
    if (castTime <= TIMES_LEVEL1) {
        dispCastTime_.below10msTimes++;
    } else if (castTime <= TIMES_LEVEL2) {
        dispCastTime_.below25msTimes++;
    } else if (castTime <= TIMES_LEVEL4) {
        dispCastTime_.below50msTimes++;
    } else {
        dispCastTime_.above50msTimes++;
    }
}

void DfxHisysevent::CalcPointerDispTimes()
{
    int64_t endTime = GetSysClockTime();
    dispCastTime_.sampleCount++;
    int64_t castTime = (endTime - dispatchStartTime_) / CONVERSION_US_TO_MS;
    if (dispCastTime_.sampleCount == POINTER_CLEAR_TIMES) {
        dispCastTime_.sampleCount = 0;
        dispCastTime_.totalTimes++;
        if (castTime <= TIMES_LEVEL1) {
            dispCastTime_.below10msTimes++;
        } else if (castTime <= TIMES_LEVEL2) {
            dispCastTime_.below25msTimes++;
        } else if (castTime <= TIMES_LEVEL4) {
            dispCastTime_.below50msTimes++;
        } else {
            dispCastTime_.above50msTimes++;
        }
    }
}

void DfxHisysevent::ReportDispTimes()
{
    if (dispCastTime_.totalTimes >= REPORT_DISPATCH_TIMES) {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "INPUT_DISPATCH_TIME",
            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
            "BELOW10MS", dispCastTime_.below10msTimes,
            "BELOW25MS", dispCastTime_.below25msTimes,
            "BELOW50MS", dispCastTime_.below50msTimes,
            "ABOVE50MS", dispCastTime_.above50msTimes,
            "MSG", "The costing time to dispatch event");
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        } else {
            dispCastTime_.sampleCount = 0;
            dispCastTime_.totalTimes = 0;
            dispCastTime_.below10msTimes = 0;
            dispCastTime_.below25msTimes = 0;
            dispCastTime_.below50msTimes = 0;
            dispCastTime_.above50msTimes = 0;
        }
    }
}

void DfxHisysevent::CalcComboStartTimes(const int32_t keyDownDuration)
{
    int64_t endTime = GetSysClockTime();
    comboStartCastTime_.totalTimes++;
    int64_t castTime = (endTime - comboStartTime_) / CONVERSION_US_TO_MS - keyDownDuration;
    if (castTime <= TIMES_LEVEL1) {
        comboStartCastTime_.below10msTimes++;
    } else if (castTime <= TIMES_LEVEL3) {
        comboStartCastTime_.below30msTimes++;
    } else if (castTime <= TIMES_LEVEL4) {
        comboStartCastTime_.below50msTimes++;
    } else {
        comboStartCastTime_.above50msTimes++;
    }
}

void DfxHisysevent::ReportComboStartTimes()
{
    if (comboStartCastTime_.totalTimes >= REPORT_COMBO_START_TIMES) {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "COMBO_START_TIME",
            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
            "BELOW10MS", comboStartCastTime_.below10msTimes,
            "BELOW30MS", comboStartCastTime_.below30msTimes,
            "BELOW50MS", comboStartCastTime_.below50msTimes,
            "ABOVE50MS", comboStartCastTime_.above50msTimes,
            "MSG", "The costing time to launch application of combination");
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        } else {
            comboStartCastTime_.totalTimes = 0;
            comboStartCastTime_.below10msTimes = 0;
            comboStartCastTime_.below30msTimes = 0;
            comboStartCastTime_.below50msTimes = 0;
            comboStartCastTime_.above50msTimes = 0;
        }
    }
}

void DfxHisysevent::ReportPowerInfo(std::shared_ptr<KeyEvent> key, OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    CHKPV(key);
    if (key->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "INPUT_POWER_UP",
            type);
        if (ret != RET_OK) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    } else if (key->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "INPUT_POWER_DOWN",
            type);
        if (ret != RET_OK) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    } else {
        MMI_HILOGW("Press power key is error");
    }
}

void DfxHisysevent::StatisticTouchpadGesture(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    int32_t pointerAction = pointerEvent->GetPointerAction();
    int32_t fingerCount = pointerEvent->GetFingerCount();

    if (pointerAction == PointerEvent::POINTER_ACTION_AXIS_BEGIN) {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "TOUCHPAD_PINCH",
            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
            "FINGER_COUNT", fingerCount);
        if (ret != RET_OK) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    } else if (pointerAction == PointerEvent::POINTER_ACTION_SWIPE_BEGIN) {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "TOUCHPAD_SWIPE",
            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
            "FINGER_COUNT", fingerCount);
        if (ret != RET_OK) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    } else {
        MMI_HILOGW("HiviewDFX Statistic touchpad gesture is error, pointer action is invalid");
    }
}

void DfxHisysevent::ReportTouchpadSettingState(TOUCHPAD_SETTING_CODE settingCode, bool flag)
{
    const std::map<uint32_t, std::string> mapSettingCodeToSettingType = {
        { TOUCHPAD_SCROLL_SETTING, "TOUCHPAD_SCROLL_SETTING" },
        { TOUCHPAD_SCROLL_DIR_SETTING, "TOUCHPAD_SCROLL_DIR_SETTING" },
        { TOUCHPAD_TAP_SETTING, "TOUCHPAD_TAP_SETTING" },
        { TOUCHPAD_SWIPE_SETTING, "TOUCHPAD_SWIPE_SETTING" },
        { TOUCHPAD_PINCH_SETTING, "TOUCHPAD_PINCH_SETTING" },
        { TOUCHPAD_DOUBLE_TAP_DRAG_SETTING, "TOUCHPAD_DOUBLE_TAP_DRAG_SETTING" },
    };

    auto it = mapSettingCodeToSettingType.find(settingCode);
    if (it == mapSettingCodeToSettingType.end()) {
        MMI_HILOGE("HiviewDFX Report touchpad setting state is error, setting code is invalid");
        return;
    }
    std::string name = it->second;

    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        name,
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "SWITCH_STATE", flag);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
    MMI_HILOGI("HiviewDFX Report touchpad setting code is:%{public}s, setting state is:%{public}s",
        (it->second).c_str(), flag ? "true" : "false");
}

void DfxHisysevent::ReportTouchpadSettingState(TOUCHPAD_SETTING_CODE settingCode, int32_t value)
{
    const std::map<uint32_t, std::string> mapSettingCodeToSettingType = {
        { TOUCHPAD_POINTER_SPEED_SETTING, "TOUCHPAD_POINTER_SPEED_SETTING" },
        { TOUCHPAD_RIGHT_CLICK_SETTING, "TOUCHPAD_RIGHT_CLICK_SETTING" },
    };

    auto it = mapSettingCodeToSettingType.find(settingCode);
    if (it == mapSettingCodeToSettingType.end()) {
        MMI_HILOGW("HiviewDFX Report touchpad setting state is error, setting code is invalid");
        return;
    }
    std::string name = it->second;

    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        name,
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "SWITCH_VALUE", value);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
    MMI_HILOGI("HiviewDFX Report touchpad setting code is:%{public}s, setting state is:%{public}d",
        (it->second).c_str(), value);
}

void DfxHisysevent::ReportSingleKnuckleDoubleClickEvent(int32_t intervalTime, int32_t distanceInterval)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "SK_S_T", FINGERSENSE_EVENT_TIMES,
        "SKS_T_I", intervalTime / CONVERSION_US_TO_MS,
        "DKS_D_I", distanceInterval,
        "TP_INFO", GetTpVendorName(),
        "S_INFO", GetAccVendorName(),
        "LCD_INFO", GetLcdInfo());
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportFailIfInvalidTime(const std::shared_ptr<PointerEvent> touchEvent, int32_t intervalTime)
{
    if (intervalTime >= DOWN_TO_PREV_UP_MAX_TIME_THRESHOLD) {
        return;
    }
    CHKPV(touchEvent);
    size_t size = touchEvent->GetPointerIds().size();
    std::string knuckleFailCount;
    std::string invalidTimeFailCount;
    if (size == SINGLE_KNUCKLE_SIZE) {
        knuckleFailCount = "SKF_T_I";
        invalidTimeFailCount = "SK_F_T";
    } else if (size == DOUBLE_KNUCKLE_SIZE) {
        knuckleFailCount = "DKF_T_I";
        invalidTimeFailCount = "DK_F_T";
    } else {
        MMI_HILOGE("HiviewDFX Report knuckle state error, knuckle size:%{public}zu", size);
        return;
    }
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "FSF_T_C", FINGERSENSE_EVENT_TIMES,
        knuckleFailCount, intervalTime / CONVERSION_US_TO_MS,
        invalidTimeFailCount, FINGERSENSE_EVENT_TIMES,
        "TP_INFO", GetTpVendorName(),
        "S_INFO", GetAccVendorName(),
        "LCD_INFO", GetLcdInfo());
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportFailIfInvalidDistance(const std::shared_ptr<PointerEvent> touchEvent, float distance)
{
    CHKPV(touchEvent);
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "SK_F_T", FINGERSENSE_EVENT_TIMES,
        "DKF_D_I", distance,
        "FSF_D_C", FINGERSENSE_EVENT_TIMES,
        "TP_INFO", GetTpVendorName(),
        "S_INFO", GetAccVendorName(),
        "LCD_INFO", GetLcdInfo());
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportKnuckleClickEvent()
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::INPUT_UE,
        "KNUCKLE_CLICK",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "PNAMEID", EMPTY_STRING,
        "PVERSIONID", EMPTY_STRING);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportScreenCaptureGesture()
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::INPUT_UE,
        "SINGLE_KNUCKLE_DOUBLE_CLICK",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "PNAMEID", EMPTY_STRING,
        "PVERSIONID", EMPTY_STRING);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
void DfxHisysevent::ReportMagicCursorColorChange(std::string fill_Color, std::string stroke_Color)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "MAGIC_CURSOR_COLOR",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "FILL_COLOR", fill_Color,
        "STROKE_COLOR", stroke_Color);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportMagicCursorShapeChange(std::string fill_Code, OHOS::MMI::MOUSE_ICON mouse_Style)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "MAGIC_CURSOR_SHAPE",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "MOUSE_STYLE", mouse_Style,
        "FILL_CODE", fill_Code);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportMagicCursorSizeChange(std::string fill_Code, std::string mouse_Size)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "MAGIC_CURSOR_SIZE",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "MOUSE_SIZE", mouse_Size,
        "FILL_CODE", fill_Code);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportMagicCursorFault(std::string error_Code, std::string error_Name)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FANTASY_CURSOR_FAILED",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "ERROR_CODE", error_Code,
        "ERROR_NAME", error_Name);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR

void DfxHisysevent::ReportSmartShotSuccTimes()
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "RG_S_T", FINGERSENSE_EVENT_TIMES,
        "TP_INFO", GetTpVendorName(),
        "S_INFO", GetAccVendorName(),
        "LCD_INFO", GetLcdInfo());
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportKnuckleGestureTrackLength(int32_t knuckleGestureTrackLength)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "RG_TRACK_LENGTH", knuckleGestureTrackLength,
        "TP_INFO", GetTpVendorName(),
        "S_INFO", GetAccVendorName(),
        "LCD_INFO", GetLcdInfo());
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportKnuckleGestureTrackTime(const std::vector<int64_t> &gestureTimeStamps)
{
    size_t size = gestureTimeStamps.size();
    if (size < MIN_GESTURE_TIMESTAMPS_SIZE) {
        MMI_HILOGE("HiviewDFX Report knuckle gesture track time error, knuckle timestamps size:%{public}zu", size);
        return;
    }
    int32_t knuckleGestureTrackTime = (gestureTimeStamps[size - 1] - gestureTimeStamps[0]) / CONVERSION_US_TO_MS;
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "RG_TRACK_TIME", knuckleGestureTrackTime,
        "TP_INFO", GetTpVendorName(),
        "S_INFO", GetAccVendorName(),
        "LCD_INFO", GetLcdInfo());
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportScreenRecorderGesture(int32_t intervalTime)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "DK_S_T", FINGERSENSE_EVENT_TIMES,
        "DKS_T_I", intervalTime / CONVERSION_US_TO_MS,
        "TP_INFO", GetTpVendorName(),
        "S_INFO", GetAccVendorName(),
        "LCD_INFO", GetLcdInfo());
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportKnuckleGestureFaildTimes()
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "LG_F_T", FINGERSENSE_EVENT_TIMES,
        "TP_INFO", GetTpVendorName(),
        "S_INFO", GetAccVendorName(),
        "LCD_INFO", GetLcdInfo());
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportKnuckleDrawSSuccessTimes()
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "L_S_S_T", FINGERSENSE_EVENT_TIMES,
        "TP_INFO", GetTpVendorName(),
        "S_INFO", GetAccVendorName(),
        "LCD_INFO", GetLcdInfo());
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportKnuckleGestureFromFailToSuccessTime(int32_t intervalTime)
{
    intervalTime /= CONVERSION_US_TO_MS;
    if (intervalTime < 0 || intervalTime >= FAIL_SUCC_TIME_DIFF) {
        return;
    }
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "RG_F_S_TIME_DIFF", intervalTime,
        "TP_INFO", GetTpVendorName(),
        "S_INFO", GetAccVendorName(),
        "LCD_INFO", GetLcdInfo());
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportKnuckleGestureFromSuccessToFailTime(int32_t intervalTime)
{
    intervalTime /= CONVERSION_US_TO_MS;
    if (intervalTime < 0 || intervalTime >= FAIL_SUCC_TIME_DIFF) {
        return;
    }
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "RG_S_F_TIME_DIFF", intervalTime,
        "TP_INFO", GetTpVendorName(),
        "S_INFO", GetAccVendorName(),
        "LCD_INFO", GetLcdInfo());
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportFailIfKnockTooFast()
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "SK_F_T", FINGERSENSE_EVENT_TIMES,
        "FSF_C_C", FINGERSENSE_EVENT_TIMES,
        "TP_INFO", GetTpVendorName(),
        "S_INFO", GetAccVendorName(),
        "LCD_INFO", GetLcdInfo());
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportFailIfOneSuccTwoFail(const std::shared_ptr<PointerEvent> touchEvent)
{
    CHKPV(touchEvent);
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    if (item.GetToolType() == PointerEvent::TOOL_TYPE_KNUCKLE) {
        return;
    }
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "SK_F_T", FINGERSENSE_EVENT_TIMES,
        "FSF_1S_2F_C", FINGERSENSE_EVENT_TIMES,
        "TP_INFO", GetTpVendorName(),
        "S_INFO", GetAccVendorName(),
        "LCD_INFO", GetLcdInfo());
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

std::string DfxHisysevent::GetTpVendorName()
{
    if (ROTATE_POLICY != FOLDABLE_DEVICE) {
        return GetVendorInfo(TP_PATH);
    }
    auto displayMode = WIN_MGR->GetDisplayMode();
    if (displayMode == DisplayMode::FULL) {
        return GetVendorInfo(TP0_PATH);
    } else if (displayMode == DisplayMode::MAIN) {
        return GetVendorInfo(TP1_PATH);
    }
    return "NA";
}

std::string DfxHisysevent::GetAccVendorName()
{
    if (ROTATE_POLICY != FOLDABLE_DEVICE) {
        return GetVendorInfo(ACC_PATH);
    }
    return GetVendorInfo(ACC0_PATH);
}

std::string DfxHisysevent::GetLcdInfo()
{
    return GetVendorInfo(LCD_PATH);
}

void DfxHisysevent::ReportSubscribeKeyEvent(int32_t subscribeId, int32_t finalKey,
    std::string name, int32_t pid)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "SUBSCRIBE_KEY_EVENT",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "SUBSCRIBE_ID", subscribeId,
        "FINAL_KEY", finalKey,
        "NAME", name,
        "PID", pid);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportUnSubscribeKeyEvent(int32_t subscribeId, int32_t finalKey,
    std::string name, int32_t pid)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "UNSUBSCRIBE_KEY_EVENT",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "SUBSCRIBE_ID", subscribeId,
        "FINAL_KEY", finalKey,
        "NAME", name,
        "PID", pid);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportKeyboardEvent(int32_t eventType, int32_t keyCode, int32_t keyAction)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "KAYBOARD_EVENT",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "KEY_EVENT_TYPE", eventType,
        "KEY_CODE", keyCode,
        "KEY_ACTION", keyAction);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportLaunchAbility(std::string bundleName)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "LAUNCH_ABILITY",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "BUNDLE_NAME", bundleName);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportCommonAction(std::string action)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "COMMON_ACTION",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "ACTION", action);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportTouchEvent(int32_t pointAction, int32_t pointId, int32_t windowId)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "TOUCH_EVENT",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "POINT_ACTION", pointAction,
        "POINT_ID", pointId,
        "WINDOW_ID", windowId);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportSetCustomCursor(int32_t windowPid, int32_t windowId)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "SET_CUSTOM_CURSOR",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "WINDOW_PID", windowPid,
        "WINDOW_ID", windowId);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportSetMouseIcon(int32_t windowId)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "SET_MOUSE_ICON",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "WINDOW_ID", windowId);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportSetPointerStyle(int32_t windowId, int32_t pointerStyleId, bool isUiExtension)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "SET_POINTER_STYLE",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "WINDOW_ID", windowId,
        "POINTER_STYLE_ID", pointerStyleId,
        "IS_UIEXTENSION", isUiExtension);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportSetPointerVisible(bool visible, int32_t priority)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "SET_POINTER_VISIBLE",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "VISIBLE", visible,
        "PRIORITY", priority);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportSetPointerSpeed(int32_t speed)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "SET_POINTER_SPEED",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "SPEED", speed);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportAddInputHandler(int32_t handlerType)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "ADD_INPUT_HANDLER",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "INPUT_HANDLER_TYPE", handlerType);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportRemoveInputHandler(int32_t handlerType)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "REMOVE_INPUT_HANDLER",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "INPUT_HANDLER_TYPE", handlerType);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportInjectPointerEvent(bool isNativeInject)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "INJECT_POINTER_EVENT",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "IS_NATIVE_INJECT", isNativeInject);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportEnableCombineKey(bool enable)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "ENABLE_COMBINE_KEY",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "ENABLE", enable);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportAppendExtraData()
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "APPEND_EXTRA_DATA",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportTransmitInfrared(int64_t number)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "APPEND_EXTRA_DATA",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "ENABLE", number);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportSetCurrentUser(int32_t userId)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "SET_CURRENT_USER",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "USER_ID", userId);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
void DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api api, int32_t durationMS)
{
    apiDurationStatics_.RecordDuration(api, durationMS);
    if (!apiDurationStatics_.IsLimitMatched()) {
        return;
    }
    static std::vector<std::string> apiDurationBox { "<=3MS", "<=5MS", "<=10MS", ">10MS" };
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "EXTERNAL_CALL_STATISTIC",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "API_DURATION_BOX", apiDurationBox,
        "IS_SCREEN_CAPTURE_WORKING",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::IS_SCREEN_CAPTURE_WORKING),
        "GET_DEFAULT_DISPLAY",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::GET_DEFAULT_DISPLAY),
        "GET_SYSTEM_ABILITY_MANAGER",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::GET_SYSTEM_ABILITY_MANAGER),
        "IS_FOLDABLE",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::IS_FOLDABLE),
        "IS_SCREEN_LOCKED",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::IS_SCREEN_LOCKED),
        "RS_NOTIFY_TOUCH_EVENT",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::RS_NOTIFY_TOUCH_EVENT),
        "RESOURCE_SCHEDULE_REPORT_DATA",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::RESOURCE_SCHEDULE_REPORT_DATA),
        "GET_CUR_RENDERER_CHANGE_INFOS",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::GET_CUR_RENDERER_CHANGE_INFOS),
        "GET_PROC_RUNNING_INFOS_BY_UID",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::GET_PROC_RUNNING_INFOS_BY_UID),
        "TELEPHONY_CALL_MGR_INIT",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::TELEPHONY_CALL_MGR_INIT),
        "TELEPHONY_CALL_MGR_MUTE_RINGER",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::TELEPHONY_CALL_MGR_MUTE_RINGER),
        "TELEPHONY_CALL_MGR_HANG_UP_CALL",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::TELEPHONY_CALL_MGR_HANG_UP_CALL),
        "TELEPHONY_CALL_MGR_REJECT_CALL",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::TELEPHONY_CALL_MGR_REJECT_CALL),
        "RE_SCREEN_MODE_CHANGE_LISTENER",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::RE_SCREEN_MODE_CHANGE_LISTENER),
        "SET_ON_REMOTE_DIED_CALLBACK",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::SET_ON_REMOTE_DIED_CALLBACK),
        "REG_SCREEN_CAPTURE_LISTENER",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::REG_SCREEN_CAPTURE_LISTENER),
        "ABILITY_MGR_START_EXT_ABILITY",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::ABILITY_MGR_START_EXT_ABILITY),
        "ABILITY_MGR_CLIENT_START_ABILITY",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::ABILITY_MGR_CLIENT_START_ABILITY),
        "ABILITY_MGR_CONNECT_ABILITY",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::ABILITY_MGR_CONNECT_ABILITY),
        "GET_RUNNING_PROCESS_INFO_BY_PID",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::GET_RUNNING_PROCESS_INFO_BY_PID),
        "REGISTER_APP_DEBUG_LISTENER",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::REGISTER_APP_DEBUG_LISTENER),
        "UNREGISTER_APP_DEBUG_LISTENER",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::UNREGISTER_APP_DEBUG_LISTENER),
        "PUBLISH_COMMON_EVENT",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::PUBLISH_COMMON_EVENT),
        "GET_VISIBILITY_WINDOW_INFO",
            apiDurationStatics_.GetDurationDistribution(ApiDurationStatistics::Api::GET_VISIBILITY_WINDOW_INFO)
        );
    apiDurationStatics_.ResetApiStatistics();
}

void DfxHisysevent::ReportMMiServiceThreadLongTask(const std::string &taskName)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "MMI_LONG_TASK",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "TASK_NAME", taskName);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}
#endif // OHOS_BUILD_ENABLE_DFX_RADAR

void DfxHisysevent::ClearKeyEventCount()
{
    calKeyEventTime_.clear();
    keyEventCount_ = 0;
}

void DfxHisysevent::ReportKeyEvent(std::string name)
{
    if (name == NAME_FILTER) {
        ReportKeyEventTimes(KEY_FILTER);
    } else if (name == NAME_INTERCEPT) {
        ReportKeyEventTimes(KEY_INTERCEPT);
    } else if (name == NAME_SUBCRIBER) {
        ReportKeyEventTimes(KEY_SUBCRIBER);
    } else if (name == NAME_FINGERPRINT) {
        ReportKeyEventTimes(FINGERPRINT);
    } else if (name == NAME_STYLUS) {
        ReportKeyEventTimes(STYLUS_PEN);
    } else if (name == BUNDLE_NAME_PARSER.GetBundleName("AIBASE_BUNDLE_NAME")) {
        ReportKeyEventTimes(AIBASE_VOICE);
    } else if (name == BUNDLE_NAME_PARSER.GetBundleName("SCREENSHOT_BUNDLE_NAME")) {
        ReportKeyEventTimes(SCREEN_SHOT);
    } else if (name == BUNDLE_NAME_PARSER.GetBundleName("SCREENRECORDER_BUNDLE_NAME")) {
        ReportKeyEventTimes(SCREEN_RECORDING);
    } else if (name == BUNDLE_NAME_PARSER.GetBundleName("WALLET_BUNDLE_NAME")) {
        ReportKeyEventTimes(OPEN_WALLET);
    } else if (name == BUNDLE_NAME_PARSER.GetBundleName("SOS_BUNDLE_NAME")) {
        ReportKeyEventTimes(OPEN_SOS);
    } else if (name == NAME_CANCEL) {
        ReportKeyEventTimes(KEY_EVENT_CANCEL);
    } else if (name == TOUCH_SCREEN_ON) {
        ReportKeyEventTimes(KEY_SCREEN_ON);
    } else {
        ReportKeyEventTimes(DISPATCH_KEY);
    }
}

void DfxHisysevent::ReportKeyEventTimes(KEY_CONSUMPTION_TYPE type)
{
    if (keyEventCount_ < REPORT_MAX_KEY_EVENT_TIMES) {
        keyEventCount_++;
        calKeyEventTime_[type]++;
    } else {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "KEY_EVENT_STATISTIC",
            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
            "DISPATCH_KEY", calKeyEventTime_[DISPATCH_KEY],
            "KEY_FILTER", calKeyEventTime_[KEY_FILTER],
            "KEY_INTERCEPT", calKeyEventTime_[KEY_INTERCEPT],
            "KEY_SUBCRIBER", calKeyEventTime_[KEY_SUBCRIBER],
            "FINGERPRINT", calKeyEventTime_[FINGERPRINT],
            "STYLUS_PEN", calKeyEventTime_[STYLUS_PEN],
            "AIBASE_VOICE", calKeyEventTime_[AIBASE_VOICE],
            "SCREEN_SHOT", calKeyEventTime_[SCREEN_SHOT],
            "SCREEN_RECORDING", calKeyEventTime_[SCREEN_RECORDING],
            "OPEN_WALLET", calKeyEventTime_[OPEN_WALLET],
            "OPEN_SOS", calKeyEventTime_[OPEN_SOS],
            "KEY_CANCEL", calKeyEventTime_[KEY_EVENT_CANCEL],
            "KEY_SCREEN_ON", calKeyEventTime_[KEY_SCREEN_ON]);
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
        ClearKeyEventCount();
    }
}

void DfxHisysevent::ReportFailLaunchAbility(std::string bundleName, int32_t errorCode)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "KEY_EVENT_FAULT",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "BUNDLE_NAME", bundleName,
        "ERROR_CODE", errorCode);
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportFailSubscribeKey(std::string functionName, std::string subscribeName,
    int32_t keyCode, int32_t errorCode)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "KEY_EVENT_FAULT",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "FUNCTION_NAME", functionName,
        "SUBSCRIBE_NAME", subscribeName,
        "KEY_CODE", keyCode,
        "ERROR_CODE", errorCode);
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportFailHandleKey(std::string name, int32_t keyCode, int32_t errorCode)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "KEY_EVENT_FAULT",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "FUNCTION_NAME", name,
        "KEY_CODE", keyCode,
        "ERROR_CODE", errorCode);
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportCallingMute()
{
    int32_t ret = HiSysEventWrite(
        WATCH_CROWN_MUTE,
        "CALL_UI_WATCH_CROWN_MUTE",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "PNAMEID", "",
        "PVERSIONID", "",
        "MUTE_TYPE", 1);
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportTouchpadKnuckleDoubleClickEvent(int32_t fingerCount)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::CLICKPAD_UE,
        fingerCount == 1 ? "FREETOUCH_GESTURE_KNUCKLE_SINGLE" : "FREETOUCH_GESTURE_KNUCKLE_DOUBLE",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportTouchpadLeftEdgeSlideEvent()
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::CLICKPAD_UE,
        "FREETOUCH_GES_LEFT_EDGE_SWIPE",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportTouchpadRightEdgeSlideEvent()
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::CLICKPAD_UE,
        "FREETOUCH_GES_RIGHT_EDGE_SWIPE",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}

void DfxHisysevent::ReportTouchpadSwipeInwardEvent()
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::CLICKPAD_UE,
        "CLICKPAD_GES_EDGE_INWARD_SWIPE",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC);
    if (ret != RET_OK) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
    }
}
} // namespace MMI
} // namespace OHOS