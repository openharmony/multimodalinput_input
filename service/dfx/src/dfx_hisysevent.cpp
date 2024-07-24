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

#include "i_input_windows_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DfxHisysevent"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INVALID_DEVICE_ID { -1 };
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
const std::string EMPTY_STRING { "" };
const std::string LCD_PATH { "/sys/class/graphics/fb0/lcd_model" };
const std::string ACC_PATH { "/sys/devices/platform/_sensor/acc_info" };
const std::string TP_PATH { "/sys/touchscreen/touch_chip_info" };
} // namespace

static std::string GetVendorInfo(const std::string &nodePath)
{
    char realPath[PATH_MAX] = {};
    if (realpath(nodePath.c_str(), realPath) == nullptr) {
        MMI_HILOGE("The realpath return nullptr");
        return "";
    }
    std::ifstream file(realPath);
    if (!file.is_open()) {
        MMI_HILOGE("Unable to open file:%{public}s, error:%{public}d", nodePath.c_str(), errno);
        return "";
    }
    std::string vendorInfo;
    file >> vendorInfo;
    file.close();
    return vendorInfo;
}

void DfxHisysevent::OnDeviceConnect(int32_t id, OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    std::shared_ptr<InputDevice> dev = INPUT_DEV_MGR->GetInputDevice(id);
    CHKPV(dev);
    std::string message;
    std::string name;
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::FAULT) {
        message = "The input_device connection failed for already existing";
        name = "INPUT_DEV_CONNECTION_FAILURE";
    } else {
        message = "The input_device connection succeed";
        name = "INPUT_DEV_CONNECTION_SUCCESS";
    }
    if (id == INT32_MAX) {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            name,
            type,
            "MSG", "The input_device connection failed because the nextId_ exceeded the upper limit");
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    } else {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            name,
            type,
            "DEVICE_ID", id,
            "DEVICE_PHYS", dev->GetPhys(),
            "DEVICE_NAME", dev->GetName(),
            "DEVICE_TYPE", dev->GetType(),
            "MSG", message);
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    }
}

void DfxHisysevent::OnDeviceDisconnect(int32_t id, OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (id == INVALID_DEVICE_ID) {
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "INPUT_DEV_DISCONNECTION_FAILURE",
            type,
            "MSG", "The input device failed to disconnect to server");
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    } else {
        std::shared_ptr dev = INPUT_DEV_MGR->GetInputDevice(id);
        CHKPV(dev);
        int32_t ret = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "INPUT_DEV_DISCONNECTION_SUCCESS",
            type,
            "DEVICE_Id", id,
            "DEVICE_PHYS", dev->GetPhys(),
            "DEVICE_NAME", dev->GetName(),
            "DEVICE_TYPE", dev->GetType(),
            "MSG", "The input device successfully disconnect to server");
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d", ret);
        }
    }
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
    int64_t castTime = (endTime - dispatchStartTime_)  / CONVERSION_US_TO_MS;
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
    int64_t castTime = (endTime - dispatchStartTime_)  / CONVERSION_US_TO_MS;
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
        MMI_HILOGW("press power key is error");
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
}

void DfxHisysevent::ReportSingleKnuckleDoubleClickEvent(int32_t intervalTime, int32_t distanceInterval)
{
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "SK_S_T", FINGERSENSE_EVENT_TIMES,
        "SKS_T_I", intervalTime,
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
    if (intervalTime >= FAIL_SUCC_TIME_DIFF) {
        return;
    }
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "RG_S_F_TIME_DIFF", intervalTime / CONVERSION_US_TO_MS,
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
    if (intervalTime >= FAIL_SUCC_TIME_DIFF) {
        return;
    }
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "FINGERSENSE_KNOCK_EVENT_INFO",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "RG_F_S_TIME_DIFF", intervalTime / CONVERSION_US_TO_MS,
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

std::string DfxHisysevent::GetTpVendorName()
{
    return GetVendorInfo(TP_PATH);
}

std::string DfxHisysevent::GetAccVendorName()
{
    return GetVendorInfo(ACC_PATH);
}

std::string DfxHisysevent::GetLcdInfo()
{
    return GetVendorInfo(LCD_PATH);
}
} // namespace MMI
} // namespace OHOS