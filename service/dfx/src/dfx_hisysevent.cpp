/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "dfx_hisysevent.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "DfxHisysevent" };
} // namespace

void DfxHisysevent::InputDeviceConnection(int32_t id, OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    std::shared_ptr dev = InputDevMgr->GetInputDevice(id);
    std::string message = "";
    std::string name = "";
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::FAULT) {
        message = "The input_device connection failed for already existing";
        name = "INPUT_DEV_CONNECTION_FAILURE";
    } else {
        message = "The input_device connection succeed";
        name = "INPUT_DEV_CONNECTION_SUCCESS";
    }
    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        name,
        type,
        "DEVICE_ID", id,
        "DEVICE_PHYS", dev->GetPhys(),
        "DEVICE_NAME", dev->GetName(),
        "DEVICE_TYPE", dev->GetType(),
        "MSG", message);
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }
}

void DfxHisysevent::InputDeviceConnection(void)
{
    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "INPUT_DEV_CONNECTION_FAILURE",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "MSG", "The input_device connection failed because the nextId_ exceeded the upper limit");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }
}

void DfxHisysevent::InputDeviceDisconnection(int32_t id)
{
    std::shared_ptr dev = InputDevMgr->GetInputDevice(id);
    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "INPUT_DEV_DISCONNECTION_SUCCESS",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "DEVICE_Id", id,
        "DEVICE_PHYS", dev->GetPhys(),
        "DEVICE_NAME", dev->GetName(),
        "DEVICE_TYPE", dev->GetType(),
        "MSG", "The input_device disconnection succeed");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }
}

void DfxHisysevent::InputDeviceDisconnection(void)
{
    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "INPUT_DEV_DISCONNECTION_FAILURE",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "MSG", "The input_device disconnection failed");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }
}

void DfxHisysevent::ClientConnectionEvent(const int32_t pid, const int32_t uid, const int32_t moduleType,
    const std::string &programName)
{
    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "CLIENT_CONNECTION_FAILURE",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "PID", pid,
        "UID", uid,
        "MODULETYPE", moduleType,
        "PROGRAMNAME", programName,
        "MSG", "The client_connection failed");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }
}

void DfxHisysevent::ClientConnectionEvent(const int32_t pid, const int32_t uid, const int32_t moduleType,
    const std::string &programName, const int32_t serverFd)
{
    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "CLIENT_CONNECTION_SUCCESS",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "PID", pid,
        "UID", uid,
        "MODULETYPE", moduleType,
        "FD", serverFd,
        "PROGRAMNAME", programName,
        "MSG", "The client_connection succeed");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }
}

void DfxHisysevent::ClientDisconnectionEvent(void)
{
    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "CLIENT_DISCONNECTION_FAILURE",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "MSG", "The client disconnection failed");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }
}

void DfxHisysevent::ClientDisconnectionEvent(const SessionPtr& secPtr, int32_t fd)
{
    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "CLIENT_DISCONNECTION_SUCCESS",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "PID", secPtr->GetPid(),
        "UID", secPtr->GetUid(),
        "MODULETYPE", secPtr->GetModuleType(),
        "FD", fd,
        "PROGRAMNAME", secPtr->GetProgramName(),
        "MSG", "The client disconnection succeeded");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }
}

void DfxHisysevent::TargetPointerEvent(std::shared_ptr<PointerEvent> pointer)
{
    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "TARGET_POINTER_EVENT_FAILURE",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "EVENTTYPE", pointer->GetEventType(),
        "MSG", "Calling UpdateTargetPointer failed");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }
}

void DfxHisysevent::TargetPointerEvent(std::shared_ptr<PointerEvent> pointer, int32_t fd)
{
    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "TARGET_POINTER_EVENT_SUCCESS",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "EVENTTYPE", pointer->GetEventType(),
        "AGENT_WINDOWID", pointer->GetAgentWindowId(),
        "TARGET_WINDOWID", pointer->GetTargetWindowId(),
        "PID", WinMgr->GetPidAndUpdateTarget(pointer),
        "FD", fd,
        "MSG", "Calling UpdateTargetPointer succeeded");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }
}

void DfxHisysevent::TargetKeyEvent(std::shared_ptr<KeyEvent> key)
{
    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "TARGET_KEY_EVENT_FAILURE",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "EVENTTYPE", key->GetEventType(),
        "KEYCODE", key->GetKeyCode(),
        "ACTION", key->GetAction(),
        "ACTION_TIME", key->GetActionTime(),
        "ACTION_STARTTIME", key->GetActionStartTime(),
        "FLAG", key->GetFlag(),
        "KEYACTION", key->GetKeyAction(),
        "MSG", "Calling UpdateTarget failed");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }
}

void DfxHisysevent::TargetKeyEvent(std::shared_ptr<KeyEvent> key, int32_t fd)
{
    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "TARGET_KEY_EVENT_SUCCESS",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
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
        "PID", WinMgr->GetPidAndUpdateTarget(key),
        "MSG", "Calling UpdateTarget succeeded");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }
}

void DfxHisysevent::FocusWindowChange(const DisplayGroupInfo& oldDisplayGroupInfo,
    const DisplayGroupInfo& newDisplayGroupInfo)
{
    const int32_t oldFocusWindowId = oldDisplayGroupInfo.focusWindowId;
    const int32_t newFocusWindowId = newDisplayGroupInfo.focusWindowId;
    int32_t oldFocusWindowPid = -1;
    int32_t newFocusWindowPid = -1;
    for (auto &item : oldDisplayGroupInfo.windowsInfo) {
        if (item.id == oldFocusWindowId) {
            oldFocusWindowPid = item.pid;
            break;
        }
    }
    for (auto &item : newDisplayGroupInfo.windowsInfo) {
        if (item.id == newFocusWindowId) {
            newFocusWindowPid = item.pid;
            break;
        }
    }
    if (oldFocusWindowId != newFocusWindowId) {
        int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "FOCUS_WINDOW_CHANGE",
            OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "OLD_FOCUS_WINDOWID", oldFocusWindowId,
            "NEW_FOCUS_WINDOWID", newFocusWindowId,
            "OLD_FOCUS_WINDOWPID", oldFocusWindowPid,
            "NEW_FOCUS_WINDOWPID", newFocusWindowPid,
            "MSG", "The focusWindowId changing succeeded");
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
        }
    }
}

void DfxHisysevent::ZorderWindowChange(const DisplayGroupInfo& oldDisplayGroupInfo,
    const DisplayGroupInfo& newDisplayGroupInfo)
{
    int32_t oldZorderFirstWindowId = -1;
    int32_t newZorderFirstWindowId = -1;
    int32_t oldZorderFirstWindowPid = -1;
    int32_t newZorderFirstWindowPid = -1;
    if (!oldDisplayGroupInfo.windowsInfo.empty()) {
        oldZorderFirstWindowId = oldDisplayGroupInfo.windowsInfo[0].id;
    }
    if (!newDisplayGroupInfo.windowsInfo.empty()) {
        newZorderFirstWindowId = newDisplayGroupInfo.windowsInfo[0].id;
    }
    for (auto &item : oldDisplayGroupInfo.windowsInfo) {
        if (item.id == oldZorderFirstWindowId) {
            oldZorderFirstWindowPid = item.pid;
            break;
        }
    }
    for (auto &item : newDisplayGroupInfo.windowsInfo) {
        if (item.id == newZorderFirstWindowId) {
            newZorderFirstWindowPid = item.pid;
            break;
        }
    }
    if (oldZorderFirstWindowId != newZorderFirstWindowId) {
        int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
            OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
            "Z_ORDER_WINDOW_CHANGE",
            OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "OLD_ZORDER_FIRST_WINDOWID", oldZorderFirstWindowId,
            "NEW_ZORDER_FIRST_WINDOWID", newZorderFirstWindowId,
            "OLD_ZORDER_FIRST_WINDOWPID", oldZorderFirstWindowPid,
            "NEW_ZORDER_FIRST_WINDOWPID", newZorderFirstWindowPid,
            "MSG", "The ZorderFirstWindow changing succeeded");
        if (ret != 0) {
            MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
        }
    }
}

void DfxHisysevent::ApplicationBlockInput(const SessionPtr& sess)
{
    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "APPLICATION_BLOCK_INPUT",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "PID", sess->GetPid(),
        "UID", sess->GetUid(),
        "PACKAGE_NAME", "",
        "PROCESS_NAME", "",
        "MSG", "User input does not respond");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }
}
}
}

