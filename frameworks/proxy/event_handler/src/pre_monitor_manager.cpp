/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "pre_monitor_manager.h"

#include "bytrace_adapter.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PreMonitorManager"

namespace OHOS {
namespace MMI {
namespace {
static const std::vector<int32_t> supportedKeyCodes = {
    KeyEvent::KEYCODE_POWER,
    KeyEvent::KEYCODE_META_LEFT,
    KeyEvent::KEYCODE_VOLUME_UP,
    KeyEvent::KEYCODE_VOLUME_DOWN,
    KeyEvent::KEYCODE_META_RIGHT,
    KeyEvent::KEYCODE_FUNCTION,
    KeyEvent::KEYCODE_KEY_PEN_AIR_MOUSE
};
} // namespace
PreMonitorManager::PreMonitorManager() {}
PreMonitorManager::~PreMonitorManager() {}

int32_t PreMonitorManager::AddHandler(
    std::shared_ptr<IInputEventConsumer> consumer, HandleEventType eventType, std::vector<int32_t> keys)
{
    CALL_DEBUG_ENTER;
    for (auto& keycode : keys) {
        if (std::find(supportedKeyCodes.begin(), supportedKeyCodes.end(), keycode) == supportedKeyCodes.end()) {
            MMI_HILOGE("PreKeys is not expect");
            return RET_ERR;
        }
    }
    CHKPR(consumer, INVALID_HANDLER_ID);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    std::lock_guard<std::mutex> guard(mtxHandlers_);
    int32_t handlerId = GetNextId();
    if (RET_OK == AddLocal(handlerId, eventType, keys, consumer)) {
        MMI_HILOGD("New handler successfully registered, report to server");
        int32_t ret = AddToServer(handlerId, eventType, keys);
        if (ret != RET_OK) {
            MMI_HILOGE("Add Handler to server failed");
            RemoveLocal(handlerId);
            return ret;
        }
        MMI_HILOGI("Finish add Handler");
    } else {
        MMI_HILOGE("Add Handler local failed");
        handlerId = INVALID_HANDLER_ID;
    }
    return handlerId;
}

int32_t PreMonitorManager::RemoveHandler(int32_t handlerId)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Unregister handler:%{public}d", handlerId);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    std::lock_guard<std::mutex> guard(mtxHandlers_);
    int32_t ret = RemoveLocal(handlerId);
    if (ret == RET_OK) {
        ret = RemoveFromServer(handlerId);
        if (ret != RET_OK) {
            return ret;
        }
        MMI_HILOGI("Remove Handler Succ");
    }
    return ret;
}

int32_t PreMonitorManager::AddLocal(int32_t handlerId, HandleEventType eventType, std::vector<int32_t> keys,
    std::shared_ptr<IInputEventConsumer> consumer)
{
    PreMonitorManager::Handler handler{
        .handlerId_ = handlerId,
        .eventType_ = eventType,
        .callback_ = consumer,
        .keys_ = keys,
    };
    auto ret = monitorHandlers_.emplace(handler.handlerId_, handler);
    if (!ret.second) {
        MMI_HILOGE("Duplicate handler:%{public}d", handler.handlerId_);
        return RET_ERR;
    }
    return RET_OK;
}
int32_t PreMonitorManager::AddToServer(int32_t handlerId, HandleEventType eventType, std::vector<int32_t> keys)
{
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->AddPreInputHandler(handlerId, eventType, keys);
    if (ret != RET_OK) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
    }
    return ret;
}
int32_t PreMonitorManager::RemoveLocal(int32_t handlerId)
{
    auto iter = monitorHandlers_.find(handlerId);
    if (iter == monitorHandlers_.end()) {
        MMI_HILOGE("No handler with specified");
        return RET_ERR;
    }
    monitorHandlers_.erase(iter);
    return RET_OK;
}

int32_t PreMonitorManager::RemoveFromServer(int32_t handlerId)
{
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->RemovePreInputHandler(handlerId);
    if (ret != 0) {
        MMI_HILOGE("RemoveFromServer failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t PreMonitorManager::GetNextId()
{
    if (nextId_ == std::numeric_limits<int32_t>::max()) {
        MMI_HILOGE("Exceeded limit of 32-bit maximum number of integers");
        return INVALID_HANDLER_ID;
    }
    return nextId_++;
}

HandleEventType PreMonitorManager::GetEventType() const
{
    uint32_t eventType{ HANDLE_EVENT_TYPE_NONE };
    if (monitorHandlers_.empty()) {
        MMI_HILOGD("The monitorHandlers_ is empty");
        return HANDLE_EVENT_TYPE_NONE;
    }
    for (const auto &inputHandler : monitorHandlers_) {
        eventType |= inputHandler.second.eventType_;
    }

    return eventType;
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void PreMonitorManager::OnPreKeyEvent(std::shared_ptr<KeyEvent> keyEvent, int32_t handlerId)
{
    CHK_PID_AND_TID();
    CHKPV(keyEvent);

    if (handlerId < 0) {
        MMI_HILOGE("Leave, the handler id is less than 0");
        return;
    }
    std::lock_guard<std::mutex> guard(mtxHandlers_);
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::KEY_DISPATCH_EVENT);
    for (const auto &item : monitorHandlers_) {
        if ((item.second.eventType_ & HANDLE_EVENT_TYPE_PRE_KEY) != HANDLE_EVENT_TYPE_PRE_KEY) {
            continue;
        }
        if (item.first == handlerId) {
            std::shared_ptr<IInputEventConsumer> consumer = item.second.callback_;
            CHKPV(consumer);
            consumer->OnInputEvent(keyEvent);
            MMI_HILOGD("Key event id:%{public}d keycode:%{private}d", handlerId, keyEvent->GetKeyCode());
            return;
        }
    }
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_MONITOR)
void PreMonitorManager::OnConnected()
{
    CALL_DEBUG_ENTER;
    for (const auto &inputHandler : monitorHandlers_) {
        int32_t handlerId = inputHandler.first;
        std::vector<int32_t> keys = inputHandler.second.keys_;
        AddToServer(handlerId, inputHandler.second.eventType_, keys);
    }
}
#endif // OHOS_BUILD_ENABLE_MONITOR

std::shared_ptr<IInputEventConsumer> PreMonitorManager::FindHandler(int32_t handlerId)
{
    auto iter = monitorHandlers_.find(handlerId);
    if (iter != monitorHandlers_.end()) {
        return iter->second.callback_;
    }
    return nullptr;
}
} // namespace MMI
} // namespace OHOS
