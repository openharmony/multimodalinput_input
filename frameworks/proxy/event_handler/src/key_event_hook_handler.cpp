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

#include "key_event_hook_handler.h"

#include "error_multimodal.h"
#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventHookHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr long long TIMEOUT_MS { 3000 };
}

KeyEventHookHandler &KeyEventHookHandler::GetInstance()
{
    static KeyEventHookHandler instance;
    return instance;
}

int32_t KeyEventHookHandler::AddKeyEventHook(std::function<void(std::shared_ptr<KeyEvent>)> callback, int32_t &hookId)
{
    CALL_INFO_TRACE;
    CHKPR(callback, INVALID_HANDLER_ID);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    SetHookCallback(callback);
    int32_t curHookId { -1 };
    if (int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->AddKeyEventHook(curHookId); ret != RET_OK) {
        MMI_HILOGE("AddKeyEventHook to server, ret:%{public}d", ret);
        hookId = -1;
        ResetHookCallback();
        return ret;
    }
    hookId = curHookId;
    RemoveAllPendingKeys();
    return RET_OK;
}

int32_t KeyEventHookHandler::RemoveKeyEventHook(int32_t hookId)
{
    CALL_INFO_TRACE;
    if (int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->RemoveKeyEventHook(hookId); ret != RET_OK) {
        MMI_HILOGE("RemoveKeyEventHook failed, ret:%{public}d", ret);
        return ret;
    }
    ResetHookCallback();
    RemoveAllPendingKeys();
    return RET_OK;
}

int32_t KeyEventHookHandler::DispatchToNextHandler(int32_t eventId)
{
    CALL_DEBUG_ENTER;
    UpdatePendingKeys();
    if (!IsValidEvent(eventId)) {
        MMI_HILOGE("DispatchToNextHandler failed, not valid event, maybe timeout");
        return ERROR_INVALID_PARAMETER;
    }
    if (int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->DispatchToNextHandler(eventId); ret != RET_OK) {
        MMI_HILOGE("DispatchToNextHandler failed, ret:%{public}d", ret);
        return ret;
    }
    RemoveExpiredPendingKeys(eventId);
    return RET_OK;
}

void KeyEventHookHandler::OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    MMI_HILOGD("EventId:%{public}d, kc:%{private}d, ka:%{public}d",
        keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetKeyAction());
    long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    AppendPendingKeys(keyEvent->GetId(), now);
    UpdatePendingKeys();
    auto hookCallback = GetHookCallback();
    CHKPV(hookCallback);
    hookCallback(keyEvent);
}

void KeyEventHookHandler::SetHookIdUpdater(std::function<void(int32_t)> callback)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    hookIdUpdater_ = callback;
}

std::function<void(int32_t)> KeyEventHookHandler::GetHookIdUpdater()
{
    CALL_DEBUG_ENTER;
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    return hookIdUpdater_;
}

void KeyEventHookHandler::SetHookCallback(std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    hookCallback_ = callback;
}

void KeyEventHookHandler::ResetHookCallback()
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    hookCallback_ = nullptr;
}

std::function<void(std::shared_ptr<KeyEvent>)> KeyEventHookHandler::GetHookCallback()
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    return hookCallback_;
}

void KeyEventHookHandler::UpdatePendingKeys()
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    while (!pendingKeys_.empty()) {
        if (auto head = pendingKeys_.front(); now - head.timeStampRcvd > TIMEOUT_MS) {
            pendingKeys_.pop_front();
            continue;
        }
        break;
    }
}

void KeyEventHookHandler::RemoveAllPendingKeys()
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    pendingKeys_.clear();
}

void KeyEventHookHandler::AppendPendingKeys(int32_t eventId, long long timeStamp)
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    pendingKeys_.push_back({eventId, timeStamp});
}

void KeyEventHookHandler::RemoveExpiredPendingKeys(int32_t eventId)
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    while (!pendingKeys_.empty()) {
        if (auto head = pendingKeys_.front(); head.eventId <= eventId) {
            pendingKeys_.pop_front();
            continue;
        }
        break;
    }
}

bool KeyEventHookHandler::IsValidEvent(int32_t eventId)
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    auto iter = std::find_if(pendingKeys_.begin(), pendingKeys_.end(),
        [eventId, now] (const auto &pendingKey) {
            if (pendingKey.eventId == eventId) {
                return now - pendingKey.timeStampRcvd < TIMEOUT_MS;
            }
            return false;
        }
    );
    return iter != pendingKeys_.end();
}

void KeyEventHookHandler::UpdateGlobalHookId(int32_t hookId)
{
    CALL_INFO_TRACE;
    auto hookIdUpdater = GetHookIdUpdater();
    CHKPV(hookIdUpdater);
    hookIdUpdater(hookId);
}

void KeyEventHookHandler::OnConnected()
{
    CALL_INFO_TRACE;
    if (auto hookCallback = GetHookCallback(); hookCallback == nullptr) {
        MMI_HILOGW("No hook added before");
        return;
    }
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return;
    }
    int32_t curHookId { -1 };
    if (int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->AddKeyEventHook(curHookId); ret != RET_OK) {
        MMI_HILOGE("AddKeyEventHook to server, ret:%{public}d", ret);
        ResetHookCallback();
        return;
    }
    UpdateGlobalHookId(curHookId);
}
} // namespace MMI
} // namespace OHOS
