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

#include "input_event_stager.h"

#include "error_multimodal.h"
#include "mmi_log.h"
#include "input_handler_type.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEventStager"

namespace OHOS {
namespace MMI {
namespace {
constexpr long long STASH_EVENT_TIMEOUT_MS { 3000 };
}

InputEventStager &InputEventStager::GetInstance()
{
    static InputEventStager instance;
    return instance;
}

int32_t InputEventStager::UpdateKeyEvent(std::shared_ptr<KeyEvent> event)
{
    RemoveExpiredKeyEvent();
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    stashKeyEvents_.push_back({ event, GetNowMs() });
    return RET_OK;
}

int32_t InputEventStager::UpdateTouchEvent(std::shared_ptr<PointerEvent> event)
{
    RemoveExpiredTouchEvent();
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    stashTouchEvents_.push_back({ event, GetNowMs() });
    return RET_OK;
}

int32_t InputEventStager::UpdateMouseEvent(std::shared_ptr<PointerEvent> event)
{
    RemoveExpiredMouseEvent();
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    stashMouseEvents_.push_back({ event, GetNowMs() });
    return RET_OK;
}

std::shared_ptr<KeyEvent> InputEventStager::GetKeyEvent(int32_t eventId)
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    auto iter = std::find_if(stashKeyEvents_.begin(), stashKeyEvents_.end(), [eventId] (const auto &stashEvent) {
        CHKPF(stashEvent.event);
        return stashEvent.event->GetId() == eventId;
    });
    if (iter == stashKeyEvents_.end()) {
        return nullptr;
    }
    return iter->event;
}

std::shared_ptr<PointerEvent> InputEventStager::GetTouchEvent(int32_t eventId)
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    auto iter = std::find_if(stashTouchEvents_.begin(), stashTouchEvents_.end(), [eventId] (const auto &stashEvent) {
        CHKPF(stashEvent.event);
        return stashEvent.event->GetId() == eventId;
    });
    if (iter == stashTouchEvents_.end()) {
        return nullptr;
    }
    return iter->event;
}

std::shared_ptr<PointerEvent> InputEventStager::GetMouseEvent(int32_t eventId)
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    auto iter = std::find_if(stashMouseEvents_.begin(), stashMouseEvents_.end(), [eventId] (const auto &stashEvent) {
        CHKPF(stashEvent.event);
        return stashEvent.event->GetId() == eventId;
    });
    if (iter == stashMouseEvents_.end()) {
        return nullptr;
    }
    return iter->event;
}

int32_t InputEventStager::RemoveExpiredKeyEvent()
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    stashKeyEvents_.erase(std::remove_if(stashKeyEvents_.begin(),
        stashKeyEvents_.end(), [now = GetNowMs()] (const auto &elem) {
            return now - elem.timeStampRcvd >= STASH_EVENT_TIMEOUT_MS;
        }), stashKeyEvents_.end());
    return RET_OK;
}

int32_t InputEventStager::RemoveExpiredTouchEvent()
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    stashTouchEvents_.erase(std::remove_if(stashTouchEvents_.begin(),
        stashTouchEvents_.end(), [now = GetNowMs()] (const auto &elem) {
            return now - elem.timeStampRcvd >= STASH_EVENT_TIMEOUT_MS;
        }), stashTouchEvents_.end());
    return RET_OK;
}

int32_t InputEventStager::RemoveExpiredMouseEvent()
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    stashMouseEvents_.erase(std::remove_if(stashMouseEvents_.begin(),
        stashMouseEvents_.end(), [now = GetNowMs()] (const auto &elem) {
            return now - elem.timeStampRcvd >= STASH_EVENT_TIMEOUT_MS;
        }), stashMouseEvents_.end());
    return RET_OK;
}

void InputEventStager::ClearStashEvents(HookEventType hookEventType)
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (hookEventType & HOOK_EVENT_TYPE_KEY) {
        stashKeyEvents_.clear();
    }
    if (hookEventType & HOOK_EVENT_TYPE_TOUCH) {
        stashTouchEvents_.clear();
    }
    if (hookEventType & HOOK_EVENT_TYPE_MOUSE) {
        stashMouseEvents_.clear();
    }
}

long long InputEventStager::GetNowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
} // namespace MMI
} // namespace OHOS