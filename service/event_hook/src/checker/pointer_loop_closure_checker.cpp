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

#include "pointer_loop_closure_checker.h"

#include "define_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerLoopClosureChecker"

namespace OHOS {
namespace MMI {

int32_t PointerLoopClosureChecker::ClosureChecker::HandleDown(int32_t flag)
{
    return UpdatePendingDownFlags(flag);
}

int32_t PointerLoopClosureChecker::ClosureChecker::HandleUpOrCancel(int32_t flag)
{
    if (CheckLoopClosure(flag) != RET_OK) {
        MMI_HILOGW("CheckLoopClosure of flag:%{private}d failed", flag);
        return RET_ERR;
    }
    if (RemovePendingDownFlags(flag) != RET_OK) {
        MMI_HILOGW("RemovePendingDownFlags of flag:%{private}d failed", flag);
        return RET_ERR;
    }
    MMI_HILOGD("HandleUpOrCancel of flag:%{private}d success", flag);
    return RET_OK;
}

int32_t PointerLoopClosureChecker::ClosureChecker::HandleMove(int32_t flag)
{
    if (CheckLoopClosure(flag) != RET_OK) {
        MMI_HILOGW("CheckLoopClosure of flag:%{private}d failed", flag);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t PointerLoopClosureChecker::ClosureChecker::CheckLoopClosure(int32_t flag)
{
    CALL_DEBUG_ENTER;
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    if (pendingFlags_.find(flag) == pendingFlags_.end()) {
        MMI_HILOGW("No pending down flag:%{private}d existed", flag);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t PointerLoopClosureChecker::ClosureChecker::UpdatePendingDownFlags(int32_t flag)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    pendingFlags_.insert(flag);
    return RET_OK;
}

int32_t PointerLoopClosureChecker::ClosureChecker::RemovePendingDownFlags(int32_t flag)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (pendingFlags_.find(flag) == pendingFlags_.end()) {
        MMI_HILOGW("No pending down flag:%{private}d  existed", flag);
        return RET_ERR;
    }
    pendingFlags_.erase(flag);
    return RET_OK;
}

int32_t PointerLoopClosureChecker::CheckAndUpdateEventLoopClosure(std::shared_ptr<PointerEvent> event)
{
    CHKPR(event, RET_ERR);
    auto sourceType = event->GetSourceType();
    if (auto sourceType = event->GetSourceType();
        sourceType == PointerEvent::SOURCE_TYPE_MOUSE || sourceType == PointerEvent::SOURCE_TYPE_TOUCHPAD) {
        return HandleMouseEvent(event);
    } else if (sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        return HandleTouchEvent(event);
    } else {
        MMI_HILOGW("Unsupported sourceType:%{public}d", sourceType);
    }
    return RET_ERR;
}

int32_t PointerLoopClosureChecker::HandleMouseEvent(std::shared_ptr<PointerEvent> event)
{
    auto flag = event->GetButtonId();
    if (flag == PointerEvent::BUTTON_NONE) {
        return RET_OK;
    }
    auto action = event->GetPointerAction();
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    if (action == PointerEvent::POINTER_ACTION_MOVE || action == PointerEvent::POINTER_ACTION_PULL_MOVE) {
        return closureChecker_.HandleMove(flag);
    } else if (action == PointerEvent::POINTER_ACTION_BUTTON_DOWN) {
        return closureChecker_.HandleDown(flag);
    } else if (action == PointerEvent::POINTER_ACTION_BUTTON_UP || action == PointerEvent::POINTER_ACTION_CANCEL) {
        return closureChecker_.HandleUpOrCancel(flag);
    } else {
        MMI_HILOGW("Unsupported action:%{public}d, skip check", action);
    }
    return RET_OK;
}

int32_t PointerLoopClosureChecker::HandleTouchEvent(std::shared_ptr<PointerEvent> event)
{
    auto flag = event->GetPointerId();
    auto action = event->GetPointerAction();
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    if (action == PointerEvent::POINTER_ACTION_MOVE || action == PointerEvent::POINTER_ACTION_PULL_MOVE) {
        return closureChecker_.HandleMove(flag);
    } else if (action == PointerEvent::POINTER_ACTION_DOWN) {
        return closureChecker_.HandleDown(flag);
    } else if (action == PointerEvent::POINTER_ACTION_UP || action == PointerEvent::POINTER_ACTION_CANCEL) {
        return closureChecker_.HandleUpOrCancel(flag);
    } else {
        MMI_HILOGW("Unsupported action:%{public}d, skip check", action);
    }
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS