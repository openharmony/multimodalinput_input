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

#include "key_loop_closure_checker.h"

#include "define_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyLoopClosureChecker"

namespace OHOS {
namespace MMI {

int32_t KeyLoopClosureChecker::CheckAndUpdateEventLoopClosure(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPR(keyEvent, RET_ERR);
    auto keyAction = keyEvent->GetKeyAction();
    auto keyCode = keyEvent->GetKeyCode();
    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        return HandleEventLoopClosureKeyDown(keyCode);
    } else if (keyAction == KeyEvent::KEY_ACTION_UP || keyAction == KeyEvent::KEY_ACTION_CANCEL) {
        return HandleEventLoopClosureKeyUpOrCancel(keyCode);
    } else {
        MMI_HILOGW("Unsupported action:%{public}d", keyAction);
    }
    return RET_ERR;
}

int32_t KeyLoopClosureChecker::HandleEventLoopClosureKeyDown(int32_t keyCode)
{
    return UpdatePendingDownKeys(keyCode);
}

int32_t KeyLoopClosureChecker::HandleEventLoopClosureKeyUpOrCancel(int32_t keyCode)
{
    if (CheckLoopClosure(keyCode) != RET_OK) {
        MMI_HILOGW("CheckLoopClosure of key:%{private}d failed", keyCode);
        return RET_ERR;
    }
    if (RemovePendingDownKeys(keyCode) != RET_OK) {
        MMI_HILOGW("RemovePendingDownKeys of key:%{private}d failed", keyCode);
        return RET_ERR;
    }
    MMI_HILOGD("HandleKeyUpOrCancel of key:%{private}d success", keyCode);
    return RET_OK;
}

int32_t KeyLoopClosureChecker::CheckLoopClosure(int32_t keyCode)
{
    CALL_DEBUG_ENTER;
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    if (pendingDownKeys_.find(keyCode) == pendingDownKeys_.end()) {
        MMI_HILOGW("No pending down key:%{private}d existed", keyCode);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t KeyLoopClosureChecker::UpdatePendingDownKeys(int32_t keyCode)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    pendingDownKeys_.insert(keyCode);
    return RET_OK;
}

int32_t KeyLoopClosureChecker::RemovePendingDownKeys(int32_t keyCode)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (pendingDownKeys_.find(keyCode) == pendingDownKeys_.end()) {
        MMI_HILOGW("No pending down key:%{private}d  existed", keyCode);
        return RET_ERR;
    }
    pendingDownKeys_.erase(keyCode);
    return RET_OK;
}

} // namespace MMI
} // namespace OHOS