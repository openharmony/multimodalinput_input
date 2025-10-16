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

#include "input_event_hook.h"

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_event_data_transformation.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEventHook"

namespace OHOS {
namespace MMI {

bool InputEventHook::OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    return false;
}

bool InputEventHook::OnPointerEvent(std::shared_ptr<PointerEvent> mouseEvent)
{
    return false;
}

int32_t InputEventHook::DispatchToNextHandler(const std::shared_ptr<KeyEvent> keyEvent)
{
    return RET_OK;
}

int32_t InputEventHook::DispatchToNextHandler(const std::shared_ptr<PointerEvent> pointerEvent)
{
    return RET_OK;
}

bool InputEventHook::SendNetPacketToHook(NetPacket &pkt)
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    CHKPF(session_);
    if (!session_->SendMsg(pkt)) {
        MMI_HILOGE("Send to hook:%{public}d failed", session_->GetPid());
        return false;
    }
    return true;
}

std::shared_ptr<InputEventHook> InputEventHook::GetNextHook()
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    auto selfPtr = shared_from_this();
    CHKPP(nextHookGetter_);
    if (auto nextHook = nextHookGetter_(selfPtr); nextHook != nullptr) {
        MMI_HILOGD("GetNextHook success");
        return nextHook;
    }
    MMI_HILOGD("No next hook existed");
    return nullptr;
}

HookEventType InputEventHook::GetHookEventType()
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    return hookEventType_;
}

int32_t InputEventHook::GetHookPid()
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    CHKPR(session_, RET_ERR);
    return session_->GetPid();
}

std::string InputEventHook::GetProgramName()
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    if (session_ == nullptr) {
        return "default";
    }
    return session_->GetProgramName();
}
} // namespace MMI
} // namespace OHOS