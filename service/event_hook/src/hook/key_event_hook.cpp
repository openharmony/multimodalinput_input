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

#include "key_event_hook.h"

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventHook"

namespace OHOS {
namespace MMI {
bool KeyEventHook::OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    NetPacket pkt(MmiMessageId::ON_HOOK_KEY_EVENT);
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write key event failed");
        return false;
    }
    if (InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt) != RET_OK) {
        MMI_HILOGE("Packet key event failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return false;
    }
    if (!SendNetPacketToHook(pkt)) {
        MMI_HILOGE("SendNetPacketToHook failed");
        return false;
    }
    expirationChecker_.UpdateInputEvent(keyEvent);
    return true;
}

int32_t KeyEventHook::DispatchToNextHandler(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPR(keyEvent, RET_ERR);
    auto eventId = keyEvent->GetId();
    if (!expirationChecker_.CheckValid(keyEvent) || !expirationChecker_.CheckExpiration(eventId)) {
        MMI_HILOGW("CheckValid failed or CheckExpiration failed");
        return ERROR_INVALID_PARAMETER;
    }
    if (!orderChecker_.CheckOrder(eventId)) {
        MMI_HILOGW("CheckOrder failed");
        return ERROR_INVALID_PARAMETER;
    }
    if (closureChecker_.CheckAndUpdateEventLoopClosure(keyEvent) != RET_OK) {
        MMI_HILOGW("CheckAndUpdateEventLoopClosure failed, eventId:%{public}d", eventId);
        return RET_OK;
    }
    bool ret { false };
    if (auto nextHook = GetNextHook(); nextHook != nullptr) {
        ret =  nextHook->OnKeyEvent(keyEvent);
    } else {
        ret = DispatchDirectly(keyEvent);
    }
    orderChecker_.UpdateEvent(eventId);
    MMI_HILOGD("DispatchToNextHandler res:%{public}s", ret ? "success" : "failed");
    return ret ? RET_OK : RET_ERR;
}

bool KeyEventHook::DispatchDirectly(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPF(udsServerPtr);
    auto dispatchHandler = InputHandler->GetEventDispatchHandler();
    CHKPF(dispatchHandler);
    if (dispatchHandler->DispatchKeyEventPid(*udsServerPtr, keyEvent) != RET_OK) {
        MMI_HILOGE("DispatchKeyEventPid failed");
        return false;
    }
    return true;
}
} // namespace MMI
} // namespace OHOS