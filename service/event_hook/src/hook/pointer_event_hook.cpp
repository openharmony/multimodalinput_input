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

#include "pointer_event_hook.h"

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerEventHook"

namespace OHOS {
namespace MMI {
bool PointerEventHook::OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointerEvent);
    auto pkt = std::make_shared<NetPacket>(MmiMessageId::INVALID);
    auto sourceType = pointerEvent->GetSourceType();
    auto hookEventType = GetHookEventType();
    if (sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN && hookEventType == HOOK_EVENT_TYPE_TOUCH) {
        pkt = std::make_shared<NetPacket>(MmiMessageId::ON_HOOK_TOUCH_EVENT);
    } else if (sourceType == PointerEvent::SOURCE_TYPE_MOUSE && hookEventType == HOOK_EVENT_TYPE_MOUSE) {
        pkt = std::make_shared<NetPacket>(MmiMessageId::ON_HOOK_MOUSE_EVENT);
    } else {
        MMI_HILOGE("Unsupported sourceType");
        return false;
    }
    CHKPF(pkt);
    if (pkt->ChkRWError()) {
        MMI_HILOGE("Packet write pointerEvent failed");
        return false;
    }
    if (InputEventDataTransformation::Marshalling(pointerEvent, *pkt) != RET_OK) {
        MMI_HILOGE("Packet pointer event failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return false;
    }
    if (!SendNetPacketToHook(*pkt)) {
        MMI_HILOGE("SendNetPacketToHook failed");
        return false;
    }
    expirationChecker_.UpdateInputEvent(pointerEvent);
    return true;
}

int32_t PointerEventHook::DispatchToNextHandler(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, RET_ERR);
    auto eventId = pointerEvent->GetId();
    if (!expirationChecker_.CheckValid(pointerEvent) || !expirationChecker_.CheckExpiration(eventId)) {
        MMI_HILOGW("CheckValid failed or CheckExpiration failed");
        return ERROR_INVALID_PARAMETER;
    }
    if (!orderChecker_.CheckOrder(eventId)) {
        MMI_HILOGW("CheckOrder failed");
        return ERROR_INVALID_PARAMETER;
    }
    if (closureChecker_.CheckAndUpdateEventLoopClosure(pointerEvent) != RET_OK) {
        MMI_HILOGW("CheckAndUpdateEventLoopClosure failed, eventId:%{public}d", eventId);
        return RET_OK;
    }
    bool ret { false };
    if (auto nextHook = GetNextHook(); nextHook != nullptr) {
        ret =  nextHook->OnPointerEvent(pointerEvent);
    } else {
        ret = DispatchDirectly(pointerEvent);
    }
    orderChecker_.UpdateEvent(eventId);
    MMI_HILOGD("DispatchToNextHandler res:%{public}s", ret ? "success" : "failed");
    return ret ? RET_OK : RET_ERR;
}

bool PointerEventHook::DispatchDirectly(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointerEvent);
    auto eventDispatchHandler = InputHandler->GetEventDispatchHandler();
    CHKPF(eventDispatchHandler);
    int32_t sourceType = pointerEvent->GetSourceType();
    if (sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        eventDispatchHandler->HandleTouchEvent(pointerEvent);
    } else if (sourceType == PointerEvent::SOURCE_TYPE_MOUSE) {
        eventDispatchHandler->HandlePointerEvent(pointerEvent);
    } else {
        MMI_HILOGW("Unsupported sourceType:%{public}d", sourceType);
    }
    MMI_HILOGD("Dispatch directly, id:%{public}d", pointerEvent->GetId());
    return true;
}
} // namespace MMI
} // namespace OHOS