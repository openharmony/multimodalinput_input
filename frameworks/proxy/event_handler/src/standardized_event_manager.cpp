/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "standardized_event_manager.h"

#include <sstream>

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "event_log_helper.h"
#include "net_packet.h"
#include "proto.h"
#include "util.h"

#include "input_event_data_transformation.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, MMI_LOG_DOMAIN, "StandardizedEventManager"
};
} // namespace

StandardizedEventManager::StandardizedEventManager() {}
StandardizedEventManager::~StandardizedEventManager() {}

void StandardizedEventManager::SetClientHandle(MMIClientPtr client)
{
    CALL_DEBUG_ENTER;
    client_ = client;
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t StandardizedEventManager::SubscribeKeyEvent(
    const KeyEventInputSubscribeManager::SubscribeKeyEventInfo &subscribeInfo)
{
    CALL_DEBUG_ENTER;
    return MultimodalInputConnMgr->SubscribeKeyEvent(subscribeInfo.GetSubscribeId(), subscribeInfo.GetKeyOption());
}

int32_t StandardizedEventManager::UnsubscribeKeyEvent(int32_t subscribeId)
{
    CALL_DEBUG_ENTER;
    return MultimodalInputConnMgr->UnsubscribeKeyEvent(subscribeId);
}

int32_t StandardizedEventManager::InjectEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_INFO_TRACE;
    CHKPR(keyEvent, RET_ERR);
    keyEvent->UpdateId();
    if (keyEvent->GetKeyCode() < 0) {
        MMI_HILOGE("KeyCode is invalid:%{public}u", keyEvent->GetKeyCode());
        return RET_ERR;
    }
    int32_t ret = MultimodalInputConnMgr->InjectKeyEvent(keyEvent);
    if (ret != 0) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
int32_t StandardizedEventManager::InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_INFO_TRACE;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    MMI_HILOGD("Inject pointer event:");
    EventLogHelper::PrintEventData(pointerEvent);
    int32_t ret = MultimodalInputConnMgr->InjectPointerEvent(pointerEvent);
    if (ret != 0) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
int32_t StandardizedEventManager::MoveMouseEvent(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
    int32_t ret = MultimodalInputConnMgr->MoveMouseEvent(offsetX, offsetY);
    if (ret != 0) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

bool StandardizedEventManager::SendMsg(NetPacket& pkt) const
{
    CHKPF(client_);
    return client_->SendMessage(pkt);
}
} // namespace MMI
} // namespace OHOS
