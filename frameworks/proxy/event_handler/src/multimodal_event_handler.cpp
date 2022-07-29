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

#include "multimodal_event_handler.h"

#include "proto.h"

#include "input_event.h"
#include "input_manager_impl.h"
#include "input_handler_manager.h"
#include "mmi_client.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "MultimodalEventHandler"};
} // namespace

void OnConnected(const IfMMIClient& client)
{
    CALL_DEBUG_ENTER;
    InputMgrImpl->OnConnected();
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    KeyEventInputSubscribeMgr.OnConnected();
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_MONITOR
    IMonitorMgr->OnConnected();
#endif // OHOS_BUILD_ENABLE_MONITOR
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    InputInterMgr->OnConnected();
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
}

MultimodalEventHandler::MultimodalEventHandler() {}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t MultimodalEventHandler::InjectEvent(const std::shared_ptr<KeyEvent> keyEventPtr)
{
    CHKPR(keyEventPtr, ERROR_NULL_POINTER);
    return EventManager.InjectEvent(keyEventPtr);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

bool MultimodalEventHandler::InitClient()
{
    CALL_DEBUG_ENTER;
    if (client_ != nullptr) {
        return true;
    }
    client_ = std::make_shared<MMIClient>();
    CHKPF(client_);
    client_->RegisterConnectedFunction(&OnConnected);
    if (!(client_->Start())) {
        MMI_HILOGE("The client fails to start");
        return false;
    }
    return true;
}

MMIClientPtr MultimodalEventHandler::GetMMIClient()
{
    CHKPP(client_);
    return client_->GetSharedPtr();
}

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
int32_t MultimodalEventHandler::InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    return EventManager.InjectPointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
int32_t MultimodalEventHandler::MoveMouseEvent(int32_t offsetX, int32_t offsetY)
{
    return EventManager.MoveMouseEvent(offsetX, offsetY);
}
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
} // namespace MMI
} // namespace OHOS
