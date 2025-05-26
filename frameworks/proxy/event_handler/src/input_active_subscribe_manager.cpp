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

#include "input_active_subscribe_manager.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputActiveSubscribeManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INVALID_SUBSCRIBE_ID { -1 };
constexpr int32_t CURRENT_SUBSCRIBE_ID { 0 };
}

InputActiveSubscribeManager::InputActiveSubscribeManager() {}
InputActiveSubscribeManager::~InputActiveSubscribeManager() {}

int32_t InputActiveSubscribeManager::SubscribeInputActive(
    std::shared_ptr<IInputEventConsumer> inputEventConsumer, int64_t interval)
{
    CALL_DEBUG_ENTER;
    CHKPR(inputEventConsumer, INVALID_SUBSCRIBE_ID);
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, INVALID_SUBSCRIBE_ID);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return ERROR_INIT_CLIENT_FAILED;
    }
    std::shared_ptr<SubscribeInputActiveInfo> subscribeInfo = nullptr;
    {
        std::lock_guard<std::mutex> guard(mtx_);
        if (subscribeInfo_) {
            MMI_HILOGE("A process only supports one interface call");
            return ERROR_ONE_PROCESS_ONLY_SUPPORT_ONE;
        }
        subscribeInfo = std::make_shared<SubscribeInputActiveInfo>(inputEventConsumer, interval);
        CHKPR(subscribeInfo, ERROR_ALLOC_SUBSCRIBEINFO_FAILED);
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SubscribeInputActive(CURRENT_SUBSCRIBE_ID, interval);
    if (ret != RET_OK) {
        MMI_HILOGE("Subscribing input active failed, ret:%{public}d", ret);
        return ERROR_SUBSCRIBE_SERVER_FAILED;
    }
    std::lock_guard<std::mutex> guard(mtx_);
    if (subscribeInfo_) {
        MMI_HILOGE("A process only supports one interface call");
        return ERROR_ONE_PROCESS_ONLY_SUPPORT_ONE;
    }
    subscribeInfo_ = subscribeInfo;
    MMI_HILOGI("The subscribeId:%{public}d, inputActiveInterval:%{public}" PRId64, CURRENT_SUBSCRIBE_ID, interval);
    return CURRENT_SUBSCRIBE_ID;
}

int32_t InputActiveSubscribeManager::UnsubscribeInputActive(int32_t subscribeId)
{
    CALL_INFO_TRACE;
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    if (subscribeId != CURRENT_SUBSCRIBE_ID) {
        MMI_HILOGE("The subscribeId(%{public}d) is invalid", subscribeId);
        return ERROR_INVALID_SUBSCRIBE_ID;
    }

    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return ERROR_INIT_CLIENT_FAILED;
    }
    {
        std::lock_guard<std::mutex> guard(mtx_);
        if (!subscribeInfo_) {
            MMI_HILOGE("no SubscribeInputActive");
            return ERROR_NO_SUBSCRIBE_INPUT_ACTIVE;
        }
    }
    if (MULTIMODAL_INPUT_CONNECT_MGR->UnsubscribeInputActive(subscribeId) != RET_OK) {
        MMI_HILOGE("Leave, unsubscribe input active failed");
        return ERROR_UNSUBSCRIBE_SERVER_FAILED;
    }
    std::lock_guard<std::mutex> guard(mtx_);
    subscribeInfo_ = nullptr;
    return RET_OK;
}

int32_t InputActiveSubscribeManager::OnSubscribeInputActiveCallback(
    std::shared_ptr<KeyEvent> keyEvent, int32_t subscribeId)
{
    CHK_PID_AND_TID();
    CHKPR(keyEvent, RET_ERR);
    if (subscribeId != CURRENT_SUBSCRIBE_ID) {
        MMI_HILOGE("The subscribeId(%{public}d) is invalid", subscribeId);
        return ERROR_INVALID_SUBSCRIBE_ID;
    }
    std::shared_ptr<IInputEventConsumer> inputEventConsumer = nullptr;
    {
        std::lock_guard<std::mutex> guard(mtx_);
        if (!subscribeInfo_) {
            MMI_HILOGE("had UnsubscribeInputActive");
            return ERROR_HAD_UNSUBSCRIBE_INPUT_ACTIVE;
        }
        inputEventConsumer = subscribeInfo_->GetCallback();
    }
    CHKPR(inputEventConsumer, RET_ERR);
    inputEventConsumer->OnInputEvent(keyEvent);
    MMI_HILOGD("subscribeId: %{public}d, keycode:%{private}d", subscribeId, keyEvent->GetKeyCode());
    return RET_OK;
}

int32_t InputActiveSubscribeManager::OnSubscribeInputActiveCallback(
    std::shared_ptr<PointerEvent> pointerEvent, int32_t subscribeId)
{
    CHK_PID_AND_TID();
    CHKPR(pointerEvent, RET_ERR);
    if (subscribeId != CURRENT_SUBSCRIBE_ID) {
        MMI_HILOGE("The subscribeId(%{public}d) is invalid", subscribeId);
        return ERROR_INVALID_SUBSCRIBE_ID;
    }
    std::shared_ptr<IInputEventConsumer> inputEventConsumer = nullptr;
    {
        std::lock_guard<std::mutex> guard(mtx_);
        if (!subscribeInfo_) {
            MMI_HILOGE("had UnsubscribeInputActive");
            return ERROR_HAD_UNSUBSCRIBE_INPUT_ACTIVE;
        }
        inputEventConsumer = subscribeInfo_->GetCallback();
    }
    CHKPR(inputEventConsumer, RET_ERR);
    inputEventConsumer->OnInputEvent(pointerEvent);
    MMI_HILOGD("subscribeId: %{public}d, pointerId:%{private}d", subscribeId, pointerEvent->GetPointerId());
    return RET_OK;
}

void InputActiveSubscribeManager::OnConnected()
{
    CALL_DEBUG_ENTER;
    CHKPV(MULTIMODAL_INPUT_CONNECT_MGR);
    std::shared_ptr<SubscribeInputActiveInfo> subscribeInfo = nullptr;
    {
        std::lock_guard<std::mutex> guard(mtx_);
        if (!subscribeInfo_) {
            return;
        }
        subscribeInfo = subscribeInfo_;
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SubscribeInputActive(
        CURRENT_SUBSCRIBE_ID, subscribeInfo->GetInputActiveInterval());
    if (ret != RET_OK) {
        MMI_HILOGE("SubscribeInputActive failed, subscribeId_:%{public}d, ret:%{public}d", CURRENT_SUBSCRIBE_ID, ret);
    }
}
} // namespace MMI
} // namespace OHOS
