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
}
int32_t InputActiveSubscribeManager::subscribeManagerId_ = 0;

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
        return INVALID_SUBSCRIBE_ID;
    }
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t subscribeId = GenerateSubscribeId();
    if (subscribeId == INVALID_SUBSCRIBE_ID) {
        return INVALID_SUBSCRIBE_ID;
    }
    subscribeInfos_.emplace(std::make_pair(subscribeId, SubscribeInputActiveInfo(inputEventConsumer, interval)));
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SubscribeInputActive(subscribeId, interval);
    if (ret != RET_OK) {
        MMI_HILOGE("Subscribing input active failed, ret:%{public}d", ret);
        subscribeInfos_.erase(subscribeId);
        return INVALID_SUBSCRIBE_ID;
    }
    MMI_HILOGI("The subscribeId:%{public}d, inputActiveInterval:%{public}" PRId64, subscribeId, interval);
    return subscribeId;
}

int32_t InputActiveSubscribeManager::UnsubscribeInputActive(int32_t subscribeId)
{
    CALL_INFO_TRACE;
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    if (subscribeId < 0) {
        MMI_HILOGE("The subscribeId(%{public}d) is less then 0", subscribeId);
        return INVALID_SUBSCRIBE_ID;
    }

    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    std::lock_guard<std::mutex> guard(mtx_);
    auto it = subscribeInfos_.find(subscribeId);
    if (it == subscribeInfos_.end()) {
        MMI_HILOGE("subscribeId(%{public}d) is not exist", subscribeId);
        return RET_ERR;
    }
    if (MULTIMODAL_INPUT_CONNECT_MGR->UnsubscribeInputActive(subscribeId) != RET_OK) {
        MMI_HILOGE("Leave, unsubscribe input active failed");
        return RET_ERR;
    }
    subscribeInfos_.erase(it);
    return RET_OK;
}

int32_t InputActiveSubscribeManager::OnSubscribeInputActiveCallback(
    std::shared_ptr<KeyEvent> keyEvent, int32_t subscribeId)
{
    CHK_PID_AND_TID();
    CHKPR(keyEvent, RET_ERR);
    if (subscribeId < 0) {
        MMI_HILOGE("The subscribeId(%{public}d) is less then 0", subscribeId);
        return RET_ERR;
    }
    std::shared_ptr<IInputEventConsumer> inputEventConsumer = nullptr;
    {
        std::lock_guard<std::mutex> guard(mtx_);
        auto it = subscribeInfos_.find(subscribeId);
        if (it == subscribeInfos_.end()) {
            MMI_HILOGE("The subscribeId(%{public}d) is not found", subscribeId);
            return RET_ERR;
        }
        inputEventConsumer = it->second.GetCallback();
    }
    CHKPR(inputEventConsumer, RET_ERR);
    inputEventConsumer->OnInputEvent(keyEvent);
    MMI_HILOGD("Input active id: %{public}d, keycode:%{private}d", subscribeId, keyEvent->GetKeyCode());
    return RET_OK;
}

int32_t InputActiveSubscribeManager::OnSubscribeInputActiveCallback(
    std::shared_ptr<PointerEvent> pointerEvent, int32_t subscribeId)
{
    CHK_PID_AND_TID();
    CHKPR(pointerEvent, RET_ERR);
    if (subscribeId < 0) {
        MMI_HILOGE("The subscribeId(%{public}d) is less then 0", subscribeId);
        return RET_ERR;
    }
    std::shared_ptr<IInputEventConsumer> inputEventConsumer = nullptr;
    {
        std::lock_guard<std::mutex> guard(mtx_);
        auto it = subscribeInfos_.find(subscribeId);
        if (it == subscribeInfos_.end()) {
            MMI_HILOGE("The subscribeId(%{public}d) is not found", subscribeId);
            return RET_ERR;
        }
        inputEventConsumer = it->second.GetCallback();
    }
    CHKPR(inputEventConsumer, RET_ERR);
    inputEventConsumer->OnInputEvent(pointerEvent);
    MMI_HILOGD("Input active id: %{public}d, keycode:%{private}d", subscribeId, pointerEvent->GetPointerId());
    return RET_OK;
}

void InputActiveSubscribeManager::OnConnected()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (subscribeInfos_.empty()) {
        MMI_HILOGD("subscribeInfos_ is empty");
        return;
    }
    CHKPV(MULTIMODAL_INPUT_CONNECT_MGR);
    for (auto it = subscribeInfos_.begin(); it != subscribeInfos_.end(); it++) {
        SubscribeInputActiveInfo& subscribeInfo = it->second;
        int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SubscribeInputActive(
            it->first, subscribeInfo.GetInputActiveInterval());
        if (ret != RET_OK) {
            MMI_HILOGE("Subscribe input active failed, ret:%{public}d", ret);
        }
    }
}

int32_t InputActiveSubscribeManager::GenerateSubscribeId()
{
    if (InputActiveSubscribeManager::subscribeManagerId_ >= (INT_MAX - 1)) {
        MMI_HILOGE("The subscribeId has reached the upper limit, cannot continue the subscription");
        return INVALID_SUBSCRIBE_ID;
    }
    int32_t subscribeId = InputActiveSubscribeManager::subscribeManagerId_;
    ++InputActiveSubscribeManager::subscribeManagerId_;
    return subscribeId;
}
} // namespace MMI
} // namespace OHOS
