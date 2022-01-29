/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "interceptor_manager.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "souceType.h"

namespace OHOS::MMI {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InterceptorManager" };
}

InterceptorManager::InterceptorManager()
{
    InterceptorItemId = 0;
}

InterceptorManager::~InterceptorManager()
{
}

int32_t InterceptorManager::AddInterceptor(int32_t sourceType,
    std::function<void(std::shared_ptr<PointerEvent>)> interceptor)
{
    if (interceptor == nullptr) {
        MMI_LOGE("InterceptorManager::%{public}s param should not be null!", __func__);
        return INVALID_INTERCEPTOR_ID;
    }

    InterceptorItem interceptorItem;
    interceptorItem.id_ = ++InterceptorItemId;
    interceptorItem.sourceType = sourceType;
    interceptorItem.callback = interceptor;
    interceptor_.push_back(interceptorItem);
    MMIEventHdl.AddInterceptor(interceptorItem.sourceType, interceptorItem.id_);
    MMI_LOGT("Add sourceType = %{public}d Touchpad to InterceptorManager success!", sourceType);
    return interceptorItem.id_;
}

int32_t InterceptorManager::AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor)
{
    if (interceptor == nullptr) {
        MMI_LOGE("InterceptorManager::%{public}s param should not be null!", __func__);
        return RET_ERR;
    }

    InterceptorItem interceptorItem;
    interceptorItem.id_ = ++InterceptorItemId;
    interceptorItem.sourceType = SOURCETYPE_KEY;
    interceptorItem.callback_ = interceptor;
    interceptor_.push_back(interceptorItem);
    if (RET_OK == MMIEventHdl.AddInterceptor(interceptorItem.sourceType, interceptorItem.id_)) {
        MMI_LOGT("Add AddInterceptor KeyEvent to InterceptorManager success!");
        return MMI_STANDARD_EVENT_SUCCESS;
    }
    return MMI_STANDARD_EVENT_INVALID_PARAMETER;
}

void InterceptorManager::RemoveInterceptor(int32_t interceptorId)
{
    if (interceptorId <= 0) {
        MMI_LOGE("InterceptorManager::%{public}s interceptorId invalid", __func__);
        return;
    }
    InterceptorItem interceptorItem;
    interceptorItem.id_ = interceptorId;
    auto iter = std::find(interceptor_.begin(), interceptor_.end(), interceptorItem);
    if (iter == interceptor_.end()) {
        MMI_LOGE("InterceptorManager::%{public}s InterceptorItem does not exist", __func__);
    } else {
        iter = interceptor_.erase(iter);
        MMIEventHdl.RemoveInterceptor(interceptorItem.id_);
        MMI_LOGD("InterceptorManager::%{public}s InterceptorItem id: %{public}d removed success",
                 __func__, interceptorId);
    }
}

int32_t InterceptorManager::OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent, int32_t id)
{
    if (pointerEvent == nullptr) {
        MMI_LOGE("InterceptorManager::%{public}s param should not be null!", __func__);
    }
    PointerEvent::PointerItem pointer;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointer);
    MMI_LOGT("interceptor-clienteventTouchpad:actionTime=%{public}d;"
             "sourceType=%{public}d;pointerAction=%{public}d;"
             "pointerId=%{public}d;point.x=%{public}d;point.y=%{public}d;press=%{public}d"
             "*********************************************************",
             pointerEvent->GetActionTime(), pointerEvent->GetSourceType(), pointerEvent->GetPointerAction(),
             pointerEvent->GetPointerId(), pointer.GetGlobalX(), pointer.GetGlobalY(), pointer.IsPressed());
    InterceptorItem interceptorItem;
    interceptorItem.id_ = id;
    auto iter = std::find(interceptor_.begin(), interceptor_.end(), interceptorItem);
    if (iter == interceptor_.end()) {
        MMI_LOGE("InterceptorManager::%{public}s InterceptorItem does not exist", __func__);
    } else {
        MMI_LOGE("InterceptorManager::%{public}s SendMsg", __func__);
        if (iter->callback) {
            iter->callback(pointerEvent);
        } else {
        MMI_LOGE("InterceptorManager::callback is null");
        }
    }
    return MMI_STANDARD_EVENT_SUCCESS;
}

int32_t InterceptorManager::OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    if (keyEvent == nullptr) {
        MMI_LOGE("InterceptorManager::%{public}s param should not be null!", __func__);
    }
    std::list<InterceptorItem>::iterator iter;
    for (iter = interceptor_.begin(); iter != interceptor_.end(); iter++) {
        if (iter->sourceType == SOURCETYPE_KEY) {
            MMI_LOGD("InterceptorManager::%{public}s SendMsg", __func__);
            iter->callback_(keyEvent);
        }     
    }
    return MMI_STANDARD_EVENT_SUCCESS;
}
}