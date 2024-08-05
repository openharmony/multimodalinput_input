/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "oh_input_interceptor.h"

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_manager.h"
#include "input_manager_impl.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "OHInputInterceptor"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INVALID_INTERCEPTOR_ID = -1;
}
int32_t OHInputInterceptor::Start(OHInterceptorType type)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    if (type == INTERCEPTOR_TYPE_KEY) {
        if (keyInterceptorId_ < 0) {
            keyInterceptorId_ =  InputMgrImpl.AddInterceptor(shared_from_this(), DEFUALT_INTERCEPTOR_PRIORITY,
                CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD));
        }
        return keyInterceptorId_;
    } else {
        if (pointerInterceptorId_ < 0) {
            uint32_t deviceTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX) -
                CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
            pointerInterceptorId_ =  InputMgrImpl.AddInterceptor(shared_from_this(),
                DEFUALT_INTERCEPTOR_PRIORITY, deviceTags);
        }
        return pointerInterceptorId_;
    }
}

int32_t OHInputInterceptor::Stop(OHInterceptorType type)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    if (keyInterceptorId_ < 0 && pointerInterceptorId_ < 0) {
        MMI_HILOGE("There is no interceptor to be removed");
        return RET_ERR;
    }
    if (type == INTERCEPTOR_TYPE_KEY && keyInterceptorId_ != INVALID_INTERCEPTOR_ID) {
        int32_t ret = InputMgrImpl.RemoveInterceptor(keyInterceptorId_);
        if (ret != RET_OK) {
            return ret;
        }
        keyInterceptorId_ = INVALID_INTERCEPTOR_ID;
    } else if (type == INTERCEPTOR_TYPE_POINTER && pointerInterceptorId_ != INVALID_INTERCEPTOR_ID) {
        int32_t ret = InputMgrImpl.RemoveInterceptor(pointerInterceptorId_);
        if (ret != RET_OK) {
            return ret;
        }
        pointerInterceptorId_ = INVALID_INTERCEPTOR_ID;
    }
    return RET_OK;
}

void OHInputInterceptor::SetCallback(std::function<void(std::shared_ptr<PointerEvent>)> callback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    pointerCallback_ = callback;
}

void OHInputInterceptor::SetCallback(std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    keyCallback_ = callback;
}

void OHInputInterceptor::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPV(pointerCallback_);
    pointerCallback_(pointerEvent);
}

void OHInputInterceptor::OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPV(keyCallback_);
    keyCallback_(keyEvent);
}

void OHInputInterceptor::OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const {}
}
}