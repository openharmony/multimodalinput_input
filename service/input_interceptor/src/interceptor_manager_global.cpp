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
#include "interceptor_manager_global.h"
#include "input_event_data_transformation.h"
#include "proto.h"
#include "souceType.h"

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InterceptorManagerGlobal" };
    }
}

OHOS::MMI::InterceptorManagerGlobal::InterceptorManagerGlobal()
{
}

OHOS::MMI::InterceptorManagerGlobal::~InterceptorManagerGlobal()
{
}

void OHOS::MMI::InterceptorManagerGlobal::OnAddInterceptor(int32_t sourceType, int32_t id, SessionPtr session)
{
    std::lock_guard<std::mutex> lock(mu_);
    InterceptorItem interceptorItem {};
    interceptorItem.sourceType = sourceType;
    interceptorItem.id = id;
    interceptorItem.session =  session;
    auto iter = std::find(interceptor_.begin(), interceptor_.end(), interceptorItem);
    if (iter != interceptor_.end()) {
        MMI_LOGE("ServerInputFilterManager: touchpad event repeate register");
        return;
    } else {
        iter = interceptor_.insert(iter, interceptorItem);
        MMI_LOGD("sourceType: %{public}d, fd: %{public}d register in server", sourceType, session->GetFd());
    }
}

void OHOS::MMI::InterceptorManagerGlobal::OnRemoveInterceptor(int32_t id)
{
    std::lock_guard<std::mutex> lock(mu_);
    InterceptorItem interceptorItem {};
    interceptorItem.id = id;
    auto iter = std::find(interceptor_.begin(), interceptor_.end(), interceptorItem);
    if (iter == interceptor_.end()) {
        MMI_LOGE("OnRemoveInterceptor::interceptorItem does not exist");
    } else {
        MMI_LOGD("sourceType: %{public}d, fd: %{public}d remove from server", iter->sourceType,
                 iter->session->GetFd());
        interceptor_.erase(iter);
    }
}

bool OHOS::MMI::InterceptorManagerGlobal::OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    if (interceptor_.empty()) {
        MMI_LOGE("InterceptorManagerGlobal::%{public}s no interceptor to send msg", __func__);
        return false;
    }
    PointerEvent::PointerItem pointer;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointer);
    MMI_LOGT("\ninterceptor-server\neventTouchpad:actionTime=%{public}d;"
             "sourceType=%{public}d;pointerAction=%{public}d;"
             "pointerId=%{public}d;point.x=%{public}d;point.y=%{public}d;press=%{public}d"
             "\n*********************************************************\n",
             pointerEvent->GetActionTime(), pointerEvent->GetSourceType(), pointerEvent->GetPointerAction(),
             pointerEvent->GetPointerId(), pointer.GetGlobalX(), pointer.GetGlobalY(), pointer.IsPressed());
    NetPacket newPkt(MmiMessageId::TOUCHPAD_EVENT_INTERCEPTOR);
    InputEventDataTransformation::SerializePointerEvent(pointerEvent, newPkt);
    std::list<InterceptorItem>::iterator iter;
    for (iter = interceptor_.begin(); iter != interceptor_.end(); iter++) {
        newPkt << iter->session->GetPid() <<iter->id;
        MMI_LOGD("server send the interceptor msg to client : pid = %{public}d", iter->session->GetPid());
        iter->session->SendMsg(newPkt);
    }
    return true;
}

bool OHOS::MMI::InterceptorManagerGlobal::OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    MMI_LOGD("OnKeyEvent begin");
    if (interceptor_.empty()) {
        MMI_LOGE("InterceptorManagerGlobal::%{public}s no interceptor to send msg", __func__);
        return false;
    }
    NetPacket newPkt(MmiMessageId::KEYBOARD_EVENT_INTERCEPTOR);
    InputEventDataTransformation::KeyEventToNetPacket(keyEvent, newPkt);
    std::list<InterceptorItem>::iterator iter;
    for (iter = interceptor_.begin(); iter != interceptor_.end(); iter++) {
        if (iter->sourceType == SOURCETYPE_KEY) {
            newPkt << iter->session->GetPid();
            MMI_LOGD("server send the interceptor msg to client : pid = %{public}d", iter->session->GetPid());
            iter->session->SendMsg(newPkt);
        }
    }
    MMI_LOGD("OnKeyEvent end");
    return true;
}