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
#include "interceptor_manager_global.h"
#include <cinttypes>
#include "input_event_data_transformation.h"
#include "proto.h"
#include "souceType.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InterceptorManagerGlobal" };
    }
} // namespace MMI
} // namespace OHOS

OHOS::MMI::InterceptorManagerGlobal::InterceptorManagerGlobal()
{
}

OHOS::MMI::InterceptorManagerGlobal::~InterceptorManagerGlobal()
{
}

void OHOS::MMI::InterceptorManagerGlobal::OnAddInterceptor(int32_t sourceType, int32_t id, SessionPtr session)
{
    MMI_LOGD("enter");
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
        MMI_LOGD("sourceType:%{public}d,fd:%{public}d register in server", sourceType, session->GetFd());
    }
    MMI_LOGD("leave");
}

void OHOS::MMI::InterceptorManagerGlobal::OnRemoveInterceptor(int32_t id)
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> lock(mu_);
    InterceptorItem interceptorItem {};
    interceptorItem.id = id;
    auto iter = std::find(interceptor_.begin(), interceptor_.end(), interceptorItem);
    if (iter == interceptor_.end()) {
        MMI_LOGE("OnRemoveInterceptor::interceptorItem does not exist");
    } else {
        MMI_LOGD("sourceType:%{public}d,fd:%{public}d remove from server", iter->sourceType,
                 iter->session->GetFd());
        interceptor_.erase(iter);
    }
    MMI_LOGD("leave");
}

bool OHOS::MMI::InterceptorManagerGlobal::OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("enter");
    if (interceptor_.empty()) {
        MMI_LOGE("InterceptorManagerGlobal::%{public}s no interceptor to send msg", __func__);
        return false;
    }
    PointerEvent::PointerItem pointer;
    CHKF(pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointer), PARAM_INPUT_FAIL);
    MMI_LOGT("Interceptor-servereventTouchpad:actionTime:%{public}" PRId64 ","
             "sourceType:%{public}d,pointerAction:%{public}d,"
             "pointer:%{public}d,point.x:%{public}d,point.y:%{public}d,press:%{public}d",
             pointerEvent->GetActionTime(), pointerEvent->GetSourceType(), pointerEvent->GetPointerAction(),
             pointerEvent->GetPointerId(), pointer.GetGlobalX(), pointer.GetGlobalY(), pointer.IsPressed());
    NetPacket newPkt(MmiMessageId::TOUCHPAD_EVENT_INTERCEPTOR);
    InputEventDataTransformation::Marshalling(pointerEvent, newPkt);
    std::list<InterceptorItem>::iterator iter;
    for (const auto &item : interceptor_) {
        newPkt << item.session->GetPid() <<iter->id;
        MMI_LOGD("server send the interceptor msg to client, pid:%{public}d", item.session->GetPid());
        item.session->SendMsg(newPkt);
    }
    MMI_LOGD("leave");
    return true;
}

bool OHOS::MMI::InterceptorManagerGlobal::OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    MMI_LOGD("enter");
    if (interceptor_.empty()) {
        MMI_LOGE("InterceptorManagerGlobal::%{public}s no interceptor to send msg", __func__);
        return false;
    }
    NetPacket newPkt(MmiMessageId::KEYBOARD_EVENT_INTERCEPTOR);
    InputEventDataTransformation::KeyEventToNetPacket(keyEvent, newPkt);
    for (const auto &item : interceptor_) {
        if (item.sourceType == SOURCETYPE_KEY) {
            newPkt << item.session->GetPid();
            MMI_LOGD("server send the interceptor msg to client, pid:%{public}d", item.session->GetPid());
            item.session->SendMsg(newPkt);
        }
    }
    MMI_LOGD("leave");
    return true;
}