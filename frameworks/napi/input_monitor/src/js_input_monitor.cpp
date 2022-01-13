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

#include "js_input_monitor.h"
#include <cinttypes>
#include <uv.h>
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_manager.h"
#include "js_input_monitor_util.h"

#define INPUTMGR OHOS::MMI::InputManager::GetInstance()

namespace OHOS {
namespace MMI {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
        LOG_CORE, MMI_LOG_DOMAIN, "JsInputMonitor"
    };

    constexpr int32_t NAPI_ERR = 3;
    template<class MemberFunType, class ClassType>
    auto CallbackBind2(MemberFunType func, ClassType* obj)
    {
        return std::bind(func, obj, std::placeholders::_1);
    }

    struct CallBackInfo {
        std::shared_ptr<PointerEvent> pointerEvent_ {nullptr};
        std::function<void(std::shared_ptr<PointerEvent>)> handle_ {nullptr};
    };
}
int32_t InputMonitor::Start()
{
    std::lock_guard<std::mutex> guard(lk_);
    if (monitorId_ < 0) {
        monitorId_ = INPUTMGR->AddMonitor2(shared_from_this());
        return monitorId_ >= 0 ? RET_OK : RET_ERR;
    }
    return RET_OK;
}

void InputMonitor::Stop()
{
    std::lock_guard<std::mutex> guard(lk_);
    if (monitorId_ < 0) {
        return;
    }
    INPUTMGR->RemoveMonitor2(monitorId_);
    monitorId_ = -1;
    return;
}

void InputMonitor::SetCallback(std::function<void(std::shared_ptr<PointerEvent>)> callback)
{
    std::lock_guard<std::mutex> guard(lk_);
    callback_ = callback;
}

void InputMonitor::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHK(pointerEvent != nullptr, NULL_POINTER);
    std::function<void(std::shared_ptr<PointerEvent>)> callback;
    {
        std::lock_guard<std::mutex> guard(lk_);
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
            if (pointerEvent->GetPointersIdList().size() == 1) {
                if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
                    consumed_ = false;
                }
            }
        }
        callback = callback_;
    }
    if (!callback) {
        MMI_LOGE("callback is null");
        return;
    }
    callback(pointerEvent);
}

void InputMonitor::OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const {}

void InputMonitor::OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const {}

void InputMonitor::MarkConsumed(int32_t eventId)
{
    std::lock_guard<std::mutex> guard(lk_);
    if (consumed_) {
        MMI_LOGD("consumed_ is true");
        return;
    }
    if (monitorId_ < 0) {
        return;
    }
    INPUTMGR->MarkConsumed(monitorId_, eventId);
    consumed_ = true;
}

JsInputMonitor::JsInputMonitor(napi_env jsEnv, napi_value receiver)
    : monitor_(std::make_shared<InputMonitor>()),
      jsEnv_(jsEnv)
{
    SetReceiver(receiver);
    if (monitor_ != nullptr) {
        monitor_->SetCallback([this](std::shared_ptr<PointerEvent> pointerEvent) {
            OnPointerEvent(pointerEvent);
        });
    }
    handle_ = CallbackBind2(&JsInputMonitor::OnPointerEventInJsThread, this);
}

JsInputMonitor::~JsInputMonitor()
{
    if (monitor_ != nullptr) {
        monitor_->Stop();
        monitor_.reset();
    }
    uint32_t refCount = 0;
    auto status = napi_reference_unref(jsEnv_, receiver_, &refCount);
    if (status != napi_ok) {
        MMI_LOGE("napi_reference_unref is failed");
        return;
    }
}

void JsInputMonitor::SetReceiver(napi_value receiver)
{
    CHK(receiver != nullptr, NULL_POINTER);
    if (receiver_ == nullptr && jsEnv_ != nullptr) {
        uint32_t refCount = 1;
        auto status = napi_create_reference(jsEnv_, receiver, refCount, &receiver_);
        if (status != napi_ok) {
            MMI_LOGE("napi_create_reference is failed");
            return;
        }
    }
}

void JsInputMonitor::Start()
{
    if (monitor_ != nullptr) {
        monitor_->Start();
        return;
    }
    MMI_LOGE("monitor_ is null");
}

void JsInputMonitor::Stop()
{
    if (monitor_ != nullptr) {
        monitor_->Stop();
        return;
    }
    MMI_LOGE("monitor_ is null");
}

void JsInputMonitor::MarkConsumed(int32_t eventId)
{
    if (monitor_ != nullptr) {
        monitor_->MarkConsumed(eventId);
    }
    MMI_LOGE("monitor_ is null");
}

int32_t JsInputMonitor::IsMatch(napi_env jsEnv, napi_value receiver)
{
    CHKR(receiver != nullptr, NULL_POINTER, NAPI_ERR);
    if (jsEnv_ == jsEnv) {
        bool isEquals = false;
        napi_value handlerTemp = nullptr;
        auto status = napi_get_reference_value(jsEnv_, receiver_, &handlerTemp);
        if (status != napi_ok) {
            MMI_LOGE("napi_get_reference_value is failed");
            return NAPI_ERR;
        }
        status = napi_strict_equals(jsEnv_, handlerTemp, receiver, &isEquals);
        if (status != napi_ok) {
            MMI_LOGE("napi_strict_equals is failed");
            return NAPI_ERR;
        }
        if (isEquals) {
            MMI_LOGE("isEquals = %{public}d", isEquals);
            return RET_OK;
        }
        return RET_ERR;
    }
    return RET_ERR;
}

int32_t JsInputMonitor::IsMatch(napi_env jsEnv)
{
    if (jsEnv_ == jsEnv) {
        return RET_OK;
    }
    return RET_ERR;
}

void JsInputMonitor::OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHK(pointerEvent != nullptr, NULL_POINTER);
    CallBackInfo* cb = new CallBackInfo;
    CHK(cb != nullptr, NULL_POINTER);
    cb->handle_ = handle_;
    cb->pointerEvent_ = pointerEvent;
    uv_work_t* work = new uv_work_t;
    CHK(work != nullptr, NULL_POINTER);
    uv_loop_s* loop {nullptr};
    auto status = napi_get_uv_event_loop(jsEnv_, &loop);
    if (status != napi_ok) {
        MMI_LOGE("napi_get_uv_event_loop is failed");
        return;
    }
    CHK(loop != nullptr, NULL_POINTER);
    work->data = (void*)cb;
    uv_queue_work(loop,
                  work,
                  [](uv_work_t *work) {},
                  [](uv_work_t *work, int32_t status) {
                      MMI_LOGD("uv_queue_work enter");
                      struct CallBackInfo* cbInfo = (struct CallBackInfo*)work->data;
                      if (cbInfo->handle_ != nullptr && cbInfo->pointerEvent_ != nullptr) {
                          cbInfo->handle_(cbInfo->pointerEvent_);
                          MMI_LOGD("run handle_");
                      }
                      delete cbInfo;
                      delete work;
                      cbInfo = nullptr;
                      work = nullptr;
                      MMI_LOGD("uv_queue_work leave");
                  });
}

void JsInputMonitor::OnPointerEventInJsThread(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("enter");
    if (jsEnv_ == nullptr && receiver_ == nullptr && pointerEvent == nullptr) {
        MMI_LOGE("null pointer");
        return;
    }
    auto eventId = pointerEvent->GetId();
    napi_value callBack = nullptr;
    napi_value result = nullptr;
    napi_value touch = nullptr;
    auto status = napi_create_object(jsEnv_, &touch);
    if (status != napi_ok) {
        MMI_LOGE("napi_create_object is failed");
        return;
    }
    auto ret = TransformPointerEvent(pointerEvent, touch);
    printfPointerEvent(pointerEvent);
    if (ret != RET_OK) {
        return;
    }
    if (touch == nullptr) {
        MMI_LOGE("touch is null");
        return;
    }

    status = napi_get_reference_value(jsEnv_, receiver_, &callBack);
    if (status != napi_ok) {
        MMI_LOGE("napi_get_reference_value is failed");
        return;
    }

    status = napi_call_function(jsEnv_, nullptr, callBack, 1, &touch, &result);
    if (status != napi_ok) {
        MMI_LOGE("napi_call_function is failed");
        return;
    }

    bool retValue = false;
    status = napi_get_value_bool(jsEnv_, result, &retValue);
    if (status != napi_ok) {
        MMI_LOGE("napi_get_value_bool is failed");
        return;
    }
    if (retValue) {
        MMI_LOGE("MarkConsumed enter");
        MarkConsumed(eventId);
        MMI_LOGE("MarkConsumed leave");
    }
    MMI_LOGD("leave");
}

void JsInputMonitor::printfPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHK(pointerEvent != nullptr, NULL_POINTER);
    PointerEvent::PointerItem item;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item);
    MMI_LOGD("type:%{public}d, timestamp:%{public}d, deviceId:%{public}d,\
        globalX:%{public}d, globalY:%{public}d, localX:%{public}d, localY:%{public}d, \
        size:%{public}d, force:%{public}d", pointerEvent->GetSourceType(), item.GetDownTime(),
        item.GetDeviceId(), item.GetGlobalX(), item.GetGlobalY(), item.GetLocalX(),
        item.GetLocalY(), item.GetWidth()+item.GetHeight()/2, item.GetPressure());
}

int32_t JsInputMonitor::TransformPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CHKR(pointerEvent != nullptr, NULL_POINTER, RET_ERR);
    CHKR(SetNamedProperty(jsEnv_, result, "type", pointerEvent->GetSourceType()) == napi_ok,
        CALL_NAPI_API_ERR, RET_ERR);

    napi_value pointers = nullptr;
    auto status = napi_create_array(jsEnv_, &pointers);
    if (status != napi_ok) {
        MMI_LOGE("napi_create_array is failed");
        return RET_ERR;
    }

    int32_t currentPointerId = pointerEvent->GetPointerId();
    std::vector<PointerEvent::PointerItem> pointerItems;
    for (auto &it : pointerEvent->GetPointersIdList()) {
        PointerEvent::PointerItem pointerItem;
        pointerEvent->GetPointerItem(it, pointerItem);
        pointerItems.push_back(pointerItem);
    }
    uint32_t index = 0;
    int32_t touchArea = 0;
    napi_value currentPointer = nullptr;
    for (auto &it : pointerItems) {
        napi_value item = nullptr;
        status = napi_create_object(jsEnv_, &item);
        if (status != napi_ok) {
            MMI_LOGE("napi_create_object is failed");
            return RET_ERR;
        }
        if (currentPointerId == it.GetPointerId()) {
            status = napi_create_object(jsEnv_, &currentPointer);
            if (status != napi_ok) {
                MMI_LOGE("napi_create_object is failed");
                return RET_ERR;
            }
            CHKR(SetNamedProperty(jsEnv_, currentPointer, "globalX", it.GetGlobalX()) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
            CHKR(SetNamedProperty(jsEnv_, currentPointer, "globalY", it.GetGlobalY()) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
            CHKR(SetNamedProperty(jsEnv_, currentPointer, "localX", 0) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
            CHKR(SetNamedProperty(jsEnv_, currentPointer, "localY", 0) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
            touchArea = (it.GetWidth() + it.GetHeight()) / 2;
            CHKR(SetNamedProperty(jsEnv_, currentPointer, "size", touchArea) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
            CHKR(SetNamedProperty(jsEnv_, currentPointer, "force", it.GetPressure()) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
            CHKR(SetNamedProperty(jsEnv_, result, "timestamp", it.GetDownTime()) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
            CHKR(SetNamedProperty(jsEnv_, result, "deviceId", it.GetDeviceId()) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
        }
        CHKR(SetNamedProperty(jsEnv_, item, "globalX", it.GetGlobalX()) == napi_ok,
            CALL_NAPI_API_ERR, RET_ERR);
        CHKR(SetNamedProperty(jsEnv_, item, "globalY", it.GetGlobalY()) == napi_ok,
            CALL_NAPI_API_ERR, RET_ERR);
        CHKR(SetNamedProperty(jsEnv_, item, "localX", 0) == napi_ok,
            CALL_NAPI_API_ERR, RET_ERR);
        CHKR(SetNamedProperty(jsEnv_, item, "localY", 0) == napi_ok,
            CALL_NAPI_API_ERR, RET_ERR);
        touchArea = (it.GetWidth() + it.GetHeight()) / 2;
        CHKR(SetNamedProperty(jsEnv_, item, "size", touchArea) == napi_ok,
            CALL_NAPI_API_ERR, RET_ERR);
        CHKR(SetNamedProperty(jsEnv_, item, "force", it.GetPressure()) == napi_ok,
            CALL_NAPI_API_ERR, RET_ERR);
        status = napi_set_element(jsEnv_, pointers, index, item);
        if (status != napi_ok) {
            MMI_LOGE("napi_set_element is failed");
            return RET_ERR;
        }
        index++;
    }
    CHKR(SetNamedProperty(jsEnv_, result, "touches", pointers) == napi_ok,
        CALL_NAPI_API_ERR, RET_ERR);
    CHKR(SetNamedProperty(jsEnv_, result, "changedTouches", currentPointer) == napi_ok,
        CALL_NAPI_API_ERR, RET_ERR);
    return RET_OK;
}
}
}
