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
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_manager.h"
#include "js_input_monitor_manager.h"
#include "js_input_monitor_util.h"

#define InputMgr OHOS::MMI::InputManager::GetInstance()

namespace OHOS {
namespace MMI {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsInputMonitor" };
    constexpr int32_t NAPI_ERR = 3;
}

bool InputMonitor::Start()
{
    MMI_LOGD("Enter");
    std::lock_guard<std::mutex> guard(mutex_);
    if (monitorId_ < 0) {
        monitorId_ = InputMgr->AddMonitor(shared_from_this());
        return monitorId_ >= 0;
    }
    MMI_LOGD("Leave");
    return true;
}

void InputMonitor::Stop()
{
    MMI_LOGD("Enter");
    std::lock_guard<std::mutex> guard(mutex_);
    if (monitorId_ < 0) {
        return;
    }
    InputMgr->RemoveMonitor(monitorId_);
    monitorId_ = -1;
    MMI_LOGD("Leave");
    return;
}

void InputMonitor::SetCallback(std::function<void(std::shared_ptr<PointerEvent>)> callback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    callback_ = callback;
}

void InputMonitor::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    MMI_LOGD("Enter");
    //CHKF(pointerEvent != nullptr, ERROR_NULL_POINTER);
    if (!JSIMM.GetMonitor(id_)) {
        MMI_LOGE("failed to process pointer event, id:%{public}d", id_);
        return;
    }
    std::function<void(std::shared_ptr<PointerEvent>)> callback;
    {
        std::lock_guard<std::mutex> guard(mutex_);
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
    MMI_LOGD("Leave");
}

void InputMonitor::SetId(int32_t id) {
    id_ = id;
}

void InputMonitor::OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const {}

void InputMonitor::OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const {}

void InputMonitor::MarkConsumed(int32_t eventId)
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (consumed_) {
        MMI_LOGD("consumed_ is true");
        return;
    }
    if (monitorId_ < 0) {
        return;
    }
    InputMgr->MarkConsumed(monitorId_, eventId);
    consumed_ = true;
}

JsInputMonitor::JsInputMonitor(napi_env jsEnv, napi_value receiver, int32_t id)
    : monitor_(std::make_shared<InputMonitor>()),
      jsEnv_(jsEnv),
      id_(id)
{
    SetReceiver(receiver);
    if (monitor_ != nullptr) {
        monitor_->SetCallback([jsId=id](std::shared_ptr<PointerEvent> pointerEvent) {
            auto jsMonitor = JSIMM.GetMonitor(jsId);
            if (jsMonitor == nullptr) {
                MMI_LOGE("failed to get js monitor");
                return;
            }
           jsMonitor->OnPointerEvent(pointerEvent);
        });
        monitor_->SetId(id_);
    }
    auto status = napi_get_uv_event_loop(jsEnv_,&loop_);
    if (status != napi_ok) {
        MMI_LOGE("napi_get_uv_event_loop is failed");
        return;
    }
}

void JsInputMonitor::SetReceiver(napi_value receiver)
{
    CHK(receiver != nullptr, ERROR_NULL_POINTER);
    if (receiver_ == nullptr && jsEnv_ != nullptr) {
        uint32_t refCount = 1;
        auto status = napi_create_reference(jsEnv_, receiver, refCount, &receiver_);
        if (status != napi_ok) {
            MMI_LOGE("napi_create_reference is failed");
            return;
        }
    }
}

void JsInputMonitor::MarkConsumed(int32_t eventId)
{
    if (monitor_ == nullptr) {
        MMI_LOGE("monitor_ is null");
        return;
    }
    monitor_->MarkConsumed(eventId);
}

int32_t JsInputMonitor::IsMatch(napi_env jsEnv, napi_value receiver)
{
    CHKR(receiver != nullptr, ERROR_NULL_POINTER, NAPI_ERR);
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

void JsInputMonitor::printfPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHK(pointerEvent != nullptr, ERROR_NULL_POINTER);
    PointerEvent::PointerItem item;
    CHK(pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item), PARAM_INPUT_FAIL);
    MMI_LOGD("type:%{public}d, timestamp:%{public}d, deviceId:%{public}d,\
        globalX:%{public}d, globalY:%{public}d, localX:%{public}d, localY:%{public}d, \
        size:%{public}d, force:%{public}d", pointerEvent->GetSourceType(), item.GetDownTime(),
        item.GetDeviceId(), item.GetGlobalX(), item.GetGlobalY(), item.GetLocalX(),
        item.GetLocalY(), item.GetWidth()+item.GetHeight()/2, item.GetPressure());
}

std::string JsInputMonitor::GetAction(int32_t action)
{
    switch (action) {
        case PointerEvent::POINTER_ACTION_CANCEL:
            return "cancel";
        case PointerEvent::POINTER_ACTION_DOWN:
            return "down";
        case PointerEvent::POINTER_ACTION_MOVE:
            return "move";
        case PointerEvent::POINTER_ACTION_UP:
            return "up";
        default:
            return "";
    }
}

int32_t JsInputMonitor::TransformPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CHKR(pointerEvent != nullptr, ERROR_NULL_POINTER, RET_ERR);
    CHKR(SetNameProperty(jsEnv_, result, "type", GetAction(pointerEvent->GetPointerAction())) == napi_ok,
        CALL_NAPI_API_ERR, RET_ERR);

    napi_value pointers = nullptr;
    auto status = napi_create_array(jsEnv_, &pointers);
    if (status != napi_ok) {
        MMI_LOGE("napi_create_array is failed");
        return RET_ERR;
    }

    int32_t currentPointerId = pointerEvent->GetPointerId();
    std::vector<PointerEvent::PointerItem> pointerItems;
    for (auto &item : pointerEvent->GetPointersIdList()) {
        PointerEvent::PointerItem pointerItem;
        pointerEvent->GetPointerItem(item, pointerItem);
        pointerItems.push_back(pointerItem);
    }
    uint32_t index = 0;
    int32_t touchArea = 0;
    napi_value currentPointer = nullptr;
    for (auto &it : pointerItems) {
        napi_value element = nullptr;
        status = napi_create_object(jsEnv_, &element);
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
            CHKR(SetNameProperty(jsEnv_, currentPointer, "globalX", it.GetGlobalX()) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
            CHKR(SetNameProperty(jsEnv_, currentPointer, "globalY", it.GetGlobalY()) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
            CHKR(SetNameProperty(jsEnv_, currentPointer, "localX", 0) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
            CHKR(SetNameProperty(jsEnv_, currentPointer, "localY", 0) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
            touchArea = (it.GetWidth() + it.GetHeight()) / 2;
            CHKR(SetNameProperty(jsEnv_, currentPointer, "size", touchArea) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
            CHKR(SetNameProperty(jsEnv_, currentPointer, "force", it.GetPressure()) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
            CHKR(SetNameProperty(jsEnv_, result, "timestamp", it.GetDownTime()) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
            CHKR(SetNameProperty(jsEnv_, result, "deviceId", it.GetDeviceId()) == napi_ok,
                CALL_NAPI_API_ERR, RET_ERR);
        }
        CHKR(SetNameProperty(jsEnv_, element, "globalX", it.GetGlobalX()) == napi_ok,
            CALL_NAPI_API_ERR, RET_ERR);
        CHKR(SetNameProperty(jsEnv_, element, "globalY", it.GetGlobalY()) == napi_ok,
            CALL_NAPI_API_ERR, RET_ERR);
        CHKR(SetNameProperty(jsEnv_, element, "localX", 0) == napi_ok,
            CALL_NAPI_API_ERR, RET_ERR);
        CHKR(SetNameProperty(jsEnv_, element, "localY", 0) == napi_ok,
            CALL_NAPI_API_ERR, RET_ERR);
        touchArea = (it.GetWidth() + it.GetHeight()) / 2;
        CHKR(SetNameProperty(jsEnv_, element, "size", touchArea) == napi_ok,
            CALL_NAPI_API_ERR, RET_ERR);
        CHKR(SetNameProperty(jsEnv_, element, "force", it.GetPressure()) == napi_ok,
            CALL_NAPI_API_ERR, RET_ERR);
        status = napi_set_element(jsEnv_, pointers, index, element);
        if (status != napi_ok) {
            MMI_LOGE("napi_set_element is failed");
            return RET_ERR;
        }
        index++;
    }
    CHKR(SetNameProperty(jsEnv_, result, "touches", pointers) == napi_ok,
        CALL_NAPI_API_ERR, RET_ERR);
    CHKR(SetNameProperty(jsEnv_, result, "changedTouches", currentPointer) == napi_ok,
        CALL_NAPI_API_ERR, RET_ERR);
    return RET_OK;
}

bool JsInputMonitor::Start() {
    MMI_LOGD("Enter");
    CHKPF(monitor_, OHOS::ERROR_NULL_POINTER);
    if (isMonitoring_) {
        MMI_LOGW("js is monitoring");
        return true;
    }
    if (monitor_->Start()) {
        isMonitoring_ = true;
        return true;
    }
    MMI_LOGD("Leave");
    return false;
}

JsInputMonitor::~JsInputMonitor()
{
    MMI_LOGD("Enter");
    if (isMonitoring_) {
        isMonitoring_ = false;
        if (monitor_ != nullptr) {
            monitor_->Stop();
        }
    }
    uint32_t refCount = 0;
    auto status = napi_reference_unref(jsEnv_, receiver_, &refCount);
    if (status != napi_ok) {
        MMI_LOGE("napi_reference_unref is failed");
        return;
    }
    MMI_LOGD("Leave");
}

void JsInputMonitor::Stop() {
    MMI_LOGD("Enter");
    CHKP(monitor_);
    if (isMonitoring_) {
        isMonitoring_ = false;
        if (monitor_ != nullptr) {
            monitor_->Stop();
        }
    }
    MMI_LOGD("Leave");
}

int32_t JsInputMonitor::GetId()
{
    return id_;
}

void JsInputMonitor::OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Enter");
    CHKP(monitor_);
    int32_t num = 0;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        evQueue_.push(pointerEvent);
        num = jsThreadNum_;
    }
    if (num < 1) {
        int32_t *id = &id_;
        uv_work_t *work = new uv_work_t;
        work->data = id;
        uv_queue_work(loop_, work, [](uv_work_t *work){}, &JsInputMonitor::JsCallback);
        std::lock_guard<std::mutex> guard(mutex_);
        jsThreadNum_++;
    }
    MMI_LOGD("Leave");
}

void JsInputMonitor::JsCallback(uv_work_t *work, int32_t status)
{
    MMI_LOGD("Enter");
    int32_t *id = static_cast<int32_t *>(work->data);
    delete work;
    work = nullptr;
    auto jsMonitor = JSIMM.GetMonitor(*id);
    if (jsMonitor == nullptr) {
        id = nullptr;
        return;
    }
    jsMonitor->OnPointerEventInJsThread();
    id = nullptr;
    MMI_LOGD("Leave");
}

void JsInputMonitor::OnPointerEventInJsThread()
{
    MMI_LOGD("Enter");
    if (!isMonitoring_) {
        MMI_LOGE("js monitor stop");
        return;
    }
    if (jsEnv_ == nullptr || receiver_ == nullptr) {
        MMI_LOGE("jsEnv_ or receiver_ is null");
        return;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    napi_handle_scope scope = nullptr;
    while (!evQueue_.empty()) {
        if (!isMonitoring_) {
            MMI_LOGE("js monitor stop handle callback");
            break;
        }
        auto pointerEvent = evQueue_.front();
        evQueue_.pop();
        if (pointerEvent == nullptr) {
            continue;
        }
        auto status = napi_open_handle_scope(jsEnv_, &scope);
        if (status != napi_ok) {
            break;
        }
        napi_value touch = nullptr;
        status = napi_create_object(jsEnv_, &touch);
        if (status != napi_ok) {
            napi_close_handle_scope(jsEnv_, scope);
            break;
        }
        auto ret = TransformPointerEvent(pointerEvent, touch);
        if (ret != napi_ok) {
            napi_close_handle_scope(jsEnv_, scope);
            break;
        }
        if (touch == nullptr) {
            napi_close_handle_scope(jsEnv_, scope);
            break;
        }
        napi_value callback = nullptr;
        status = napi_get_reference_value(jsEnv_, receiver_, &callback);
        if (status != napi_ok) {
            napi_close_handle_scope(jsEnv_, scope);
            break;
        }
        napi_value global = nullptr;
        status = napi_get_global(jsEnv_, &global);
        if (status != napi_ok) {
            napi_close_handle_scope(jsEnv_, scope);
            break;
        } 
        napi_value result = nullptr;
        status = napi_call_function(jsEnv_, global, callback, 1, &touch, &result);
        if (status != napi_ok) {
            napi_close_handle_scope(jsEnv_, scope);
            break;
        }
        bool retValue = false;
        status = napi_get_value_bool(jsEnv_, result, &retValue);
        if (status != napi_ok) {
            napi_close_handle_scope(jsEnv_, scope);
            return;
        }
        if (retValue) {
            auto eventId = pointerEvent->GetId();
            MarkConsumed(eventId);
        }
        napi_close_handle_scope(jsEnv_, scope);
    }
    --jsThreadNum_;
     MMI_LOGD("Leave");
}
} // namespace MMI
} // namespace OHOS
