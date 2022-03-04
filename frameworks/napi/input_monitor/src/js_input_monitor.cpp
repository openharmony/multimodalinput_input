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

#include "js_input_monitor.h"
#include <cinttypes>
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
        MMI_LOGE("Invalid values");
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
    CHKPV(pointerEvent);
    if (JsInputMonMgr.GetMonitor(id_) == nullptr) {
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
    CHKPV(callback);
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
        MMI_LOGE("Invalid values");
        return;
    }
    InputMgr->MarkConsumed(monitorId_, eventId);
    consumed_ = true;
}

JsInputMonitor::JsInputMonitor(napi_env jsEnv, napi_value callback, int32_t id)
    : monitor_(std::make_shared<InputMonitor>()),
      jsEnv_(jsEnv),
      id_(id)
{
    SetCallback(callback);
    if (monitor_ == nullptr) {
        MMI_LOGE("monitor is null");
        return;
    }
    monitor_->SetCallback([jsId=id](std::shared_ptr<PointerEvent> pointerEvent) {
        auto jsMonitor = JsInputMonMgr.GetMonitor(jsId);
        CHKPV(jsMonitor);
        jsMonitor->OnPointerEvent(pointerEvent);
    });
    monitor_->SetId(id_);
}

void JsInputMonitor::SetCallback(napi_value callback)
{
    if (receiver_ == nullptr && jsEnv_ != nullptr) {
        uint32_t refCount = 1;
        auto status = napi_create_reference(jsEnv_, callback, refCount, &receiver_);
        if (status != napi_ok) {
            MMI_LOGE("napi_create_reference is failed");
            return;
        }
    }
}

void JsInputMonitor::MarkConsumed(int32_t eventId)
{
    CHKPV(monitor_);
    monitor_->MarkConsumed(eventId);
}

int32_t JsInputMonitor::IsMatch(napi_env jsEnv, napi_value callback)
{
    CHKPR(callback, ERROR_NULL_POINTER);
    if (jsEnv_ == jsEnv) {
        napi_value handlerTemp = nullptr;
        auto status = napi_get_reference_value(jsEnv_, receiver_, &handlerTemp);
        if (status != napi_ok) {
            MMI_LOGE("napi_get_reference_value is failed");
            return NAPI_ERR;
        }
        bool isEquals = false;
        status = napi_strict_equals(jsEnv_, handlerTemp, callback, &isEquals);
        if (status != napi_ok) {
            MMI_LOGE("napi_strict_equals is failed");
            return NAPI_ERR;
        }
        if (isEquals) {
            MMI_LOGI("js callback match success");
            return RET_OK;
        }
        MMI_LOGI("js callback match failed");
        return RET_ERR;
    }
    MMI_LOGI("js callback match failed");
    return RET_ERR;
}

int32_t JsInputMonitor::IsMatch(napi_env jsEnv)
{
    if (jsEnv_ == jsEnv) {
        MMI_LOGI("env match success");
        return RET_OK;
    }
    MMI_LOGI("env match failed");
    return RET_ERR;
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

int32_t JsInputMonitor::GetJsPointerItem(const PointerEvent::PointerItem &item, napi_value value)
{
    if (SetNameProperty(jsEnv_, value, "globalX", item.GetGlobalX()) != napi_ok) {
        MMI_LOGE("Set globalX property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, value, "globalY", item.GetGlobalY()) != napi_ok) {
        MMI_LOGE("Set globalY property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, value, "localX", 0) != napi_ok) {
        MMI_LOGE("Set localX property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, value, "localY", 0) != napi_ok) {
        MMI_LOGE("Set localY property failed");
        return RET_ERR;
    }
    int32_t touchArea = (item.GetWidth() + item.GetHeight()) / 2;
    if (SetNameProperty(jsEnv_, value, "size", touchArea) != napi_ok) {
        MMI_LOGE("Set size property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, value, "force", item.GetPressure()) != napi_ok) {
        MMI_LOGE("Set force property failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t JsInputMonitor::TransformPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (SetNameProperty(jsEnv_, result, "type", GetAction(pointerEvent->GetPointerAction())) != napi_ok) {
        MMI_LOGE("Set type property failed");
        return RET_ERR;
    }
    napi_value pointers = nullptr;
    auto status = napi_create_array(jsEnv_, &pointers);
    if (status != napi_ok) {
        MMI_LOGE("napi_create_array is failed");
        return RET_ERR;
    }
    std::vector<PointerEvent::PointerItem> pointerItems;
    for (const auto &item : pointerEvent->GetPointersIdList()) {
        PointerEvent::PointerItem pointerItem;
        if (!pointerEvent->GetPointerItem(item, pointerItem)) {
            MMI_LOGE("Get pointer item failed");
            return RET_ERR;
        }
        pointerItems.push_back(pointerItem);
    }
    uint32_t index = 0;
    napi_value currentPointer = nullptr;
    int32_t currentPointerId = pointerEvent->GetPointerId();
    for (const auto &it : pointerItems) {
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
            if (GetJsPointerItem(it, currentPointer) != RET_OK) {
                MMI_LOGE("transform pointerItem failed");
                return RET_ERR;
            }
            if (SetNameProperty(jsEnv_, result, "timestamp", pointerEvent->GetActionTime()) != napi_ok) {
                MMI_LOGE("Set timestamp property failed");
                return RET_ERR;
            }
            if (SetNameProperty(jsEnv_, result, "deviceId", it.GetDeviceId()) != napi_ok) {
                MMI_LOGE("Set deviceId property failed");
                return RET_ERR;
            }
        }
        if (GetJsPointerItem(it, element) != RET_OK) {
            MMI_LOGE("transform pointerItem failed");
            return RET_ERR;
        }
        status = napi_set_element(jsEnv_, pointers, index, element);
        if (status != napi_ok) {
            MMI_LOGE("napi_set_element is failed");
            return RET_ERR;
        }
        index++;
    }
    if (SetNameProperty(jsEnv_, result, "touches", pointers) != napi_ok) {
            MMI_LOGE("Set touches property failed");
            return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "changedTouches", currentPointer) != napi_ok) {
            MMI_LOGE("Set changedTouches property failed");
            return RET_ERR;
    }
    return RET_OK;
}

bool JsInputMonitor::Start() {
    MMI_LOGD("Enter");
    CHKPF(monitor_);
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
    CHKPV(monitor_);
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
    CHKPV(monitor_);
    CHKPV(pointerEvent);
    int32_t num = 0;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        evQueue_.push(pointerEvent);
        num = jsTaskNum_;
    }
    if (num < 1) {
        int32_t *id = &id_;
        uv_work_t *work = new (std::nothrow) uv_work_t;
        CHKPV(work);
        work->data = id;
        uv_loop_s *loop = nullptr;
        auto status = napi_get_uv_event_loop(jsEnv_, &loop);
        if (status != napi_ok) {
            MMI_LOGE("napi_get_uv_event_loop is failed");
            return;
        }
        uv_queue_work(loop, work, [](uv_work_t *work){}, &JsInputMonitor::JsCallback);
        std::lock_guard<std::mutex> guard(mutex_);
        jsTaskNum_++;
    }
    MMI_LOGD("Leave");
}

void JsInputMonitor::JsCallback(uv_work_t *work, int32_t status)
{
    MMI_LOGD("Enter");
    CHKPV(work);
    int32_t *id = static_cast<int32_t *>(work->data);
    delete work;
    work = nullptr;
    auto jsMonitor = JsInputMonMgr.GetMonitor(*id);
    CHKPV(jsMonitor);
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
    CHKPV(jsEnv_);
    CHKPV(receiver_);
    std::lock_guard<std::mutex> guard(mutex_);
    napi_handle_scope scope = nullptr;
    while (!evQueue_.empty()) {
        if (!isMonitoring_) {
            MMI_LOGE("js monitor stop handle callback");
            break;
        }
        auto pointerEvent = evQueue_.front();
        CHKPC(pointerEvent);
        evQueue_.pop();
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
        napi_value result = nullptr;
        status = napi_call_function(jsEnv_, nullptr, callback, 1, &touch, &result);
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
    --jsTaskNum_;
     MMI_LOGD("Leave");
}
} // namespace MMI
} // namespace OHOS
