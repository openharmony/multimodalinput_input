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

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_manager.h"
#include "js_input_monitor_manager.h"
#include "js_input_monitor_util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsInputMonitor" };
constexpr int32_t AXIS_TYPE_SCROLL_VERTICAL = 0;
constexpr int32_t AXIS_TYPE_SCROLL_HORIZONTAL = 1;
constexpr int32_t AXIS_TYPE_PINCH = 2;
constexpr int32_t NAPI_ERR = 3;
constexpr int32_t CANCEL = 0;
constexpr int32_t MOVE = 1;
constexpr int32_t BUTTON_DOWN = 2;
constexpr int32_t BUTTON_UP = 3;
constexpr int32_t AXIS_BEGIN = 4;
constexpr int32_t AXIS_UPDATE = 5;
constexpr int32_t AXIS_END = 6;
constexpr int32_t MIDDLE = 1;
constexpr int32_t RIGHT = 2;
constexpr int32_t MOUSE_FLOW = 15;
} // namespace

int32_t InputMonitor::Start()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    if (monitorId_ < 0) {
        monitorId_ = InputMgr->AddMonitor(shared_from_this());
    }
    return monitorId_;
}

void InputMonitor::Stop()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    if (monitorId_ < 0) {
        MMI_HILOGE("Invalid values");
        return;
    }
    InputMgr->RemoveMonitor(monitorId_);
    monitorId_ = -1;
    return;
}

void InputMonitor::SetCallback(std::function<void(std::shared_ptr<PointerEvent>)> callback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    callback_ = callback;
}

void InputMonitor::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (JsInputMonMgr.GetMonitor(id_) == nullptr) {
        MMI_HILOGE("Failed to process pointer event, id:%{public}d", id_);
        return;
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE
        && pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE) {
        static int32_t count = MOUSE_FLOW;
        if (++count < MOUSE_FLOW) {
            pointerEvent->MarkProcessed();
            return;
        } else {
            count = 0;
        }
    }
    std::function<void(std::shared_ptr<PointerEvent>)> callback;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
            if (JsInputMonMgr.GetMonitor(id_)->GetTypeName() != "touch") {
                pointerEvent->MarkProcessed();
                return;
            }
            if (pointerEvent->GetPointerIds().size() == 1) {
                if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
                    consumed_ = false;
                }
            }
        }
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
            if (JsInputMonMgr.GetMonitor(id_)->GetTypeName() != "mouse") {
                return;
            }
            if (pointerEvent->GetPointerIds().size() == 1) {
                if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
                    consumed_ = false;
                }
            }
        }
        callback = callback_;
    }
    CHKPV(callback);
    callback(pointerEvent);
}

void InputMonitor::SetId(int32_t id)
{
    id_ = id;
}

void InputMonitor::OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const {}

void InputMonitor::OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const {}

void InputMonitor::MarkConsumed(int32_t eventId)
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (consumed_) {
        MMI_HILOGD("The consumed_ is true");
        return;
    }
    if (monitorId_ < 0) {
        MMI_HILOGE("Invalid values");
        return;
    }
    InputMgr->MarkConsumed(monitorId_, eventId);
    consumed_ = true;
}

JsInputMonitor::JsInputMonitor(napi_env jsEnv, const std::string &typeName, napi_value callback, int32_t id)
    : monitor_(std::make_shared<InputMonitor>()),
      jsEnv_(jsEnv),
      typeName_(typeName),
      monitorId_(id)
{
    SetCallback(callback);
    if (monitor_ == nullptr) {
        MMI_HILOGE("The monitor is null");
        return;
    }
    monitor_->SetCallback([jsId = id](std::shared_ptr<PointerEvent> pointerEvent) {
        auto& jsMonitor {JsInputMonMgr.GetMonitor(jsId)};
        CHKPV(jsMonitor);
        jsMonitor->OnPointerEvent(pointerEvent);
    });
    monitor_->SetId(monitorId_);
}

void JsInputMonitor::SetCallback(napi_value callback)
{
    if (receiver_ == nullptr && jsEnv_ != nullptr) {
        uint32_t refCount = 1;
        auto status = napi_create_reference(jsEnv_, callback, refCount, &receiver_);
        if (status != napi_ok) {
            THROWERR(jsEnv_, "napi_create_reference is failed");
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
            THROWERR(jsEnv_, "napi_get_reference_value is failed");
            return NAPI_ERR;
        }
        bool isEquals = false;
        status = napi_strict_equals(jsEnv_, handlerTemp, callback, &isEquals);
        if (status != napi_ok) {
            THROWERR(jsEnv_, "napi_strict_equals is failed");
            return NAPI_ERR;
        }
        if (isEquals) {
            MMI_HILOGI("Js callback match success");
            return RET_OK;
        }
        MMI_HILOGI("Js callback match failed");
        return RET_ERR;
    }
    MMI_HILOGI("Js callback match failed");
    return RET_ERR;
}

int32_t JsInputMonitor::IsMatch(napi_env jsEnv)
{
    if (jsEnv_ == jsEnv) {
        MMI_HILOGI("Env match success");
        return RET_OK;
    }
    MMI_HILOGI("Env match failed");
    return RET_ERR;
}

std::string JsInputMonitor::GetAction(int32_t action) const
{
    switch (action) {
        case PointerEvent::POINTER_ACTION_CANCEL: {
            return "cancel";
        }
        case PointerEvent::POINTER_ACTION_DOWN: {
            return "down";
        }
        case PointerEvent::POINTER_ACTION_MOVE: {
            return "move";
        }
        case PointerEvent::POINTER_ACTION_UP: {
            return "up";
        }
        default: {
            return "";
        }
    }
}

int32_t JsInputMonitor::GetJsPointerItem(const PointerEvent::PointerItem &item, napi_value value) const
{
    if (SetNameProperty(jsEnv_, value, "globalX", item.GetDisplayX()) != napi_ok) {
        MMI_HILOGE("Set globalX property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, value, "globalY", item.GetDisplayY()) != napi_ok) {
        MMI_HILOGE("Set globalY property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, value, "localX", 0) != napi_ok) {
        MMI_HILOGE("Set localX property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, value, "localY", 0) != napi_ok) {
        MMI_HILOGE("Set localY property failed");
        return RET_ERR;
    }
    int32_t touchArea = (item.GetWidth() + item.GetHeight()) / 2;
    if (SetNameProperty(jsEnv_, value, "size", touchArea) != napi_ok) {
        MMI_HILOGE("Set size property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, value, "force", item.GetPressure()) != napi_ok) {
        MMI_HILOGE("Set force property failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t JsInputMonitor::TransformPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (SetNameProperty(jsEnv_, result, "type", GetAction(pointerEvent->GetPointerAction())) != napi_ok) {
        MMI_HILOGE("Set type property failed");
        return RET_ERR;
    }
    napi_value pointers = nullptr;
    auto status = napi_create_array(jsEnv_, &pointers);
    if (status != napi_ok) {
        MMI_HILOGE("napi_create_array is failed");
        return RET_ERR;
    }
    std::vector<PointerEvent::PointerItem> pointerItems;
    for (const auto &item : pointerEvent->GetPointerIds()) {
        PointerEvent::PointerItem pointerItem;
        if (!pointerEvent->GetPointerItem(item, pointerItem)) {
            MMI_HILOGE("Get pointer item failed");
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
            MMI_HILOGE("napi_create_object is failed");
            return RET_ERR;
        }
        if (currentPointerId == it.GetPointerId()) {
            status = napi_create_object(jsEnv_, &currentPointer);
            if (status != napi_ok) {
                MMI_HILOGE("napi_create_object is failed");
                return RET_ERR;
            }
            if (GetJsPointerItem(it, currentPointer) != RET_OK) {
                MMI_HILOGE("Transform pointerItem failed");
                return RET_ERR;
            }
            if (SetNameProperty(jsEnv_, result, "timestamp", pointerEvent->GetActionTime()) != napi_ok) {
                MMI_HILOGE("Set timestamp property failed");
                return RET_ERR;
            }
            if (SetNameProperty(jsEnv_, result, "deviceId", it.GetDeviceId()) != napi_ok) {
                MMI_HILOGE("Set deviceId property failed");
                return RET_ERR;
            }
        }
        if (GetJsPointerItem(it, element) != RET_OK) {
            MMI_HILOGE("Transform pointerItem failed");
            return RET_ERR;
        }
        status = napi_set_element(jsEnv_, pointers, index, element);
        if (status != napi_ok) {
            MMI_HILOGE("napi_set_element is failed");
            return RET_ERR;
        }
        ++index;
    }
    if (SetNameProperty(jsEnv_, result, "touches", pointers) != napi_ok) {
            MMI_HILOGE("Set touches property failed");
            return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "changedTouches", currentPointer) != napi_ok) {
            MMI_HILOGE("Set changedTouches property failed");
            return RET_ERR;
    }
    return RET_OK;
}

MapFun JsInputMonitor::GetFuns(const std::shared_ptr<PointerEvent> pointerEvent, const PointerEvent::PointerItem& item)
{
    MapFun mapFun;
    mapFun["actionTime"] = std::bind(&PointerEvent::GetActionTime, pointerEvent);
    mapFun["screenId"] = std::bind(&PointerEvent::GetTargetDisplayId, pointerEvent);
    mapFun["windowId"] = std::bind(&PointerEvent::GetTargetWindowId, pointerEvent);
    mapFun["deviceId"] = std::bind(&PointerEvent::PointerItem::GetDeviceId, item);
    mapFun["windowX"] = std::bind(&PointerEvent::PointerItem::GetDisplayX, item);
    mapFun["windowY"] = std::bind(&PointerEvent::PointerItem::GetDisplayY, item);
    mapFun["screenX"] = std::bind(&PointerEvent::PointerItem::GetWindowX, item);
    mapFun["screenY"] = std::bind(&PointerEvent::PointerItem::GetWindowY, item);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    mapFun["rawDeltaX"] = std::bind(&PointerEvent::PointerItem::GetRawDx, item);
    mapFun["rawDeltaY"] = std::bind(&PointerEvent::PointerItem::GetRawDy, item);
#endif // OHOS_BUILD_ENABLE_COOPERATE
    return mapFun;
}

bool JsInputMonitor::SetMouseProperty(const std::shared_ptr<PointerEvent> pointerEvent,
    const PointerEvent::PointerItem& item, napi_value result)
{
    int32_t buttonId = pointerEvent->GetButtonId();
    if (buttonId == PointerEvent::MOUSE_BUTTON_MIDDLE) {
        buttonId = MIDDLE;
    } else if (buttonId == PointerEvent::MOUSE_BUTTON_RIGHT) {
        buttonId = RIGHT;
    }
    if (SetNameProperty(jsEnv_, result, "button", buttonId) != napi_ok) {
        THROWERR(jsEnv_, "Set property failed");
        return false;
    }

    auto mapFun = GetFuns(pointerEvent, item);
    for (const auto &it : mapFun) {
        if (SetNameProperty(jsEnv_, result, it.first, it.second()) != napi_ok) {
            THROWERR(jsEnv_, "Set property failed");
            return false;
        }
    }
    return true;
}

bool JsInputMonitor::GetAxesValue(const std::shared_ptr<PointerEvent> pointerEvent, napi_value element)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointerEvent);
    double axisValue = -1.0;
    int32_t axis = -1;
    if (pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        axisValue = pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL);
        axis = AXIS_TYPE_SCROLL_VERTICAL;
    }
    if (pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        axisValue = pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL);
        axis = AXIS_TYPE_SCROLL_HORIZONTAL;
    }
    if (pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_PINCH)) {
        axisValue = pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH);
        axis = AXIS_TYPE_PINCH;
    }
    if (SetNameProperty(jsEnv_, element, "axis", axis) != napi_ok) {
        THROWERR(jsEnv_, "Set property of axis failed");
        return false;
    }
    if (SetNameProperty(jsEnv_, element, "value", axisValue) != napi_ok) {
        THROWERR(jsEnv_, "Set property of value failed");
        return false;
    }
    return true;
}

int32_t JsInputMonitor::GetMousePointerItem(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    napi_value axes = nullptr;
    napi_status status = napi_create_array(jsEnv_, &axes);
    if (status != napi_ok || axes == nullptr) {
        THROWERR(jsEnv_, "napi_create_array is failed");
        return RET_ERR;
    }
    uint32_t index = 0;
    int32_t currentPointerId = pointerEvent->GetPointerId();
    std::vector<int32_t> pointerIds { pointerEvent->GetPointerIds() };
    for (const auto& pointerId : pointerIds) {
        if (pointerId == currentPointerId) {
            PointerEvent::PointerItem item;
            if (!pointerEvent->GetPointerItem(pointerId, item)) {
                MMI_HILOGE("Invalid pointer:%{public}d", pointerId);
                return RET_ERR;
            }
            if (SetNameProperty(jsEnv_, result, "id", currentPointerId) != napi_ok) {
                THROWERR(jsEnv_, "Set property of id failed");
                return false;
            }
            if (!SetMouseProperty(pointerEvent, item, result)) {
                MMI_HILOGE("Set property of mouse failed");
                return RET_ERR;
            }
        }
        napi_value element = nullptr;
        if (napi_create_object(jsEnv_, &element) != napi_ok) {
            THROWERR(jsEnv_, "napi_create_object is failed");
            return false;
        }
        if (!GetAxesValue(pointerEvent, element)) {
            THROWERR(jsEnv_, "Get axesValue failed");
            return RET_ERR;
        }
        status = napi_set_element(jsEnv_, axes, index, element);
        if (status != napi_ok) {
            THROWERR(jsEnv_, "Napi set element in axes failed");
            return RET_ERR;
        }
        ++index;
    }
    if (SetNameProperty(jsEnv_, result, "axes", axes) != napi_ok) {
        THROWERR(jsEnv_, "Set property of axes failed");
        return RET_ERR;
    }
    return RET_OK;
}

bool JsInputMonitor::GetPressedButtons(const std::set<int32_t>& pressedButtons, napi_value result)
{
    CALL_DEBUG_ENTER;
    napi_value value = nullptr;
    napi_status status = napi_create_array(jsEnv_, &value);
    if (status != napi_ok || value == nullptr) {
        THROWERR(jsEnv_, "napi_create_array is failed");
        return false;
    }
    uint32_t index = 0;
    for (const auto &item : pressedButtons) {
        int32_t buttonId = item;
        if (buttonId == PointerEvent::MOUSE_BUTTON_MIDDLE) {
            buttonId = MIDDLE;
        } else if (buttonId == PointerEvent::MOUSE_BUTTON_RIGHT) {
            buttonId = RIGHT;
        }
        napi_value element = nullptr;
        if (napi_create_int32(jsEnv_, buttonId, &element) != napi_ok) {
            THROWERR(jsEnv_, "Napi create int32 failed");
            return false;
        }
        status = napi_set_element(jsEnv_, value, index, element);
        if (status != napi_ok) {
            THROWERR(jsEnv_, "Napi set element failed");
            return false;
        }
        ++index;
    }
    if (SetNameProperty(jsEnv_, result, "pressedButtons", value) != napi_ok) {
        THROWERR(jsEnv_, "Set property of pressedButtons failed");
        return false;
    }
    return true;
}

bool JsInputMonitor::GetPressedKeys(const std::vector<int32_t>& pressedKeys, napi_value result)
{
    CALL_DEBUG_ENTER;
    napi_value value = nullptr;
    napi_status status = napi_create_array(jsEnv_, &value);
    if (status != napi_ok || value == nullptr) {
        THROWERR(jsEnv_, "napi_create_array is failed");
        return false;
    }
    uint32_t index = 0;
    for (const auto &it : pressedKeys) {
        napi_value element = nullptr;
        if (napi_create_int32(jsEnv_, it, &element) != napi_ok) {
            THROWERR(jsEnv_, "Napi create int32 failed");
            return false;
        }
        status = napi_set_element(jsEnv_, value, index, element);
        if (status != napi_ok) {
            THROWERR(jsEnv_, "Napi set element failed");
            return false;
        }
        ++index;
    }
    if (SetNameProperty(jsEnv_, result, "pressedKeys", value) != napi_ok) {
        THROWERR(jsEnv_, "Set property of pressedKeys failed");
        return false;
    }
    return true;
}

bool JsInputMonitor::HasKeyCode(const std::vector<int32_t>& pressedKeys, int32_t keyCode)
{
    return std::find(pressedKeys.begin(), pressedKeys.end(), keyCode) != pressedKeys.end();
}

bool JsInputMonitor::GetPressedKey(const std::vector<int32_t>& pressedKeys, napi_value result)
{
    CALL_DEBUG_ENTER;
    bool isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_CTRL_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_CTRL_RIGHT);
    if (SetNameProperty(jsEnv_, result, "ctrlKey", isExists) != napi_ok) {
        THROWERR(jsEnv_, "Set ctrlKey with failed");
        return false;
    }
    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_ALT_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_ALT_RIGHT);
    if (SetNameProperty(jsEnv_, result, "altKey", isExists) != napi_ok) {
        THROWERR(jsEnv_, "Set altKey failed");
        return false;
    }
    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_SHIFT_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_SHIFT_RIGHT);
    if (SetNameProperty(jsEnv_, result, "shiftKey", isExists) != napi_ok) {
        THROWERR(jsEnv_, "Set shiftKey failed");
        return false;
    }
    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_META_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_META_RIGHT);
    if (SetNameProperty(jsEnv_, result, "logoKey", isExists) != napi_ok) {
        THROWERR(jsEnv_, "Set logoKey failed");
        return false;
    }
    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_FN);
    if (SetNameProperty(jsEnv_, result, "fnKey", isExists) != napi_ok) {
        THROWERR(jsEnv_, "Set fnKey failed");
        return false;
    }
    return true;
}

int32_t JsInputMonitor::TransformTsActionValue(int32_t pointerAction)
{
    switch (pointerAction) {
        case PointerEvent::POINTER_ACTION_CANCEL: {
            return CANCEL;
        }
        case PointerEvent::POINTER_ACTION_MOVE: {
            return MOVE;
        }
        case PointerEvent::POINTER_ACTION_BUTTON_DOWN: {
            return BUTTON_DOWN;
        }
        case PointerEvent::POINTER_ACTION_BUTTON_UP: {
            return BUTTON_UP;
        }
        case PointerEvent::POINTER_ACTION_AXIS_BEGIN: {
            return AXIS_BEGIN;
        }
        case PointerEvent::POINTER_ACTION_AXIS_UPDATE: {
            return AXIS_UPDATE;
        }
        case PointerEvent::POINTER_ACTION_AXIS_END: {
            return AXIS_END;
        }
        default: {
            MMI_HILOGE("Abnormal pointer action");
            return RET_ERR;
        }
    }
}

int32_t JsInputMonitor::TransformMousePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t actionValue = TransformTsActionValue(pointerEvent->GetPointerAction());
    if (actionValue == RET_ERR) {
        MMI_HILOGE("Transform Action Value failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "action", actionValue) != napi_ok) {
        MMI_HILOGE("Set property of action failed");
        return RET_ERR;
    }
    std::vector<int32_t> pressedKeys = pointerEvent->GetPressedKeys();
    if (!GetPressedKeys(pressedKeys, result)) {
        MMI_HILOGE("Get pressedButtons failed");
        return RET_ERR;
    }
    if (!GetPressedKey(pressedKeys, result)) {
        MMI_HILOGE("Get singlePressedKey failed");
        return RET_ERR;
    }
    if (GetMousePointerItem(pointerEvent, result) != RET_OK) {
        MMI_HILOGE("Get item of mousePointer failed");
        return RET_ERR;
    }
    std::set<int32_t> pressedButtons = pointerEvent->GetPressedButtons();
    if (!GetPressedButtons(pressedButtons, result)) {
        MMI_HILOGE("Get pressedKeys failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t JsInputMonitor::Start()
{
    CALL_DEBUG_ENTER;
    CHKPF(monitor_);
    if (isMonitoring_) {
        MMI_HILOGW("Js is monitoring");
        return RET_OK;
    }
    int32_t ret = monitor_->Start();
    if (ret >= 0) {
        isMonitoring_ = true;
    }
    return ret;
}

JsInputMonitor::~JsInputMonitor()
{
    CALL_DEBUG_ENTER;
    if (isMonitoring_) {
        isMonitoring_ = false;
        if (monitor_ != nullptr) {
            monitor_->Stop();
        }
    }
    uint32_t refCount = 0;
    auto status = napi_reference_unref(jsEnv_, receiver_, &refCount);
    if (status != napi_ok) {
        THROWERR(jsEnv_, "napi_reference_unref is failed");
        return;
    }
}

void JsInputMonitor::Stop()
{
    CALL_DEBUG_ENTER;
    CHKPV(monitor_);
    if (isMonitoring_) {
        isMonitoring_ = false;
        if (monitor_ != nullptr) {
            monitor_->Stop();
        }
    }
}

int32_t JsInputMonitor::GetId() const
{
    return monitorId_;
}

std::string JsInputMonitor::GetTypeName() const
{
    return typeName_;
}

void JsInputMonitor::OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    if (!isMonitoring_) {
        MMI_HILOGE("Js monitor stop");
        return;
    }
    CHKPV(monitor_);
    CHKPV(pointerEvent);
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!evQueue_.empty()) {
            if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN ||
                pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
                auto markProcessedEvent = evQueue_.front();
                CHKPV(markProcessedEvent);
                markProcessedEvent->MarkProcessed();
                std::queue<std::shared_ptr<PointerEvent>> tmp;
                std::swap(evQueue_, tmp);
                evQueue_.push(pointerEvent);
            }
        } else {
            evQueue_.push(pointerEvent);
        }
        jsTaskNum_ = 1;
    }

    if (!evQueue_.empty()) {
        int32_t *id = &monitorId_;
        uv_work_t *work = new (std::nothrow) uv_work_t;
        CHKPV(work);
        work->data = id;
        uv_loop_s *loop = nullptr;
        auto status = napi_get_uv_event_loop(jsEnv_, &loop);
        if (status != napi_ok) {
            THROWERR(jsEnv_, "napi_get_uv_event_loop is failed");
            delete work;
            {
                std::lock_guard<std::mutex> guard(mutex_);
                jsTaskNum_ = 0;
            }
            return;
        }
        uv_queue_work(loop, work, [](uv_work_t *work) {}, &JsInputMonitor::JsCallback);
    }
}

void JsInputMonitor::JsCallback(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    int32_t *id = static_cast<int32_t *>(work->data);
    delete work;
    work = nullptr;
    auto& jsMonitor {JsInputMonMgr.GetMonitor(*id)};
    CHKPV(jsMonitor);
    jsMonitor->OnPointerEventInJsThread(jsMonitor->GetTypeName());
    id = nullptr;
}

void JsInputMonitor::OnPointerEventInJsThread(const std::string &typeName)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    jsTaskNum_ = 0;
    if (!isMonitoring_) {
        MMI_HILOGE("Js monitor stop");
        return;
    }
    CHKPV(jsEnv_);
    CHKPV(receiver_);
    while (!evQueue_.empty()) {
        if (!isMonitoring_) {
            MMI_HILOGE("Js monitor stop handle callback");
            break;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(jsEnv_, &scope);
        if (scope == nullptr) {
            MMI_HILOGE("scope is nullptr");
            return;
        }
        auto pointerEvent = evQueue_.front();
        CHKPC(pointerEvent);
        evQueue_.pop();
        napi_value napiPointer = nullptr;
        auto status = napi_create_object(jsEnv_, &napiPointer);
        if (status != napi_ok) {
            pointerEvent->MarkProcessed();
            break;
        }
        auto ret = RET_ERR;
        if (typeName == "touch") {
            ret = TransformPointerEvent(pointerEvent, napiPointer);
        } else {
            ret = TransformMousePointerEvent(pointerEvent, napiPointer);
        }
        if (ret != RET_OK || napiPointer == nullptr) {
            pointerEvent->MarkProcessed();
            break;
        }
        napi_value callback = nullptr;
        status = napi_get_reference_value(jsEnv_, receiver_, &callback);
        if (status != napi_ok) {
            pointerEvent->MarkProcessed();
            break;
        }
        napi_value result = nullptr;
        status = napi_call_function(jsEnv_, nullptr, callback, 1, &napiPointer, &result);
        if (status != napi_ok) {
            pointerEvent->MarkProcessed();
            break;
        }
        if (typeName == "touch") {
            pointerEvent->MarkProcessed();
            bool retValue = false;
            status = napi_get_value_bool(jsEnv_, result, &retValue);
            if (status != napi_ok) {
                return;
            }
            if (retValue) {
                auto eventId = pointerEvent->GetId();
                MarkConsumed(eventId);
            }
        }
        napi_close_handle_scope(jsEnv_, scope);
    }
}
} // namespace MMI
} // namespace OHOS
