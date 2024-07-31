/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "js_input_monitor_manager.h"

#include <uv.h>

#include "define_multimodal.h"
#include "napi_constants.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsInputMonitorManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MONITOR_REGISTER_EXCEED_MAX { 4100001 };
} // namespace

JsInputMonitorManager& JsInputMonitorManager::GetInstance()
{
    static JsInputMonitorManager instance;
    return instance;
}

void JsInputMonitorManager::AddMonitor(napi_env jsEnv, const std::string &typeName,
    std::vector<Rect> hotRectArea, int32_t rectTotal, napi_value callback, const int32_t fingers)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    for (const auto &item : monitors_) {
        if ((item != nullptr) && (item->IsMatch(jsEnv, callback) != RET_ERR)) {
            MMI_HILOGW("Add js monitor failed");
            return;
        }
    }
    auto monitor = std::make_shared<JsInputMonitor>(jsEnv, typeName, hotRectArea,
        rectTotal, callback, nextId_++, fingers);
    int32_t ret = monitor->Start();
    if (ret < 0) {
        MMI_HILOGE("Js monitor startup failed");
        ThrowError(jsEnv, ret);
        return;
    }
    monitors_.push_back(monitor);
}

void JsInputMonitorManager::AddMonitor(napi_env jsEnv, const std::string &typeName,
    napi_value callback, const int32_t fingers)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    for (const auto &item : monitors_) {
        if ((item != nullptr) && (item->IsMatch(jsEnv, callback) != RET_ERR)) {
            MMI_HILOGW("Add js monitor failed");
            return;
        }
    }
    auto monitor = std::make_shared<JsInputMonitor>(jsEnv, typeName, callback, nextId_++, fingers);
    int32_t ret = monitor->Start();
    if (ret < 0) {
        MMI_HILOGE("Js monitor startup failed");
        ThrowError(jsEnv, ret);
        return;
    }
    monitors_.push_back(monitor);
}

void JsInputMonitorManager::RemoveMonitor(napi_env jsEnv, const std::string &typeName, napi_value callback,
    const int32_t fingers)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<JsInputMonitor> monitor = nullptr;
    do {
        std::lock_guard<std::mutex> guard(mutex_);
        for (auto it = monitors_.begin(); it != monitors_.end();) {
            if ((*it) == nullptr) {
                monitors_.erase(it++);
                continue;
            }
            if (IsFindJsInputMonitor(*it, jsEnv, typeName, callback, fingers)) {
                monitor = *it;
                monitors_.erase(it++);
                MMI_HILOGD("Found monitor");
                break;
            }
            ++it;
        }
    } while (0);
    if (monitor != nullptr) {
        monitor->Stop();
    }
}

void JsInputMonitorManager::RemoveMonitor(napi_env jsEnv, const std::string &typeName, const int32_t fingers)
{
    CALL_DEBUG_ENTER;
    std::list<std::shared_ptr<JsInputMonitor>> monitors;
    do {
        std::lock_guard<std::mutex> guard(mutex_);
        for (auto it = monitors_.begin(); it != monitors_.end();) {
            if ((*it) == nullptr) {
                monitors_.erase(it++);
                continue;
            }
            if (IsFindJsInputMonitor(*it, jsEnv, typeName, fingers)) {
                monitors.push_back(*it);
                monitors_.erase(it++);
                continue;
            }
            ++it;
        }
    } while (0);

    for (const auto &item : monitors) {
        if (item != nullptr) {
            item->Stop();
        }
    }
}

void JsInputMonitorManager::RemoveMonitor(napi_env jsEnv)
{
    CALL_DEBUG_ENTER;
    std::list<std::shared_ptr<JsInputMonitor>> monitors;
    do {
        std::lock_guard<std::mutex> guard(mutex_);
        for (auto it = monitors_.begin(); it != monitors_.end();) {
            if ((*it) == nullptr) {
                monitors_.erase(it++);
                continue;
            }
            if ((*it)->IsMatch(jsEnv) == RET_OK) {
                monitors.push_back(*it);
                monitors_.erase(it++);
                continue;
            }
            ++it;
        }
    } while (0);

    for (const auto &item : monitors) {
        if (item != nullptr) {
            item->Stop();
        }
    }
}

void JsInputMonitorManager::OnPointerEventByMonitorId(int32_t id, int32_t fingers,
    std::shared_ptr<PointerEvent> pointEvent)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    for (const auto &item : monitors_) {
        if ((item != nullptr) && (item->GetId() == id && item->GetFingers() == fingers)) {
            item->OnPointerEvent(pointEvent);
        }
    }
}

const std::shared_ptr<JsInputMonitor> JsInputMonitorManager::GetMonitor(int32_t id, int32_t fingers)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    for (const auto &item : monitors_) {
        if ((item != nullptr) && (item->GetId() == id && item->GetFingers() == fingers)) {
            return item;
        }
    }
    MMI_HILOGD("No monitor found");
    return nullptr;
}

std::string JsInputMonitorManager::GetMonitorTypeName(int32_t id, int32_t fingers)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    for (const auto &item : monitors_) {
        if ((item != nullptr) && (item->GetId() == id && item->GetFingers() == fingers)) {
            return item->GetTypeName();
        }
    }
    MMI_HILOGD("No monitor found");
    return "";
}

bool JsInputMonitorManager::AddEnv(napi_env env, napi_callback_info cbInfo)
{
    CALL_DEBUG_ENTER;
    if (IsExisting(env)) {
        MMI_HILOGD("Env is already existent");
        return true;
    }
    napi_value thisVar = nullptr;
    void *data = nullptr;
    int32_t *id = new (std::nothrow) int32_t;
    CHKPF(id);
    *id = 0;
    if (napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, &data) != napi_ok) {
        MMI_HILOGE("GET_CB_INFO failed");
        auto infoTemp = std::string("AddEnv GET_CB_INFO failed");
        napi_throw_error(env, nullptr, infoTemp.c_str());
        delete id;
        return false;
    }
    auto status = napi_wrap(env, thisVar, static_cast<void*>(id),
                            [](napi_env env, void *data, void *hint) {
                                MMI_HILOGD("napi_wrap enter");
                                int32_t *id = static_cast<int32_t *>(data);
                                delete id;
                                id = nullptr;
                                JS_INPUT_MONITOR_MGR.RemoveMonitor(env);
                                JS_INPUT_MONITOR_MGR.RemoveEnv(env);
                                MMI_HILOGD("napi_wrap leave");
                                }, nullptr, nullptr);
    if (status != napi_ok) {
        MMI_HILOGE("napi_wrap failed");
        delete id;
        return false;
    }
    napi_ref ref = nullptr;
    status = napi_create_reference(env, thisVar, 1, &ref);
    if (status != napi_ok) {
        MMI_HILOGE("napi_create_reference failed");
        return false;
    }
    auto iter = envManager_.insert(std::pair<napi_env, napi_ref>(env, ref));
    if (!iter.second) {
        MMI_HILOGE("Insert value failed");
        return false;
    }
    return true;
}

void JsInputMonitorManager::RemoveEnv(napi_env env)
{
    CALL_DEBUG_ENTER;
    auto it = envManager_.find(env);
    if (it == envManager_.end()) {
        MMI_HILOGD("No env found");
        return;
    }
    RemoveEnv(it);
}

void JsInputMonitorManager::RemoveEnv(std::map<napi_env, napi_ref>::iterator it)
{
    CALL_DEBUG_ENTER;
    uint32_t refCount = 0;
    CHKRV(napi_reference_unref(it->first, it->second, &refCount), REFERENCE_UNREF);
    envManager_.erase(it);
}

void JsInputMonitorManager::RemoveAllEnv()
{
    CALL_DEBUG_ENTER;
    for (auto it = envManager_.begin(); it != envManager_.end();) {
        RemoveEnv(it++);
    }
}

bool JsInputMonitorManager::IsExisting(napi_env env)
{
    CALL_DEBUG_ENTER;
    auto it = envManager_.find(env);
    if (it == envManager_.end()) {
        MMI_HILOGD("No env found");
        return false;
    }

    return true;
}

void JsInputMonitorManager::ThrowError(napi_env env, int32_t code)
{
    int32_t errorCode = -code;
    if (errorCode == MONITOR_REGISTER_EXCEED_MAX) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Maximum number of listeners exceeded for a single process");
    } else if (errorCode == COMMON_PERMISSION_CHECK_ERROR) {
        THROWERR_API9(env, COMMON_PERMISSION_CHECK_ERROR, "monitor", "ohos.permission.INPUT_MONITORING");
    } else {
        MMI_HILOGE("Add monitor failed");
    }
}

std::vector<Rect> JsInputMonitorManager::GetHotRectAreaList(napi_env env,
    napi_value rectNapiValue, uint32_t rectListLength)
{
    std::vector<Rect> hotRectAreaList;
    for (uint32_t i = 0; i < rectListLength; i++) {
        napi_value napiElement;
        CHKRR(napi_get_element(env, rectNapiValue, i, &napiElement), GET_ELEMENT, hotRectAreaList);
        Rect rectItem;
        napi_value napiX = nullptr;
        CHKRR(napi_get_named_property(env, napiElement, "left", &napiX), GET_NAMED_PROPERTY, hotRectAreaList);
        if (napiX == nullptr) {
            THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "left not found");
            return hotRectAreaList;
        }
        int32_t rectX = -1;
        CHKRR(napi_get_value_int32(env, napiX, &rectX), GET_VALUE_INT32, hotRectAreaList);
        rectItem.x = rectX;
        napi_value napiY = nullptr;
        CHKRR(napi_get_named_property(env, napiElement, "top", &napiY), GET_NAMED_PROPERTY, hotRectAreaList);
        if (napiY == nullptr) {
            THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "top not found");
            return hotRectAreaList;
        }
        int32_t rectY = -1;
        CHKRR(napi_get_value_int32(env, napiY, &rectY), GET_VALUE_INT32, hotRectAreaList);
        rectItem.y = rectY;
        napi_value napiWidth = nullptr;
        CHKRR(napi_get_named_property(env, napiElement, "width", &napiWidth), GET_NAMED_PROPERTY, hotRectAreaList);
        if (napiWidth == nullptr) {
            THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "width not found");
            return hotRectAreaList;
        }
        int32_t rectWidth = -1;
        CHKRR(napi_get_value_int32(env, napiWidth, &rectWidth), GET_VALUE_INT32, hotRectAreaList);
        rectItem.width = rectWidth;
        napi_value napiHeight = nullptr;
        CHKRR(napi_get_named_property(env, napiElement, "height", &napiHeight), GET_NAMED_PROPERTY, hotRectAreaList);
        if (napiHeight == nullptr) {
            THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "height not found");
            return hotRectAreaList;
        }
        int32_t rectHeight = -1;
        CHKRR(napi_get_value_int32(env, napiHeight, &rectHeight), GET_VALUE_INT32, hotRectAreaList);
        rectItem.height = rectHeight;
        if (rectX < 0 || rectY < 0 || rectHeight < 0 || rectWidth < 0) {
            THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Rect parameter can't be negative");
            return hotRectAreaList;
        }
        hotRectAreaList.push_back(rectItem);
    }
    return hotRectAreaList;
}

bool JsInputMonitorManager::IsFindJsInputMonitor(const std::shared_ptr<JsInputMonitor> monitor,
    napi_env jsEnv, const std::string &typeName, napi_value callback, const int32_t fingers)
{
    if ((monitor->GetTypeName() == typeName) && (monitor->GetFingers() == fingers)) {
        if (monitor->IsMatch(jsEnv, callback) == RET_OK) {
            return true;
        }
    }
    return false;
}

bool JsInputMonitorManager::IsFindJsInputMonitor(const std::shared_ptr<JsInputMonitor> monitor,
    napi_env jsEnv, const std::string &typeName, const int32_t fingers)
{
    if ((monitor->GetTypeName() == typeName) && (monitor->GetFingers() == fingers)) {
        if (monitor->IsMatch(jsEnv) == RET_OK) {
            return true;
        }
    }
    return false;
}
} // namespace MMI
} // namespace OHOS
