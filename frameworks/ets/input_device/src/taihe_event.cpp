/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <algorithm>

#include "taihe_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TaiheEvent"

enum INPUT_DEVICE_CALLBACK_EVENT {
    CALLBACK_EVENT_FAILED = -1,
    CALLBACK_EVENT_SUCCESS = 1,
    CALLBACK_EVENT_EXIST = 2,
    CALLBACK_EVENT_NOT_EXIST = 3,
};

namespace OHOS {
namespace MMI {

std::mutex taiheCbMapMutex;
const std::string CHANGED_TYPE = "change";

std::shared_ptr<TaiheEvent> TaiheEvent::GetInstance()
{
    static std::shared_ptr<TaiheEvent> instance = nullptr;
    if (!instance) {
        instance = std::make_shared<TaiheEvent>();
    }
    return instance;
}

bool TaiheEvent::AddCallback(std::string const &type, callbackTypes &&cb, uintptr_t opq)
{
    std::lock_guard<std::mutex> lock(taiheCbMapMutex);
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        MMI_HILOGE("ani_env is nullptr or GlobalReference_Create failed");
        return false;
    }
    auto &cbVec = devListener_[type];
    bool isDuplicate = std::any_of(cbVec.begin(), cbVec.end(),
        [env, callbackRef](std::shared_ptr<CallbackObjects> &obj) {
        ani_boolean isEqual = false;
        return (ANI_OK == env->Reference_StrictEquals(callbackRef, obj->ref, &isEqual)) && isEqual;
    });
    if (isDuplicate) {
        env->GlobalReference_Delete(callbackRef);
        MMI_HILOGD("callback already registered");
        return false;
    }
    cbVec.emplace_back(std::make_shared<CallbackObjects>(cb, callbackRef));
    MMI_HILOGI("register callback success, type: %{public}s", type.c_str());
    return true;
}

bool TaiheEvent::RemoveCallback(std::string const &type, uintptr_t opq)
{
    std::lock_guard<std::mutex> lock(taiheCbMapMutex);
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        MMI_HILOGE("Failed to unregister %{public}s, env is nullptr", type.c_str());
        return false;
    }
    GlobalRefGuards guard(env, callbackObj);
    if (!guard) {
        MMI_HILOGE("Failed to unregister %{public}s, GlobalRefGuard is false!", type.c_str());
        return false;
    }
    const auto pred = [env, targetRef = guard.get()](std::shared_ptr<CallbackObjects> &obj) {
        ani_boolean isEqual = false;
        return (ANI_OK == env->Reference_StrictEquals(targetRef, obj->ref, &isEqual)) && isEqual;
    };
    auto &cbVec = devListener_[type];
    const auto it = std::find_if(cbVec.begin(), cbVec.end(), pred);
    if (it == cbVec.end()) {
        MMI_HILOGE("Failed to unregister %{public}s, GlobalRefGuard is false!", type.c_str());
        return false;
    }
    cbVec.erase(it);
    MMI_HILOGI("unregister callback success, type: %{public}s", type.c_str());
    return true;
}

void TaiheEvent::RegisterListener(std::string const &type, callbackTypes &&f, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    bool isListening {false};
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = devListener_.find(type);
    if (iter == devListener_.end()) {
        MMI_HILOGE("Find %{public}s failed", type.c_str());
        return;
    }
    if (!AddCallback(type, std::forward<callbackTypes>(f), opq)) {
        MMI_HILOGE("Register listener failed");
        return;
    }
    isListening = isListeningProcess_;

    if (!isListening) {
        auto ret = InputManager::GetInstance()->RegisterDevListener("change", shared_from_this());
        if (ret != RET_OK) {
            MMI_HILOGE("RegisterDevListener fail, error:%{public}d", ret);
        } else {
            isListeningProcess_ = true;
            MMI_HILOGE("Registered success");
        }
    }
}

void TaiheEvent::UnregisterListener(std::string const &type, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    bool needStopListening { false };
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = devListener_.find(type);
    if (iter == devListener_.end()) {
        MMI_HILOGE("Find %{public}s failed", type.c_str());
        return;
    }
    if (!RemoveCallback(type, opq)) {
        MMI_HILOGE("Unregister listener failed");
        return;
    }
    needStopListening = isListeningProcess_;

    if (isListeningProcess_ && iter->second.empty()) {
        needStopListening = true;
        isListeningProcess_ = false;
    }
    if (needStopListening) {
        auto ret = InputManager::GetInstance()->UnregisterDevListener("change", shared_from_this());
        if (ret != RET_OK) {
            MMI_HILOGE("UnregisterDevListener fail, error:%{public}d", ret);
        }
    }
}

void TaiheEvent::UnregisterAllListener(std::string const &type)
{
    CALL_DEBUG_ENTER;
    bool needStopListening { false };
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = devListener_.find(type);
    if (iter == devListener_.end()) {
        MMI_HILOGE("Find %{public}s failed", type.c_str());
        return;
    }
    iter->second.clear();
    if (isListeningProcess_ && iter->second.empty()) {
        needStopListening = true;
        isListeningProcess_ = false;
    }
    if (needStopListening) {
        auto ret = InputManager::GetInstance()->UnregisterDevListener("change", shared_from_this());
        if (ret != RET_OK) {
            MMI_HILOGE("UnregisterDevListener fail, error:%{public}d", ret);
        }
    }
}

TaiheEvent::TaiheEvent()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(mutex_);
    auto ret = devListener_.insert({ CHANGED_TYPE, std::vector<std::shared_ptr<CallbackObjects>>() });
    CK(ret.second, VAL_NOT_EXP);
}

TaiheEvent::~TaiheEvent()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    devListener_.clear();
    auto ret = InputManager::GetInstance()->UnregisterDevListener("change", shared_from_this());
    if (ret != RET_OK) {
        MMI_HILOGE("UnregisterDevListener fail, error:%{public}d", ret);
    }
}

void TaiheEvent::OnDeviceAdded(int32_t deviceId, const std::string &type)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto changeEvent = devListener_.find(CHANGED_TYPE);
    if (changeEvent == devListener_.end()) {
        MMI_HILOGE("%{public}s: Find %{public}s failed", __func__, CHANGED_TYPE.c_str());
        return;
    }
    for (auto &cb : changeEvent->second) {
        CHKPC(cb);
        auto &func = std::get<taihe::callback<void(TaiheDeviceListener const&)>>(cb->callback);
        TaihecType tmpType = TaihecType::from_value(type);
        TaiheChangedType cType = TaiheChangedType::make_type(tmpType);
        TaiheDeviceListener listener{ .type = cType, .deviceId = deviceId };
        func(listener);
    }
}

void TaiheEvent::OnDeviceRemoved(int32_t deviceId, const std::string &type)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto changeEvent = devListener_.find(CHANGED_TYPE);
    if (changeEvent == devListener_.end()) {
        MMI_HILOGE("%{public}s: Find %{public}s failed", __func__, CHANGED_TYPE.c_str());
        return;
    }
    for (auto &cb : changeEvent->second) {
        CHKPC(cb);
        auto &func = std::get<taihe::callback<void(TaiheDeviceListener const&)>>(cb->callback);
        TaihecType tmpType = TaihecType::from_value(type);
        TaiheChangedType cType = TaiheChangedType::make_type(tmpType);
        TaiheDeviceListener listener{ .type = cType, .deviceId = deviceId };
        func(listener);
    }
}
} // namespace MMI
} // namespace OHOS