/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ani_input_monitor_manager.h"

#include <algorithm>
#include <sstream>
#include <iostream>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "define_multimodal.h"
#include "input_manager.h"
#include "tokenid_kit.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AniInputMonitorManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MONITOR_REGISTER_EXCEED_MAX { 4100001 };
const std::string HAP_MONITOR_PERMISSION_NAME = "ohos.permission.INPUT_MONITORING";
const std::string MODULE_NAME = "monitor";
} // namespace

static const std::vector<int32_t> supportedKeyCodes = {
    KeyEvent::KEYCODE_POWER,
    KeyEvent::KEYCODE_META_LEFT,
    KeyEvent::KEYCODE_VOLUME_UP,
    KeyEvent::KEYCODE_VOLUME_DOWN,
    KeyEvent::KEYCODE_META_RIGHT
};


AniInputMonitorManager& AniInputMonitorManager::GetInstance()
{
    static AniInputMonitorManager instance;
    return instance;
}

std::shared_ptr<AniInputMonitorConsumer> AniInputMonitorManager::GetMonitor(int32_t monitorId)
{
    std::lock_guard<std::mutex> guard(mutex_);
    auto itFind = monitors_.find(monitorId);
    if (itFind != monitors_.end()) {
        return itFind->second;
    }
    return nullptr;
}


TaiheTouchEventArray AniInputMonitorManager::QueryTouchEvents(int32_t count)
{
    CALL_DEBUG_ENTER;
    std::vector<std::shared_ptr<PointerEvent>> touchEventList;
    TaiheTouchEventArray result{};
    int32_t ret = InputManager::GetInstance()->QueryPointerRecord(count, touchEventList);
    if (ret < 0) {
        if (ret == ERROR_NO_PERMISSION) {
            taihe::set_business_error(-ret, "Permission denied.");
            return result;
        }
        return result;
    }
    if (ret == ERROR_NOT_SYSAPI) {
        taihe::set_business_error(ret, "Permission denied, non-system application called system api.");
        return result;
    }
    if (ret != 0) {
        taihe::set_business_error(ret, "unknown error");
        return result;
    }
    std::vector<TaiheTouchEvent> vecProperty;
    MMI_HILOGD("ret:%{public}d!, touchEventList size:%{public}zu", ret, touchEventList.size());
    for (const auto &per : touchEventList) {
        TaiheTouchEvent taiheItem {.action = TaiheTouchAction::key_t::CANCEL,
                .touch = TaiheTouch {.toolType = TaiheToolType::key_t::FINGER},
                .sourceType = TaiheSourceType::key_t::TOUCH_SCREEN };
        auto ret = TaiheMonitorConverter::TouchEventToTaihe(*per, taiheItem);
        if (ret != RET_OK) {
            taihe::set_business_error(ret, "unknown error");
            return result;
        }
        vecProperty.push_back(taiheItem);
    }
    result = taihe::array<TaiheTouchEvent>(vecProperty);
    return result;
}

bool AniInputMonitorManager::CreateCallback(callbackType &&cb, uintptr_t opq, std::shared_ptr<CallbackObject> &callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_); // map 锁加在外面
    std::lock_guard<std::mutex> lock(jsCbMapMutex_);
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        MMI_HILOGE("ani_env is nullptr or GlobalReference_Create failed");
        return false;
    }
    bool isDuplicate = std::any_of(monitors_.begin(), monitors_.end(),
        [env, callbackRef](const auto& it) {
        ani_boolean isEqual = false;
        if (ANI_OK != env->Reference_StrictEquals(callbackRef, it.second->GetCallback()->ref, &isEqual)) {
            MMI_HILOGD("Reference_StrictEquals error");
            return isEqual;
        }
        return isEqual;
    });
    if (isDuplicate) {
        env->GlobalReference_Delete(callbackRef);
        MMI_HILOGD("callback already registered");
        return false;
    }
    callback = std::make_shared<CallbackObject>(cb, callbackRef);
    return true;
}

bool AniInputMonitorManager::IsExistCallback(const std::shared_ptr<CallbackObject> &callback,
    taihe::optional_view<uintptr_t> opq)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(jsCbMapMutex_);
    if (!opq.has_value()) {
        MMI_HILOGE("callback is nullptr!");
        return false;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        MMI_HILOGE("ani_env is nullptr!");
        return false;
    }
    GlobalRefGuard guard(env, reinterpret_cast<ani_object>(opq.value()));
    if (!guard) {
        MMI_HILOGE("GlobalRefGuard is false!");
        return false;
    }
    ani_boolean isEqual = false;
    auto result = env->Reference_StrictEquals(guard.get(), callback->ref, &isEqual);
    if (result != ANI_OK) {
        MMI_HILOGE("ani_env Reference_StrictEquals failed");
        return false;
    }
    if (isEqual) {
        MMI_HILOGI("Callback exists.");
    } else {
        MMI_HILOGI("Callback does not exist.");
    }
    return isEqual;
}

bool AniInputMonitorManager::AddMonitor(MONITORFUNTYPE funType,
    const ConsumerParmType &param, callbackType &&cb, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    if (!AniInputMonitorConsumer::IsOnFunc(funType)) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "EventType is invalid");
        return false;
    }
    if (!IsSystemApp()) {
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return false;
    }
    std::shared_ptr<AniInputMonitorConsumer> consumer = AniInputMonitorConsumer::CreateAniInputMonitorConsumer(
        funType, param, std::move(cb), opq);
    if (!consumer) {
        MMI_HILOGE("ani create consumer failed");
        return false;
    }
    int32_t retStart = consumer->Start();
    MMI_HILOGD("ani monitor startup retStart %{public}d", retStart);
    if (retStart < 0) {
        ThrowError(retStart);
        return false;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    monitors_.emplace(retStart, consumer);
    return true;
}

bool AniInputMonitorManager::RemoveMonitor(MONITORFUNTYPE funType, taihe::optional_view<uintptr_t> opq, int32_t fingers)
{
    CALL_DEBUG_ENTER;
    if (!AniInputMonitorConsumer::IsOnFunc(funType)) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "EventType is invalid");
        return false;
    }
    if (!IsSystemApp()) {
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return false;
    }
    if (!CheckPermission(HAP_MONITOR_PERMISSION_NAME)) {
        std::string errMsg = MakePermissionCheckErrMsg(MODULE_NAME, HAP_MONITOR_PERMISSION_NAME);
        taihe::set_business_error(COMMON_PERMISSION_CHECK_ERROR, errMsg);
        return false;
    }
    std::lock_guard guard(mutex_);
    if (!opq.has_value()) {
        for (auto it = monitors_.begin(); it != monitors_.end();) {
            auto monitor = it->second;
            if (monitor->CheckOffFuncParam(funType, fingers)) {
                monitor->Stop();
                it = monitors_.erase(it);
            } else {
                ++it;
            }
        }
        return true;
    }

    for (auto it = monitors_.begin(); it != monitors_.end();) {
        auto monitor = it->second;
        bool needDel = false;
        if (monitor->CheckOffFuncParam(funType, fingers)) {
            if (IsExistCallback(monitor->GetCallback(), opq)) {
                needDel = true;
            }
        }
        if (needDel) {
            monitor->Stop();
            it = monitors_.erase(it);
        } else {
            ++it;
        }
    }
    return true;
}

bool AniInputMonitorManager::CheckKeyCode(const int32_t keycode)
{
    auto it = std::find(supportedKeyCodes.begin(), supportedKeyCodes.end(), keycode);
    if (it == supportedKeyCodes.end()) {
        MMI_HILOGE("PreKeys is not expect");
        return false;
    }
    return true;
}

void AniInputMonitorManager::ThrowError(int32_t code)
{
    int32_t errorCode = -code;
    if (errorCode == MONITOR_REGISTER_EXCEED_MAX) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Maximum number of listeners exceeded for a single process");
    } else if (errorCode == COMMON_PERMISSION_CHECK_ERROR) {
        std::string errMsg = MakePermissionCheckErrMsg(MODULE_NAME, HAP_MONITOR_PERMISSION_NAME);
        taihe::set_business_error(COMMON_PERMISSION_CHECK_ERROR, errMsg);
    } else if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode == COMMON_PARAMETER_ERROR) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    } else {
        MMI_HILOGE("Add monitor failed");
    }
}

std::string AniInputMonitorManager::MakePermissionCheckErrMsg(const std::string &moduleName,
    const std::string &permissionName)
{
    std::stringstream ss;
    ss << "Permission denied. An attempt was made to "
    << moduleName << "forbidden by permission " <<  permissionName << ".";
    return ss.str();
}

bool AniInputMonitorManager::IsSystemApp()
{
    static bool isSystemApp = []() {
        uint64_t tokenId = OHOS::IPCSkeleton::GetSelfTokenID();
        return OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
    }();
    return isSystemApp;
}

bool AniInputMonitorManager::CheckPermission(const std::string &permissionCode)
{
    CALL_DEBUG_ENTER;
    uint64_t tokenId = IPCSkeleton::GetSelfTokenID();
    using OHOS::Security::AccessToken::AccessTokenID;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(static_cast<AccessTokenID>(tokenId));
    if ((tokenType == OHOS::Security::AccessToken::TOKEN_HAP) ||
        (tokenType == OHOS::Security::AccessToken::TOKEN_NATIVE)) {
        int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permissionCode);
        if (ret != OHOS::Security::AccessToken::PERMISSION_GRANTED) {
            MMI_HILOGE("Check permission failed ret:%{public}d permission:%{public}s", ret, permissionCode.c_str());
            return false;
        }
        MMI_HILOGD("Check interceptor permission success permission:%{public}s", permissionCode.c_str());
        return true;
    } else if (tokenType == OHOS::Security::AccessToken::TOKEN_SHELL) {
        MMI_HILOGI("Token type is shell");
        return true;
    } else {
        MMI_HILOGE("Unsupported token type:%{public}d", tokenType);
        return false;
    }
}
} // namespace MMI
} // namespace OHOS
