/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "permission_helper.h"

#include "ipc_skeleton.h"
#include "privacy_kit.h"
#include "tokenid_kit.h"

#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PermissionHelper"

namespace OHOS {
namespace MMI {
namespace {
    const std::string INJECT_PERMISSION_CODE = "ohos.permission.INJECT_INPUT_EVENT";
    const std::string MONITOR_PERMISSION_CODE = "ohos.permission.INPUT_MONITORING";
    const std::string INTERCEPT_PERMISSION_CODE = "ohos.permission.INTERCEPT_INPUT_EVENT";
    const std::string INFRAREDEMITTER_PERMISSION_CODE = "ohos.permission.MANAGE_INPUT_INFRARED_EMITTER";
    const std::string CONTROL_DISPATCHING_PERMISSION_CODE = "ohos.permission.INPUT_CONTROL_DISPATCHING";
    const std::string MOUSE_CURSOR_PERMISSION_CODE = "ohos.permission.MANAGE_MOUSE_CURSOR";
    const std::string FILTER_PERMISSION_CODE = "ohos.permission.FILTER_INPUT_EVENT";
    const std::string DEVICE_CONTROLLER_PERMISSION_CODE = "ohos.permission.INPUT_DEVICE_CONTROLLER";
    const std::string KEYBOARD_CONTROLLER_PERMISSION_CODE = "ohos.permission.INPUT_KEYBOARD_CONTROLLER";
    const std::string KEY_EVENT_HOOK_PERMISSION_CODE = "ohos.permission.HOOK_KEY_EVENT";
} // namespace
bool PermissionHelper::VerifySystemApp()
{
    MMI_HILOGD("verify system App");
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    MMI_HILOGD("token type is %{public}d", static_cast<int32_t>(tokenType));
    if (tokenType == OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE
        || tokenType == OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        MMI_HILOGD("called tokenType is native, verify success");
        return true;
    }
    uint64_t accessTokenIdEx = IPCSkeleton::GetCallingFullTokenID();
    if (!OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIdEx)) {
        MMI_HILOGE("system api is called by non-system app");
        return false;
    }
    return true;
}

bool PermissionHelper::CheckInjectPermission()
{
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    MMI_HILOGD("Token type is %{public}d", static_cast<int32_t>(tokenType));
    if (tokenType == OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        MMI_HILOGD("called tokenType is shell, verify success");
        return true;
    }
    
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, INJECT_PERMISSION_CODE);
    if (ret != OHOS::Security::AccessToken::PERMISSION_GRANTED) {
        MMI_HILOGE("Check Permission:%{public}s fail for appId:%{public}d, and ret:%{public}d",
                   INJECT_PERMISSION_CODE.c_str(), tokenId, ret);
        return false;
    }
    return true;
}

bool PermissionHelper::CheckMonitor()
{
    CALL_DEBUG_ENTER;
    return CheckHapPermission(MONITOR_PERMISSION_CODE);
}

bool PermissionHelper::CheckInterceptor()
{
    CALL_DEBUG_ENTER;
    return CheckHapPermission(INTERCEPT_PERMISSION_CODE);
}

bool PermissionHelper::CheckInfraredEmmit()
{
    CALL_DEBUG_ENTER;
    return CheckHapPermission(INFRAREDEMITTER_PERMISSION_CODE);
}

bool PermissionHelper::CheckAuthorize()
{
    CALL_DEBUG_ENTER;
    return CheckHapPermission(INJECT_PERMISSION_CODE);
}

bool PermissionHelper::CheckKeyEventHook()
{
    CALL_DEBUG_ENTER;
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckHapPermission(KEY_EVENT_HOOK_PERMISSION_CODE)) {
        MMI_HILOGE("CheckHapPermission %{public}s failed", KEY_EVENT_HOOK_PERMISSION_CODE.c_str());
        AddPermissionUsedRecord(tokenId, KEY_EVENT_HOOK_PERMISSION_CODE, 0, 1);
        return false;
    }
    MMI_HILOGI("CheckHapPermission %{public}s success", KEY_EVENT_HOOK_PERMISSION_CODE.c_str());
    AddPermissionUsedRecord(tokenId, KEY_EVENT_HOOK_PERMISSION_CODE, 1, 0);
    return true;
}

bool PermissionHelper::AddPermissionUsedRecord(Security::AccessToken::AccessTokenID tokenID,
    const std::string& permissionName, int32_t successCount, int32_t failCount)
{
    if (int32_t ret = Security::AccessToken::PrivacyKit::AddPermissionUsedRecord(
        tokenID, permissionName, successCount, failCount) != RET_OK) {
        MMI_HILOGW("AddPermissionUsedRecord %{public}s failed, ret:%{public}d succ:%{public}d, fail:%{public}d",
            permissionName.c_str(), ret, successCount, failCount);
        return false;
    }
    MMI_HILOGI("AddPermissionUsedRecord %{public}s success, succ:%{public}d, fail:%{public}d",
        permissionName.c_str(), successCount, failCount);
    return true;
}

bool PermissionHelper::CheckHapPermission(const std::string &permissionCode)
{
    CALL_DEBUG_ENTER;
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
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

bool PermissionHelper::CheckHapPermission(uint32_t tokenId, const std::string &permissionCode)
{
    CALL_DEBUG_ENTER;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if ((tokenType == OHOS::Security::AccessToken::TOKEN_HAP) ||
        (tokenType == OHOS::Security::AccessToken::TOKEN_NATIVE)) {
    } else if (tokenType == OHOS::Security::AccessToken::TOKEN_SHELL) {
        MMI_HILOGI("Token type is shell");
        return true;
    } else {
        MMI_HILOGE("Unsupported token type:%{public}d", tokenType);
        return false;
    }
    std::string context = "For CheckPerm. PermiCode" + permissionCode + ";appId:" + std::to_string(tokenId);
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permissionCode);
    if (ret != OHOS::Security::AccessToken::PERMISSION_GRANTED) {
        MMI_HILOGE("Check Permi:%{public}s fail for appId:%{public}d, and ret:%{public}d",
                   permissionCode.c_str(), tokenId, ret);
        return false;
    }
    MMI_HILOGD("Check permission( %{public}s) permission success", permissionCode.c_str());
    return true;
}

bool PermissionHelper::CheckDispatchControl()
{
    CALL_DEBUG_ENTER;
    return CheckHapPermission(CONTROL_DISPATCHING_PERMISSION_CODE);
}

int32_t PermissionHelper::GetTokenType()
{
    CALL_DEBUG_ENTER;
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType == OHOS::Security::AccessToken::TOKEN_HAP) {
        uint64_t accessTokenIdEx = IPCSkeleton::GetCallingFullTokenID();
        if (OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIdEx)) {
            return TokenType::TOKEN_SYSTEM_HAP;
        }
        return TokenType::TOKEN_HAP;
    } else if (tokenType == OHOS::Security::AccessToken::TOKEN_NATIVE) {
        return TokenType::TOKEN_NATIVE;
    } else if (tokenType == OHOS::Security::AccessToken::TOKEN_SHELL) {
        return TokenType::TOKEN_SHELL;
    } else {
        MMI_HILOGW("Unsupported token type:%{public}d", tokenType);
        return TokenType::TOKEN_INVALID;
    }
}

bool PermissionHelper::RequestFromShell()
{
    CALL_DEBUG_ENTER;
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    MMI_HILOGD("Token type is %{public}d", static_cast<int32_t>(tokenType));
    return tokenType == OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL;
}

bool PermissionHelper::CheckMouseCursor()
{
    CALL_DEBUG_ENTER;
    return CheckHapPermission(MOUSE_CURSOR_PERMISSION_CODE);
}

bool PermissionHelper::CheckInputEventFilter()
{
    CALL_DEBUG_ENTER;
    return CheckHapPermission(FILTER_PERMISSION_CODE);
}

bool PermissionHelper::CheckInputDeviceController()
{
    CALL_DEBUG_ENTER;
    return CheckHapPermission(DEVICE_CONTROLLER_PERMISSION_CODE);
}

bool PermissionHelper::CheckFunctionKeyEnabled()
{
    CALL_DEBUG_ENTER;
    return CheckHapPermission(KEYBOARD_CONTROLLER_PERMISSION_CODE);
}
} // namespace MMI
} // namespace OHOS
