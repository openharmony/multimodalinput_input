/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "tokenid_kit.h"

#include "mmi_log.h"
#include "proto.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PermissionHelper"

namespace OHOS {
namespace MMI {
PermissionHelper::PermissionHelper() {}
PermissionHelper::~PermissionHelper() {}

bool PermissionHelper::VerifySystemApp()
{
    MMI_HILOGD("Verify system App");
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    MMI_HILOGD("Token type is %{public}d", static_cast<int32_t>(tokenType));
    if (tokenType == OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE
        || tokenType == OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        MMI_HILOGD("Called tokenType is native, verify success");
        return true;
    }
    uint64_t accessTokenIdEx = IPCSkeleton::GetCallingFullTokenID();
    if (!OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIdEx)) {
        MMI_HILOGE("System api is called by non-system app");
        return false;
    }
    return true;
}

bool PermissionHelper::CheckPermission(uint32_t required)
{
    CALL_DEBUG_ENTER;
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType == OHOS::Security::AccessToken::TOKEN_HAP) {
        return CheckHapPermission(tokenId, required);
    } else if (tokenType == OHOS::Security::AccessToken::TOKEN_NATIVE) {
        MMI_HILOGD("Token type is native");
        return true;
    } else if (tokenType == OHOS::Security::AccessToken::TOKEN_SHELL) {
        MMI_HILOGI("Token type is shell");
        return true;
    } else {
        MMI_HILOGE("Unsupported token type:%{public}d", tokenType);
        return false;
    }
}

bool PermissionHelper::CheckMonitor()
{
    CALL_DEBUG_ENTER;
    std::string monitorPermissionCode = "ohos.permission.INPUT_MONITORING";
    return CheckHapPermission(monitorPermissionCode);
}

bool PermissionHelper::CheckInterceptor()
{
    CALL_DEBUG_ENTER;
    std::string interceptorPermissionCode = "ohos.permission.INTERCEPT_INPUT_EVENT";
    return CheckHapPermission(interceptorPermissionCode);
}

bool PermissionHelper::CheckHapPermission(uint32_t tokenId, uint32_t required)
{
    OHOS::Security::AccessToken::HapTokenInfo findInfo;
    if (OHOS::Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, findInfo) != 0) {
        MMI_HILOGE("GetHapTokenInfo failed");
        return false;
    }
    if (!((1 << findInfo.apl) & required)) {
        MMI_HILOGE("Check hap permission failed, name:%{public}s, apl:%{public}d, required:%{public}d",
            findInfo.bundleName.c_str(), findInfo.apl, required);
        return false;
    }
    MMI_HILOGD("Check hap permission success");
    return true;
}


bool PermissionHelper::CheckInfraredEmmit()
{
    CALL_DEBUG_ENTER;
    std::string infraredEmmitPermissionCode = "ohos.permission.MANAGE_INPUT_INFRARED_EMITTER";
    return CheckHapPermission(infraredEmmitPermissionCode);
}

bool PermissionHelper::CheckHapPermission(const std::string permissionCode)
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

bool PermissionHelper::CheckHapPermission(uint32_t tokenId, const std::string permissionCode)
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
        MMI_HILOGE("Check Permi: %{public}s fail for appId:%{public}d, and ret:%{public}d",
                   permissionCode.c_str(), tokenId, ret);
        return false;
    }
    MMI_HILOGD("Check permission( %{public}s) permission success", permissionCode.c_str());
    return true;
}

bool PermissionHelper::CheckDispatchControl()
{
    CALL_DEBUG_ENTER;
    std::string inputDispatchControl = "ohos.permission.INPUT_CONTROL_DISPATCHING";
    return CheckHapPermission(inputDispatchControl);
}

int32_t PermissionHelper::GetTokenType()
{
    CALL_DEBUG_ENTER;
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType == OHOS::Security::AccessToken::TOKEN_HAP) {
        return TokenType::TOKEN_HAP;
    } else if (tokenType == OHOS::Security::AccessToken::TOKEN_NATIVE) {
        return TokenType::TOKEN_NATIVE;
    }  else if (tokenType == OHOS::Security::AccessToken::TOKEN_SHELL) {
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
    std::string mousePermissionCode = "ohos.permission.MANAGE_MOUSE_CURSOR";
    return CheckHapPermission(mousePermissionCode);
}

bool PermissionHelper::CheckInputEventFilter()
{
    CALL_DEBUG_ENTER;
    std::string filterPermissionCode = "ohos.permission.INPUT_EVENT_FILTER";
    return CheckHapPermission(filterPermissionCode);
}
} // namespace MMI
} // namespace OHOS
