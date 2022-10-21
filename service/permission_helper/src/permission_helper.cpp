/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "permission_helper.h"
#include "proto.h"
#include "ipc_skeleton.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "PermissionHelper"};
} // namespace

PermissionHelper::PermissionHelper() {}
PermissionHelper::~PermissionHelper() {}

bool PermissionHelper::CheckPermission(uint32_t required)
{
    CALL_DEBUG_ENTER;
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType == OHOS::Security::AccessToken::TOKEN_HAP) {
        return CheckHapPermission(tokenId, required);
    } else if (tokenType == OHOS::Security::AccessToken::TOKEN_NATIVE) {
        MMI_HILOGI("Token type is native");
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
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if ((tokenType == OHOS::Security::AccessToken::TOKEN_HAP) ||
        (tokenType == OHOS::Security::AccessToken::TOKEN_NATIVE)) {
        return CheckMonitorPermission(tokenId);
    } else if (tokenType == OHOS::Security::AccessToken::TOKEN_SHELL) {
        MMI_HILOGI("Token type is shell");
        return true;
    } else {
        MMI_HILOGE("Unsupported token type:%{public}d", tokenType);
        return false;
    }
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
    MMI_HILOGI("Check hap permission success");
    return true;
}

bool PermissionHelper::CheckMonitorPermission(uint32_t tokenId)
{
    static const std::string inputMonitor = "ohos.permission.INPUT_MONITORING";
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, inputMonitor);
    if (ret != OHOS::Security::AccessToken::PERMISSION_GRANTED) {
        MMI_HILOGE("Check monitor permission failed ret:%{public}d", ret);
        return false;
    }
    MMI_HILOGI("Check monitor permission success");
    return true;
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
} // namespace MMI
} // namespace OHOS