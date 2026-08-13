/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "shortcut_user_resolver.h"

#include "account_manager.h"

namespace OHOS {
namespace MMI {
int32_t ResolveCallerUserId(SessionPtr sess)
{
    if (sess == nullptr) {
        return USER_ID_ALL;
    }
    int32_t tokenType = sess->GetTokenType();
    if (tokenType == TokenType::TOKEN_NATIVE || tokenType == TokenType::TOKEN_SHELL) {
        return USER_ID_ALL;
    }
    int32_t userId = ACCOUNT_MGR->GetAccountIdFromUid(sess->GetUid());
    if (userId <= 0) {
        userId = ACCOUNT_MGR->GetCurrentAccountId();
    }
    return userId > 0 ? userId : USER_ID_ALL;
}
} // namespace MMI
} // namespace OHOS
