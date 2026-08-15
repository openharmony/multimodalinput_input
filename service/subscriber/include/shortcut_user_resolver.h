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

#ifndef SHORTCUT_USER_RESOLVER_H
#define SHORTCUT_USER_RESOLVER_H

#include "uds_session.h"

namespace OHOS {
namespace MMI {
// USER_ID_ALL marks a global registration (SA / Shell) that is not filtered by user.
inline constexpr int32_t USER_ID_ALL { -1 };

// Returns the owning userId of the registering caller: app callers (HAP / SYSTEM_HAP) map to
// their account id, SA / Shell map to USER_ID_ALL. Implementation lives in the .cpp to keep
// account_manager.h (and its transitive deps) out of this header.
int32_t ResolveCallerUserId(SessionPtr sess);
} // namespace MMI
} // namespace OHOS
#endif // SHORTCUT_USER_RESOLVER_H
