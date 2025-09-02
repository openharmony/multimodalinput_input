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

#include "ani_common.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "aniCommon"

namespace OHOS {
namespace MMI {
bool TaiheConverter::GetApiError(int32_t code, TaiheError &codeMsg)
{
    auto iter = TAIHE_ERRORS.find(code);
    if (iter == TAIHE_ERRORS.end()) {
        return false;
    }
    codeMsg = iter->second;
    return true;
}
} // namespace MMI
} // namespace OHOS