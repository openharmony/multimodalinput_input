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

#include "inputConsumer_hotkeyOptions_impl.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "inputConsumer_hotkeyOptions_impl"

namespace OHOS {
namespace MMI {

HotkeyOptions ConvertTaiheHotkeyOptions(std::shared_ptr<KeyOption> keyOption)
{
    if (keyOption == nullptr) {
        MMI_HILOGE("keyOption invalid");
        return {
            taihe::array<int32_t>(nullptr, 0),
            0,
            taihe::optional<bool>(std::nullopt)
        };
    }
    std::set<int32_t> preKeysSet = keyOption->GetPreKeys();
    std::vector<int32_t> preKeysVec(preKeysSet.begin(), preKeysSet.end());
    bool isRepeatValue = keyOption->IsRepeat();
    return {
        taihe::array<int32_t>(preKeysVec),
        keyOption->GetFinalKey(),
        taihe::optional<bool>(&isRepeatValue)
    };
}
} // namespace MMI
} // namespace OHOS