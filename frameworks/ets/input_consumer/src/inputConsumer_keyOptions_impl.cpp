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

#include "inputConsumer_keyOptions_impl.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AniConsumerkeyOps"

namespace OHOS {
namespace MMI {

std::string GenerateKeyOptionKey(const std::shared_ptr<KeyOption>& keyOption)
{
    std::string subKeyNames;
    if (keyOption == nullptr) {
        MMI_HILOGE("keyOption is nullptr");
        return subKeyNames;
    }
    const std::set<int32_t>& preKeys = keyOption->GetPreKeys();
    int32_t finalKey = keyOption->GetFinalKey();
    bool isFinalKeyDown = keyOption->IsFinalKeyDown();
    int32_t finalKeyDownDuration = keyOption->GetFinalKeyDownDuration();
    bool isRepeat = keyOption->IsRepeat();
    for (const auto& key : preKeys) {
        subKeyNames.append(std::to_string(key)).append(",");
    }
    subKeyNames.append(std::to_string(finalKey)).append(",");
    subKeyNames.append(std::to_string(isFinalKeyDown)).append(",");
    subKeyNames.append(std::to_string(finalKeyDownDuration)).append(",");
    subKeyNames.append(std::to_string(isRepeat));
    return subKeyNames;
}

inputConsumer::KeyOptions ConvertTaiheKeyOptions(std::shared_ptr<KeyOption> keyOption)
{
    CALL_DEBUG_ENTER;
    inputConsumer::KeyOptions result {};
    if (keyOption == nullptr) {
        MMI_HILOGE("keyOption invalid");
        return result;
    }
    std::set<int32_t> preKeysSet = keyOption->GetPreKeys();
    std::vector<int32_t> preKeysVec(preKeysSet.begin(), preKeysSet.end());
    result.preKeys =  taihe::array<int32_t>(preKeysVec);
    result.finalKey  = keyOption->GetFinalKey();
    result.isFinalKeyDown = keyOption->IsFinalKeyDown();
    result.finalKeyDownDuration = keyOption->GetFinalKeyDownDuration();
    bool isRepeatValue = keyOption->IsRepeat();
    result.isRepeat = taihe::optional<bool>(std::in_place, isRepeatValue);
    return result;
}
} // namespace MMI
} // namespace OHOS