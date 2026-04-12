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
    int32_t triggerType = keyOption->GetTriggerType();
    for (const auto& key : preKeys) {
        subKeyNames.append(std::to_string(key)).append(",");
    }
    if (triggerType != 0) {
        // New API (onKeyCommand) format: preKeys,finalKey,finalKeyDownDuration,triggerType,false,
        // Must match ETS GetEventInfoAPI26 format
        subKeyNames.append(std::to_string(keyOption->GetFinalKey())).append(",");
        subKeyNames.append(std::to_string(keyOption->GetFinalKeyDownDuration())).append(",");
        subKeyNames.append(std::to_string(triggerType)).append(",");
        subKeyNames.append("false,");
    } else {
        // Old API (on('key')) format: preKeys,finalKey,isFinalKeyDown,finalKeyDownDuration,isRepeat
        // Must match ETS GetEventInfoAPI9 format
        subKeyNames.append(std::to_string(keyOption->GetFinalKey())).append(",");
        subKeyNames.append(std::to_string(keyOption->IsFinalKeyDown())).append(",");
        subKeyNames.append(std::to_string(keyOption->GetFinalKeyDownDuration())).append(",");
        subKeyNames.append(std::to_string(keyOption->IsRepeat()));
    }
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
    if (keyOption->GetTriggerType() != 0) {
        result.triggerType = taihe::optional<inputConsumer::KeyCommandTriggerType>(
            std::in_place, static_cast<inputConsumer::KeyCommandTriggerType::key_t>(keyOption->GetTriggerType()));
    }
    return result;
}
} // namespace MMI
} // namespace OHOS