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

#ifndef KEY_COMMAND_CONTEXT_H
#define KEY_COMMAND_CONTEXT_H

#include "key_command_types.h"

namespace OHOS {
namespace MMI {
class KeyCommandContext {
public:
    std::map<std::string, ShortcutKey>* shortcutKeys_ { nullptr };
    std::vector<Sequence>* sequences_ { nullptr };
    std::vector<RepeatKey>* repeatKeys_ { nullptr };
    std::vector<ExcludeKey>* excludeKeys_ { nullptr };
    bool isParseConfig_ { false };
    bool isParseExcludeConfig_ { false };
    std::vector<std::string> businessIds_;

    int64_t lastVolumeDownActionTime_ { 0 };
    int32_t count_ { 0 };
    int32_t launchAbilityCount_ { 0 };
    int32_t maxCount_ { 0 };
    int64_t intervalTime_ { 120000 };
    int64_t walletLaunchDelayTimes_ { 0 };
    bool isDownStart_ { false };
    bool isHandleSequence_ { false };
    std::atomic<bool> isFreezePowerKey_ { false };

    RepeatKey repeatKey_;
    std::map<std::string, int32_t> repeatKeyCountMap_;
    std::map<int32_t, int32_t> repeatKeyMaxTimes_;
    int32_t sosDelayTimerId_ { -1 };
    std::map<int32_t, std::list<int32_t>> specialTimers_;
    std::map<int32_t, int32_t> specialKeys_;
    TwoFingerGesture twoFingerGesture_;

public:
    bool IsValid() const
    {
        return (shortcutKeys_ != nullptr) && (sequences_ != nullptr) &&
            (repeatKeys_ != nullptr) && (excludeKeys_ != nullptr);
    }
};
} // namespace MMI
} // namespace OHOS
#endif // KEY_COMMAND_CONTEXT_H
