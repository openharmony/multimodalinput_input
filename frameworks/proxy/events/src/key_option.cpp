/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "key_option.h"

#include "config_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyOption"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t PRE_KEYS_MAX_SIZE { 4 };
}
std::set<int32_t> KeyOption::GetPreKeys() const
{
    return preKeys_;
}

void KeyOption::SetPreKeys(const std::set<int32_t> &preKeys)
{
    preKeys_ = preKeys;
}

int32_t KeyOption::GetFinalKey() const
{
    return finalKey_;
}

void KeyOption::SetFinalKey(int32_t finalKey)
{
    finalKey_ = finalKey;
}

bool KeyOption::IsFinalKeyDown() const
{
    return isFinalKeyDown_;
}
void KeyOption::SetFinalKeyDown(bool pressed)
{
    isFinalKeyDown_ = pressed;
}

int32_t KeyOption::GetFinalKeyDownDuration() const
{
    return finalKeyDownDuration_;
}

int32_t KeyOption::GetFinalKeyUpDelay() const
{
    return finalKeyUpDelay_;
}

void KeyOption::SetFinalKeyDownDuration(int32_t duration)
{
    finalKeyDownDuration_ = duration;
}

void KeyOption::SetFinalKeyUpDelay(int32_t delay)
{
    finalKeyUpDelay_ = delay;
}

bool KeyOption::IsRepeat() const
{
    return isRepeat_;
}

void KeyOption::SetRepeat(bool repeat)
{
    isRepeat_ = repeat;
}

bool KeyOption::ReadFromParcel(Parcel &in)
{
    int32_t preKeysSize = 0;
    READINT32(in, preKeysSize);
    if (preKeysSize < 0) {
        return false;
    }
    if (preKeysSize > PRE_KEYS_MAX_SIZE) {
        MMI_HILOGE("The preKeys size:%{public}d, exceeds maximum allowed size:%{public}d", preKeysSize,
            PRE_KEYS_MAX_SIZE);
        return false;
    }
    for (auto i = 0; i < preKeysSize; ++i) {
        int32_t keyValue = 0;
        READINT32(in, keyValue);
        preKeys_.insert(keyValue);
    }
    return (
        in.ReadInt32(finalKey_) &&
        in.ReadBool(isFinalKeyDown_) &&
        in.ReadInt32(finalKeyDownDuration_) &&
        in.ReadInt32(finalKeyUpDelay_) &&
        in.ReadBool(isRepeat_)
    );
}

bool KeyOption::WriteToParcel(Parcel &out) const
{
    if (preKeys_.size() > PRE_KEYS_MAX_SIZE) {
        MMI_HILOGE("The preKeys size:%{public}zu, exceeds maximum allowed size:%{public}d", preKeys_.size(),
            PRE_KEYS_MAX_SIZE);
        return false;
    }
    int32_t preKeysSize = static_cast<int32_t>(preKeys_.size());
    WRITEINT32(out, preKeysSize);
    for (const auto &i : preKeys_) {
        WRITEINT32(out, i);
    }
    return (
        out.WriteInt32(finalKey_) &&
        out.WriteBool(isFinalKeyDown_) &&
        out.WriteInt32(finalKeyDownDuration_) &&
        out.WriteInt32(finalKeyUpDelay_) &&
        out.WriteBool(isRepeat_)
    );
}
} // namespace MMI
} // namespace OHOS