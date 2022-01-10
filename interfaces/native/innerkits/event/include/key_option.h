/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_MULTIMDOALINPUT_KEY_OPTION_H
#define OHOS_MULTIMDOALINPUT_KEY_OPTION_H

#include <vector>

namespace OHOS {
namespace MMI {
class KeyOption {
public:
    std::vector<int32_t> GetPreKeys() const;
    void SetPreKeys(const std::vector<int32_t>& preKeys);
    uint32_t GetPreKeySize();
    int32_t GetFinalKey() const;
    void SetFinalKey(int32_t finalKey);

    bool IsFinalKeyDown() const;
    void SetFinalKeyDown(bool pressed);

    int32_t GetFinalKeyDownDuration() const;
    void SetFinalKeyDownDuration(int32_t duration);

private:
    std::vector<int32_t> preKeys_;
    uint32_t preKeySize_;
    int32_t finalKey_;
    bool isFinalKeyDown_;
    int32_t finalKeyDownDuration_;
};
}
} // namespace OHOS:MMI

#endif // OHOS_MULTIMDOALINPUT_KEY_OPTION_H
