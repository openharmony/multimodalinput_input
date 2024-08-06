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

#ifndef KEY_OPTION_H
#define KEY_OPTION_H

#include <set>
#include "nocopyable.h"
#include "parcel.h"

namespace OHOS {
namespace MMI {
class KeyOption {
public:
    KeyOption() = default;
    DISALLOW_COPY_AND_MOVE(KeyOption);

public:
    /**
     * @brief Obtains previous keys.
     * @return Returns previous keys.
     * @since 9
     */
    std::set<int32_t> GetPreKeys() const;

    /**
     * @brief Sets previous keys, that is, the keys that are pressed first in a combination key.
     * There is no requirement on the sequence of previous keys.
     * @param preKeys Indicates the previous keys to set.
     * @return void
     * @since 9
     */
    void SetPreKeys(const std::set<int32_t>& preKeys);

    /**
     * @brief Obtains the final key.
     * @return Returns the final key.
     * @since 9
     */
    int32_t GetFinalKey() const;

    /**
     * @brief Sets the final key, that is, the key that is last pressed or released in a combination key.
     * @param finalKey Indicates the final key.
     * @return void
     * @since 9
     */
    void SetFinalKey(int32_t finalKey);

    /**
     * @brief Checks whether the final key in a combination key is pressed or released.
     * @return Returns <b>true</b> if the key is pressed; returns <b>false</b> if the key is released.
     * @since 9
     */
    bool IsFinalKeyDown() const;

    /**
     * @brief Sets whether the final key in a combination key is pressed or released.
     * @param pressed Indicates whether the key is pressed. The value <b>true</b> means that the key
     * is pressed, and the value <b>false</b> means that the key is released.
     * @return void
     * @since 9
     */
    void SetFinalKeyDown(bool pressed);

    /**
     * @brief Obtains the duration when the final key is held down or the maximum duration between
     * when the key is pressed and when the key is released.
     * If the final key is pressed, this parameter indicates the duration when the final key is held down.
     * If the last key is released, this parameter indicates the maximum duration between when the key
     * is pressed and when the key is released.
     * @return Returns the duration when the final key is held down or the maximum duration between
     * when the key is pressed and when the key is released.
     * @since 9
     */
    int32_t GetFinalKeyDownDuration() const;

    /**
     * @brief Get the delay time of lifting the last key. When the last key is lifted, the subscription
     * will be delayed and triggered.
     * @return Return to the delay time of lifting the last key.
     * @since 9
     */
    int32_t GetFinalKeyUpDelay() const;

    /**
     * @brief Sets the duration when the final key is held down or the maximum duration between when
     * the key is pressed and when the key is released.
     * If the final key is pressed, this parameter indicates the duration when the final key is held down.
     * If the last key is released, this parameter indicates the maximum duration between when the key
     * is pressed and when the key is released.
     * @param duration Indicates the duration when the final key is held down or the maximum duration
     * between when the key is pressed and when the key is released.
     * @return void
     * @since 9
     */
    void SetFinalKeyDownDuration(int32_t duration);

    /**
     * @brief Set the delay time for lifting the last key.
     * @param delay Delay time for lifting the last key.
     * @return void
     * @since 9
     */
    void SetFinalKeyUpDelay(int32_t delay);

    bool IsRepeat() const;

    void SetRepeat(bool repeat);

public:
    /**
     * @brief Writes data to a <b>Parcel</b> object.
     * @param out Indicates the object into which data will be written.
     * @return Returns <b>true</b> if the data is successfully written; returns <b>false</b> otherwise.
     * @since 9
     */
    bool WriteToParcel(Parcel &out) const;

    /**
     * @brief Reads data from a <b>Parcel</b> object.
     * @param in Indicates the object from which data will be read.
     * @return Returns <b>true</b> if the data is successfully read; returns <b>false</b> otherwise.
     * @since 9
     */
    bool ReadFromParcel(Parcel &in);

private:
    std::set<int32_t> preKeys_ {};
    int32_t finalKey_ { -1 };
    bool isFinalKeyDown_ { false };
    int32_t finalKeyDownDuration_ { 0 };
    int32_t finalKeyUpDelay_ { 0 };
    bool isRepeat_ { true };
};
} // namespace MMI
} // namespace OHOS
#endif // KEY_OPTION_H
