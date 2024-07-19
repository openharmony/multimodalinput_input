/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef INTENTION_IDENTITY_H
#define INTENTION_IDENTITY_H

#include <cinttypes>

#include "message_parcel.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
enum CommonAction : uint32_t {
    UNKNOWN_COMMON_ACTION,
    ENABLE,
    DISABLE,
    START,
    STOP,
    ADD_WATCH,
    REMOVE_WATCH,
    SET_PARAM,
    GET_PARAM,
    CONTROL
};

enum class Intention : uint32_t {
    UNKNOWN_INTENTION,
    SOCKET,
    STATIONARY,
    DRAG,
    COOPERATE,
};

inline constexpr uint32_t PARAMBITS { 12U };
inline constexpr uint32_t PARAMMASK { (uint32_t(1U) << PARAMBITS) - uint32_t(1U) };
inline constexpr uint32_t INTENTIONSHIFT { PARAMBITS };
inline constexpr uint32_t INTENTIONBITS { 8U };
inline constexpr uint32_t INTENTIONMASK { (uint32_t(1U) << INTENTIONBITS) - uint32_t(1U) };
inline constexpr uint32_t ACTIONSHIFT { INTENTIONSHIFT + INTENTIONBITS };
inline constexpr uint32_t ACTIONBITS { 4U };
inline constexpr uint32_t ACTIONMASK { (uint32_t(1U) << ACTIONBITS) - uint32_t(1U) };

constexpr uint32_t PARAMID(uint32_t action, uint32_t intention, uint32_t param)
{
    return (
        ((action & ACTIONMASK) << ACTIONSHIFT) |
        ((intention & INTENTIONMASK) << INTENTIONSHIFT) |
        (param & PARAMMASK)
    );
}

constexpr uint32_t GACTION(uint32_t id)
{
    return ((id >> ACTIONSHIFT) & ACTIONMASK);
}

constexpr uint32_t GINTENTION(uint32_t id)
{
    return ((id >> INTENTIONSHIFT) & INTENTIONMASK);
}

constexpr uint32_t GPARAM(uint32_t id)
{
    return (id & PARAMMASK);
}

class ParamBase {
public:
    virtual ~ParamBase() = default;

    virtual bool Marshalling(MessageParcel &parcel) const = 0;
    virtual bool Unmarshalling(MessageParcel &parcel) = 0;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // INTENTION_IDENTITY_H
