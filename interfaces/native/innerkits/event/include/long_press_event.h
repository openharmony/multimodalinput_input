/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef LONG_PRESS_EVENT_H
#define LONG_PRESS_EVENT_H

#include "parcel.h"

namespace OHOS {
namespace MMI {
struct LongPressRequest : public Parcelable {
    int32_t fingerCount { -1 };
    int32_t duration { -1 };

    bool Marshalling(Parcel &parcel) const
    {
        if (!parcel.WriteInt32(fingerCount)) {
            return false;
        }
        if (!parcel.WriteInt32(duration)) {
            return false;
        }
        return true;
    };

    bool ReadFromParcel(Parcel &parcel)
    {
        return (
            parcel.ReadInt32(fingerCount) &&
            parcel.ReadInt32(duration)
        );
    }

    static LongPressRequest* Unmarshalling(Parcel &parcel)
    {
        auto obj = new (std::nothrow) LongPressRequest();
        if (obj && !obj->ReadFromParcel(parcel)) {
            delete obj;
            obj = nullptr;
        }
        return obj;
    };
};

struct LongPressEvent {
    int32_t fingerCount { -1 };
    int32_t duration { -1 };
    int32_t pid { -1 };
    int32_t displayId { -1 };
    int32_t displayX { -1 };
    int32_t displayY { -1 };
    int32_t result { -1 }; // If the value is 0, it indicates correct reporting; non-zero indicates cancellation
    int32_t windowId { -1 };
    int32_t pointerId { -1 };
    int64_t downTime { -1 };
    std::string bundleName;
};
} // namespace MMI
} // namespace OHOS
#endif // LONG_PRESS_EVENT_H