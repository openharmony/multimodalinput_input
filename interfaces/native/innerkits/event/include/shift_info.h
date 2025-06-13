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

#ifndef SHIFT_INFO_H
#define SHIFT_INFO_H

#include "window_info.h"
#include "parcel.h"

namespace OHOS {
namespace MMI {
struct ShiftWindowParam : public Parcelable {
    int32_t sourceWindowId { -1 };
    int32_t targetWindowId { -1 };
    int32_t x { -1 };
    int32_t y { -1 };
    int32_t fingerId  { -1 };
    int32_t sourceType { PointerEvent::SOURCE_TYPE_UNKNOWN };

    bool Marshalling(Parcel &out) const
    {
        if (!out.WriteInt32(sourceWindowId)) {
            return false;
        }
        if (!out.WriteInt32(targetWindowId)) {
            return false;
        }
        if (!out.WriteInt32(x)) {
            return false;
        }
        if (!out.WriteInt32(y)) {
            return false;
        }
        if (!out.WriteInt32(fingerId)) {
            return false;
        }
        if (!out.WriteInt32(sourceType)) {
        }
        return true;
    }

    bool ReadFromParcel(Parcel &in)
    {
        return (
            in.ReadInt32(sourceWindowId) &&
            in.ReadInt32(targetWindowId) &&
            in.ReadInt32(x) &&
            in.ReadInt32(y) &&
            in.ReadInt32(fingerId) &&
            in.ReadInt32(sourceType)
        );
    }

    static ShiftWindowParam* Unmarshalling(Parcel &in)
    {
        auto obj = new (std::nothrow) ShiftWindowParam();
        if (obj && !obj->ReadFromParcel(in)) {
            delete obj;
            obj = nullptr;
        }
        return obj;
    };
};

struct ShiftWindowInfo {
    WindowInfo sourceWindowInfo;
    WindowInfo targetWindowInfo;
    int32_t x { -1 };
    int32_t y { -1 };
    int32_t fingerId  { -1 };
    int32_t sourceType { PointerEvent::SOURCE_TYPE_UNKNOWN };
};
} // namespace MMI
} // namespace OHOS
#endif // SHIFT_INFO_H