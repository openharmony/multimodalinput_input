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

#ifndef TOUCHPAD_CONTROL_DISPLAY_GAIN
#define TOUCHPAD_CONTROL_DISPLAY_GAIN

#include "parcel.h"

namespace OHOS {
namespace MMI {
struct TouchpadCDG : public Parcelable {
    double ppi;
    double size;
    int32_t speed;
    float zOrder;
    int32_t frequency;

    bool Marshalling(Parcel &parcel) const
    {
        if (!parcel.WriteDouble(ppi)) {
            return false;
        }
        if (!parcel.WriteDouble(size)) {
            return false;
        }
        if (!parcel.WriteInt32(speed)) {
            return false;
        }
        if (!parcel.WriteInt32(frequency)) {
            return false;
        }
        return true;
    };

    bool ReadFromParcel(Parcel &parcel)
    {
        return (
            parcel.ReadDouble(ppi) &&
            parcel.ReadDouble(size) &&
            parcel.ReadInt32(speed) &&
            parcel.ReadInt32(frequency)
        );
    }

    static TouchpadCDG* Unmarshalling(Parcel &parcel)
    {
        auto obj = new (std::nothrow) TouchpadCDG();
        if (obj && !obj->ReadFromParcel(parcel)) {
            delete obj;
            obj = nullptr;
        }
        return obj;
    };
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCHPAD_CONTROL_DISPLAY_GAIN