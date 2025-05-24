/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef POINTER_STYLE_H
#define POINTER_STYLE_H

#include <iostream>
#include "parcel.h"

namespace OHOS {
namespace MMI {
struct PointerStyle : public Parcelable {
    int32_t size { -1 };
    int32_t color { 0 };
    int32_t id { 0 };
    int32_t options { 0 };
    bool operator==(const PointerStyle &rhs) const
    {
        return id == rhs.id && size == rhs.size && color == rhs.color && options == rhs.options;
    }
    bool Marshalling(Parcel &out) const
    {
        if (!out.WriteInt32(size)) {
            return false;
        }

        if (!out.WriteInt32(color)) {
            return false;
        }

        if (!out.WriteInt32(id)) {
            return false;
        }

        if (!out.WriteInt32(options)) {
            return false;
        }
        return true;
    }

    bool ReadFromParcel(Parcel &in)
    {
        return (
            in.ReadInt32(size) &&
            in.ReadInt32(color) &&
            in.ReadInt32(id) &&
            in.ReadInt32(options)
        );
    }

    static PointerStyle *Unmarshalling(Parcel &in)
    {
        PointerStyle *data = new (std::nothrow) PointerStyle();
        if (data && !data->ReadFromParcel(in)) {
            delete data;
            data = nullptr;
        }
        return data;
    }
};

struct CustomCursor {
    void* pixelMap { nullptr };
    int32_t focusX { 0 };
    int32_t focusY { 0 };
};

struct CustomCursorParcel : public Parcelable {
    CustomCursorParcel() = default;
    explicit CustomCursorParcel(void* pixelMap, int32_t focusX, int32_t focusY);
    void* pixelMap { nullptr };
    int32_t focusX { 0 };
    int32_t focusY { 0 };
    bool Marshalling(Parcel &out) const;
    bool ReadFromParcel(Parcel &in);
    static CustomCursorParcel *Unmarshalling(Parcel &in);
};

struct CursorOptions {
    bool followSystem { false };
};

struct CursorOptionsParcel : public Parcelable {
    bool followSystem { false };
    bool Marshalling(Parcel &out) const;
    bool ReadFromParcel(Parcel &in);
    static CursorOptionsParcel *Unmarshalling(Parcel &in);
};

struct CursorPixelMap : public Parcelable {
    void* pixelMap { nullptr };
    bool Marshalling(Parcel &out) const;
    bool ReadFromParcel(Parcel &in);
    static CursorPixelMap *Unmarshalling(Parcel &in);
};

} // namespace MMI
} // namespace OHOS
#endif // POINTER_STYLE_H