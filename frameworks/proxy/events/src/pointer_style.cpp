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

#include "pointer_style.h"

#include "pixel_map.h"

namespace OHOS {
namespace MMI {
CustomCursorParcel::CustomCursorParcel(void* pixelMap, int32_t focusX, int32_t focusY)
    : Parcelable(), pixelMap(pixelMap), focusX(focusX), focusY(focusY) {}

bool CustomCursorParcel::Marshalling(Parcel &out) const
{
    if (pixelMap == nullptr) {
        return false;
    }
    OHOS::Media::PixelMap* pixelMapPtr = static_cast<OHOS::Media::PixelMap*>(pixelMap);
    if (pixelMapPtr->GetCapacity() == 0) {
        return false;
    }

    if (!pixelMapPtr->Marshalling(out)) {
        return false;
    }
    if (!out.WriteInt32(focusX)) {
        return false;
    }
    if (!out.WriteInt32(focusY)) {
        return false;
    }
    return true;
}

bool CustomCursorParcel::ReadFromParcel(Parcel &in)
{
    OHOS::Media::PixelMap* pixelMapPtr = Media::PixelMap::Unmarshalling(in);
    if (pixelMapPtr == nullptr) {
        return false;
    }
    pixelMap = (void *)pixelMapPtr;
    return (
        in.ReadInt32(focusX) &&
        in.ReadInt32(focusY)
    );
}

CustomCursorParcel *CustomCursorParcel::Unmarshalling(Parcel &in)
{
    CustomCursorParcel *data = new (std::nothrow) CustomCursorParcel();
    if (data && !data->ReadFromParcel(in)) {
        delete data;
        data = nullptr;
    }
    return data;
}

bool CursorOptionsParcel::Marshalling(Parcel &out) const
{
    if (!out.WriteBool(followSystem)) {
        return false;
    }
    return true;
}

bool CursorOptionsParcel::ReadFromParcel(Parcel &in)
{
    if (!in.ReadBool(followSystem)) {
        return false;
    }
    return true;
}

CursorOptionsParcel *CursorOptionsParcel::Unmarshalling(Parcel &in)
{
    CursorOptionsParcel *data = new (std::nothrow) CursorOptionsParcel();
    if (data && !data->ReadFromParcel(in)) {
        delete data;
        data = nullptr;
    }
    return data;
}

bool CursorPixelMap::Marshalling(Parcel &out) const
{
    if (pixelMap == nullptr) {
        return false;
    }
    OHOS::Media::PixelMap* pixelMapPtr = static_cast<OHOS::Media::PixelMap*>(pixelMap);
    if (pixelMapPtr->GetCapacity() == 0) {
        return false;
    }

    if (!pixelMapPtr->Marshalling(out)) {
        return false;
    }
    return true;
}

bool CursorPixelMap::ReadFromParcel(Parcel &in)
{
    OHOS::Media::PixelMap* pixelMapPtr = Media::PixelMap::Unmarshalling(in);
    if (pixelMapPtr == nullptr) {
        return false;
    }
    pixelMap = (void *)pixelMapPtr;
    return true;
}

CursorPixelMap *CursorPixelMap::Unmarshalling(Parcel &in)
{
    CursorPixelMap *data = new (std::nothrow) CursorPixelMap();
    if (data && !data->ReadFromParcel(in)) {
        delete data;
        data = nullptr;
    }
    return data;
}
} // namespace MMI
} // namespace OHOS