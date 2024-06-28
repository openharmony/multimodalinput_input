/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "i_anco_consumer.h"

namespace OHOS {
namespace MMI {

template<typename T>
static bool MarshalVector(const std::vector<T> &data, Parcel &parcel, bool (*writeOne)(const T &arg, Parcel &parcel))
{
    if (writeOne == nullptr) {
        return false;
    }
    uint64_t nItems = static_cast<uint64_t>(data.size());
    if (!parcel.WriteUint64(nItems)) {
        return false;
    }
    for (uint64_t index = 0; index < nItems; ++index) {
        if (!(*writeOne)(data[index], parcel)) {
            return false;
        }
    }
    return true;
}

template<typename T>
static bool UnmarshalVector(Parcel &parcel, std::vector<T> &data, bool (*readOne)(Parcel &parcel, T &arg))
{
    if (readOne == nullptr) {
        return false;
    }
    uint64_t nItems {};
    if (!parcel.ReadUint64(nItems)) {
        return false;
    }
    data.resize(nItems);

    for (uint64_t index = 0; index < nItems; ++index) {
        if (!(*readOne)(parcel, data[index])) {
            return false;
        }
    }
    return true;
}

static bool MarshalRect(const Rect &rect, Parcel &parcel)
{
    return (
        parcel.WriteInt32(rect.x) &&
        parcel.WriteInt32(rect.y) &&
        parcel.WriteInt32(rect.width) &&
        parcel.WriteInt32(rect.height)
    );
}

static bool UnmarshalRect(Parcel &parcel, Rect &rect)
{
    return (
        parcel.ReadInt32(rect.x) &&
        parcel.ReadInt32(rect.y) &&
        parcel.ReadInt32(rect.width) &&
        parcel.ReadInt32(rect.height)
    );
}

static bool MarshalWindowInfo(const AncoWindowInfo &windowInfo, Parcel &parcel)
{
    return (
        parcel.WriteInt32(windowInfo.id) &&
        parcel.WriteUint32(windowInfo.flags) &&
        parcel.WriteUint32(static_cast<uint32_t>(windowInfo.action)) &&
        parcel.WriteInt32(windowInfo.displayId) &&
        parcel.WriteFloat(windowInfo.zOrder) &&
        parcel.WriteFloatVector(windowInfo.transform) &&
        MarshalVector(windowInfo.defaultHotAreas, parcel, &MarshalRect) &&
        MarshalVector(windowInfo.ancoExcludedAreas, parcel, &MarshalRect)
    );
}

static bool UnmarshalWindowInfo(Parcel &parcel, AncoWindowInfo &windowInfo)
{
    uint32_t action {};

    bool result = (
        parcel.ReadInt32(windowInfo.id) &&
        parcel.ReadUint32(windowInfo.flags) &&
        parcel.ReadUint32(action) &&
        parcel.ReadInt32(windowInfo.displayId) &&
        parcel.ReadFloat(windowInfo.zOrder) &&
        parcel.ReadFloatVector(&windowInfo.transform) &&
        UnmarshalVector(parcel, windowInfo.defaultHotAreas, &UnmarshalRect) &&
        UnmarshalVector(parcel, windowInfo.ancoExcludedAreas, &UnmarshalRect)
    );
    windowInfo.action = static_cast<WINDOW_UPDATE_ACTION>(action);
    return result;
}

bool AncoWindows::Marshalling(const AncoWindows &windows, Parcel &parcel)
{
    return (
        parcel.WriteUint32(static_cast<uint32_t>(windows.updateType)) &&
        parcel.WriteInt32(windows.focusWindowId) &&
        MarshalVector(windows.windows, parcel, &MarshalWindowInfo)
    );
}

bool AncoWindows::Unmarshalling(Parcel &parcel, AncoWindows &windows)
{
    uint32_t updateType {};

    bool result = (
        parcel.ReadUint32(updateType) &&
        parcel.ReadInt32(windows.focusWindowId) &&
        UnmarshalVector(parcel, windows.windows, &UnmarshalWindowInfo)
    );
    windows.updateType = static_cast<ANCO_WINDOW_UPDATE_TYPE>(updateType);
    return result;
}
} // namespace MMI
} // namespace OHOS