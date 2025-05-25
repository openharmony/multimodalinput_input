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

#include "i_anco_consumer.h"

#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "IAncoConsumer"

namespace OHOS {
namespace MMI {
namespace {
constexpr uint64_t MAX_UNMARSHAL_VECTOR_SIZE { 512 };
}

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
    if (nItems > MAX_UNMARSHAL_VECTOR_SIZE) {
        MMI_HILOGE("The nItems:%{public}" PRIu64 ", exceeds maximum allowed size:%{public}"
            PRIu64, nItems, MAX_UNMARSHAL_VECTOR_SIZE);
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

bool AncoWindows::Marshalling(Parcel &out) const
{
    return (
        out.WriteUint32(static_cast<uint32_t>(updateType)) &&
        out.WriteInt32(focusWindowId) &&
        MarshalVector(windows, out, &MarshalWindowInfo)
    );
}

bool AncoWindows::ReadFromParcel(Parcel &in)
{
    uint32_t updateTypeData {};
    bool result = (
        in.ReadUint32(updateTypeData) &&
        in.ReadInt32(focusWindowId) &&
        UnmarshalVector(in, windows, &UnmarshalWindowInfo)
    );
    updateType = static_cast<ANCO_WINDOW_UPDATE_TYPE>(updateTypeData);
    return result;
}

AncoWindows *AncoWindows::Unmarshalling(Parcel &in)
{
    AncoWindows *data = new (std::nothrow) AncoWindows();
    if (data && !data->ReadFromParcel(in)) {
        delete data;
        data = nullptr;
    }
    return data;
}

bool AncoOneHandData::Marshalling(Parcel &parcel) const
{
    return (parcel.WriteInt32(oneHandX) && parcel.WriteInt32(oneHandY) &&
            parcel.WriteInt32(expandHeight) && parcel.WriteInt32(scalePercent));
}

bool AncoOneHandData::ReadFromParcel(Parcel &parcel)
{
    return (parcel.ReadInt32(oneHandX) && parcel.ReadInt32(oneHandY) &&
            parcel.ReadInt32(expandHeight) && parcel.ReadInt32(scalePercent));
}

AncoOneHandData *AncoOneHandData::Unmarshalling(Parcel &parcel)
{
    AncoOneHandData *data = new (std::nothrow) AncoOneHandData();
    if (data && !data->ReadFromParcel(parcel)) {
        delete data;
        data = nullptr;
    }
    return data;
}
} // namespace MMI
} // namespace OHOS