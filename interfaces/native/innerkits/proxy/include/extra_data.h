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

#ifndef EXTRA_DATA_H
#define EXTRA_DATA_H

#include <vector>
#include "parcel.h"

namespace OHOS {
namespace MMI {
struct ExtraData : public Parcelable {
    /*
     * buffer的最大个数
     *
     * @since 9
     */
    static constexpr int32_t MAX_BUFFER_SIZE = 1024;
    /*
     * 是否添加buffer信息
     *
     * @since 9
     */
    bool appended { false };
    /*
     * buffer信息
     *
     * @since 9
     */
    std::vector<uint8_t> buffer;
    /*
     * 事件类型
     *
     * @since 9
     */
    int32_t sourceType { -1 };
    /*
     * 事件触发的pointer id
     *
     * @since 9
     */
    int32_t pointerId { -1 };
    /*
     * 当前拖拽实例的标识
     *
     * @since 13
     */
    int32_t pullId { -1 };
    /*
     * 开始拖拽实例的事件id
     *
     * @since 13
     */
    int32_t eventId { -1 };
    /*
     * 使用硬光标绘制功能
     *
     * @since 13
     */
    bool drawCursor { false };

    static bool UnmarshalVector(Parcel &parcel, std::vector<uint8_t> &buffer)
    {
        int32_t size {};
        if (!parcel.ReadInt32(size)) {
            return false;
        }
        if (size < 0 ||size > MAX_BUFFER_SIZE) {
            return false;
        }
        buffer.resize(size);
        for (int32_t i = 0; i < size; ++i) {
            uint8_t value = 0;
            if (!parcel.ReadUint8(value)) {
                return false;
            }
            buffer.push_back(value);
        }
        return true;
    }

    bool ReadFromParcel(Parcel &parcel)
    {
        return (
            parcel.ReadBool(appended) &&
            UnmarshalVector(parcel, buffer) &&
            parcel.ReadInt32(sourceType) &&
            parcel.ReadInt32(pointerId) &&
            parcel.ReadInt32(pullId) &&
            parcel.ReadInt32(eventId) &&
            parcel.ReadBool(drawCursor)
        );
    }

    bool Marshalling(Parcel &parcel) const
    {
        if (!parcel.WriteBool(appended)) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(buffer.size()))) {
            return false;
        }
        for (int32_t i = 0; i < static_cast<int32_t>(buffer.size()); i++) {
            if (!parcel.WriteUint8(buffer[i])) {
                return false;
            }
        }
        if (!parcel.WriteInt32(sourceType)) {
            return false;
        }
        if (!parcel.WriteInt32(pointerId)) {
            return false;
        }
        if (!parcel.WriteInt32(pullId)) {
            return false;
        }
        if (!parcel.WriteInt32(eventId)) {
            return false;
        }
        if (!parcel.WriteBool(drawCursor)) {
            return false;
        }
        return true;
    }

    static struct ExtraData* Unmarshalling(Parcel &parcel)
    {
        auto extraData = new (std::nothrow) struct ExtraData();
        if (extraData && !extraData->ReadFromParcel(parcel)) {
            delete extraData;
            extraData = nullptr;
        }

        return extraData;
    }
};
} // namespace MMI
} // namespace OHOS
#endif // EXTRA_DATA_H