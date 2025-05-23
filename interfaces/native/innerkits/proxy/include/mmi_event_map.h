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

#ifndef MMI_EVENT_MAP_H
#define MMI_EVENT_MAP_H

#include <tuple>
#include <map>
#include "parcel.h"

namespace OHOS {
namespace MMI {
const int32_t TUPLE_PID { 0 };
const int32_t TUPLE_UID { 1 };
const int32_t TUPLE_NAME { 2 };
struct MmiEventMap : public Parcelable {
    std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> datas;

    bool ReadFromParcel(Parcel &parcel)
    {
        int32_t size = 0;
        if (!parcel.ReadInt32(size)) {
            return false;
        }
        if (size < 0) {
            return false;
        }
        for (int32_t i = 0; i < size; ++i) {
            int32_t pid;
            int32_t uid;
            std::string bundleName;
            int32_t value;
            bool result = (
                parcel.ReadInt32(pid) &&
                parcel.ReadInt32(uid) &&
                parcel.ReadString(bundleName) &&
                parcel.ReadInt32(value)
            );
            if (!result) {
                return false;
            }
            std::tuple<int32_t, int32_t, std::string> tuple(pid, uid, bundleName);
            datas.emplace(tuple, value);
        }
        return true;
    }

    bool Marshalling(Parcel &parcel) const
    {
        if (!parcel.WriteInt32(static_cast<int32_t>(datas.size()))) {
            return false;
        }
        for (auto &data : datas) {
            if (!parcel.WriteInt32(std::get<TUPLE_PID>(data.first))) {
                return false;
            }
            if (!parcel.WriteInt32(std::get<TUPLE_UID>(data.first))) {
                return false;
            }
            if (!parcel.WriteString(std::get<TUPLE_NAME>(data.first))) {
                return false;
            }
            if (!parcel.WriteInt32(data.second)) {
                return false;
            }
        }
        return true;
    }

    static struct MmiEventMap* Unmarshalling(Parcel &parcel)
    {
        auto mmiEventMap = new (std::nothrow) struct MmiEventMap();
        if (mmiEventMap && !mmiEventMap->ReadFromParcel(parcel)) {
            delete mmiEventMap;
            mmiEventMap = nullptr;
        }

        return mmiEventMap;
    }
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_EVENT_MAP_H