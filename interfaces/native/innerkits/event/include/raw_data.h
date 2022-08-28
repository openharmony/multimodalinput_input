/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_MULTIMDOALINPUT_RAW_DATA_H
#define OHOS_MULTIMDOALINPUT_RAW_DATA_H

#include "parcel.h"

namespace OHOS {
namespace MMI {
class RawData {
public:
    RawData();
    RawData(const int32_t dx, const int32_t dy);
    virtual ~RawData();
public:
    // Get or set the dx when the Pointer is move
    /**
     * @brief 取得x方向位移.
     * @return 返回x方向的位移
     * @since 9
     */
    int32_t GetDx() const;
    /**
     * @brief 设置x方向位移.
     * @param dx x方向的位移.
     * @return void
     * @since 9
     */
    void SetDx(int32_t dx);

    /**
     * @brief 取得y方向位移.
     * @return 返回y方向的位移
     * @since 9
     */
    int32_t GetDy() const;
    /**
     * @brief 设置y方向位移.
     * @param dy y方向的位移.
     * @return void
     * @since 9
     */
    void SetDy(int32_t dy);

public:
    bool WriteToParcel(Parcel &out) const;
    bool ReadFromParcel(Parcel &in);

private:
    int32_t dx_ = 0;
    int32_t dy_ = 0;
};
}
} // namespace OHOS::MMI
#endif // OHOS_MULTIMDOALINPUT_RAW_DATA_H
