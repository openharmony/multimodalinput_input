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
#ifndef MMI_POINT_H
#define MMI_POINT_H

#include <string>

namespace OHOS {
class MmiPoint {
public:
    MmiPoint();
    virtual ~MmiPoint();
    /**
     * A constructor used to create an {@code MmiPoint} object with the x and y coordinates specified.
     *
     * @param px Indicates the x coordinate.
     * @param py Indicates the y coordinate.
     * @since 3
     */
    MmiPoint(int32_t px, int32_t py);
    MmiPoint(float px, float py);
    MmiPoint(double px, double py);

    /**
     * A constructor used to create an {@code MmiPoint} object with the x, y, and z coordinates specified.
     *
     * @param px Indicates the x coordinate.
     * @param py Indicates the y coordinate.
     * @param pz Indicates the z coordinate.
     * @since 3
     */
    MmiPoint(int32_t px, int32_t py, int32_t pz);
    MmiPoint(float px, float py, float pz);
    MmiPoint(double px, double py, double pz);

    /**
     * Obtains the x coordinate.
     *
     * @return Returns the x coordinate.
     * @since 3
     */

    void Setxy(float px, float py);
    void Setxy(double px, double py);
    void Setxyz(float px, float py, float pz);
    void Setxyz(double px, double py, double pz);

    float GetX() const;

    /**
     * Obtains the y coordinate.
     *
     * @return Returns the y coordinate.
     * @since 3
     */
    float GetY() const;

    /**
     * Obtains the z coordinate.
     *
     * @return Returns the z coordinate.
     * @since 3
     */
    float GetZ() const;

    /**
     * Obtains a string representation of this {@code MmiPoint} object with the x, y, and z coordinates specified.
     *
     * @return Returns a string representation of this {@code MmiPoint} object with the x, y,
     * and z coordinates specified, in the format of {@code MmiPoint{px=x coordinate value,
     * py=y coordinate value, pz=z coordinate value}}.
     * @since 3
     */

    virtual std::string ToString()  const;

private:
    float px_ = 0.f;
    float py_ = 0.f;
    float pz_ = 0.f;
};
}
#endif // MMI_POINT_H