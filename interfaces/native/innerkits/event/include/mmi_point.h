/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

    MmiPoint(float px, float py);

    MmiPoint(float px, float py, float pz);

    ~MmiPoint() = default;

    float GetX();

    float GetY();

    float GetZ();

    virtual std::string ToString();

    float px_;
    float py_;
    float pz_;
};
}  // namespace OHOS
#endif  // MMI_POINT_H

