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

#include "mmi_point.h"
#include <iostream>

#include "hilog/log.h"

namespace OHOS {
namespace {
using namespace OHOS::HiviewDFX;
constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, 0xD002800, "MmiPoint" };
}

MmiPoint::MmiPoint() {}

MmiPoint::MmiPoint(float px, float py)
{
    px_ = px;
    py_ = py;
}

MmiPoint::MmiPoint(float px, float py, float pz)
{
    px_ = px;
    py_ = py;
    pz_ = pz;
}

float MmiPoint::GetX()
{
    return px_;
}

float MmiPoint::GetY()
{
    return py_;
}

float MmiPoint::GetZ()
{
    return pz_;
}

std::string MmiPoint::ToString()
{
    HiLog::Info(LABEL, "%{public}s px = %{public}f, py = %{public}f, pz = %{public}f", __func__, px_, py_, pz_);
    return "MmiPoint{ px = "+std::to_string(px_)+", py = "+std::to_string(py_)+", pz = "+std::to_string(pz_)+"}";
}
}  // namespace OHOS