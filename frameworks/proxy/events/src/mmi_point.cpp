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
#include "mmi_point.h"
#include <iostream>

namespace OHOS {
MmiPoint::MmiPoint()
{
    pz_ = 0.f;
}

MmiPoint::MmiPoint(float px, float py) : MmiPoint()
{
    px_ = px;
    py_ = py;
}

MmiPoint::MmiPoint(float px, float py, float pz) : MmiPoint(px, py)
{
    pz_ = pz;
}

MmiPoint::MmiPoint(double px, double py)
    : MmiPoint(static_cast<float>(px), static_cast<float>(py))
{
}

MmiPoint::MmiPoint(double px, double py, double pz)
    : MmiPoint(static_cast<float>(px), static_cast<float>(py), static_cast<float>(pz))
{
}

MmiPoint::MmiPoint(int32_t px, int32_t py)
    : MmiPoint(static_cast<float>(px), static_cast<float>(py))
{
}

MmiPoint::MmiPoint(int32_t px, int32_t py, int32_t pz)
    : MmiPoint(static_cast<float>(px), static_cast<float>(py), static_cast<float>(pz))
{
}

MmiPoint::~MmiPoint()
{
}

void MmiPoint::Setxy(float px, float py)
{
    px_ = px;
    py_ = py;
}

void MmiPoint::Setxy(double px, double py)
{
    Setxy(static_cast<float>(px), static_cast<float>(py));
}

void MmiPoint::Setxyz(float px, float py, float pz)
{
    px_ = px;
    py_ = py;
    pz_ = pz;
}

void MmiPoint::Setxyz(double px, double py, double pz)
{
    Setxyz(static_cast<float>(px), static_cast<float>(py), static_cast<float>(pz));
}

float MmiPoint::GetX() const
{
    return px_;
}

float MmiPoint::GetY() const
{
    return py_;
}

float MmiPoint::GetZ() const
{
    return pz_;
}

std::string MmiPoint::ToString() const
{
    return "MmiPoint{ px =" + std::to_string(px_)
        + ", py = " + std::to_string(py_)
        + ", pz = " + std::to_string(pz_) + "}";
}
}
