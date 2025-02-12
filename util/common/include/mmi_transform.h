/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MMI_TRANSFORM_H
#define MMI_TRANSFORM_H

#include <vector>

#include "window_info.h"

namespace OHOS {
namespace MMI {

template <typename T> struct Vector2D {
    T x;
    T y;
};

template <typename T> class SimpleTransform {
public:
    enum class Type {
        Translate,
        Rotate,
    };
    const Type type;
    const T a00;
    const T a01;
    const T x0;
    const T a10;
    const T a11;
    const T y0;
    static SimpleTransform<T> Translate(const Vector2D<T> &v);
    static SimpleTransform<T> RotateDirection(Direction direction);
    Vector2D<T> Apply(const Vector2D<T> &v) const;
    Vector2D<T> Reset(const Vector2D<T> &v) const;
};

template <typename T> SimpleTransform<T> SimpleTransform<T>::Translate(const Vector2D<T> &v)
{
    return SimpleTransform<T>{
        .type = Type::Translate,
        .a00 = 1,
        .a01 = 0,
        .x0 = v.x,
        .a10 = 0,
        .a11 = 1,
        .y0 = v.y,
    };
}

template <typename T> SimpleTransform<T> SimpleTransform<T>::RotateDirection(Direction direction)
{
    // direction 0 1 2 3
    // cos 1 0 -1 0
    // sin 0 1 0 -1
    T cosine = 1;
    T sine = 0;
    switch (direction) {
        case DIRECTION90:
            cosine = 0;
            sine = 1;
            break;
        case DIRECTION180:
            cosine = -1;
            sine = 0;
            break;
        case DIRECTION270:
            cosine = 0;
            sine = -1;
            break;
        case DIRECTION0:
        default:
            break;
    }
    return SimpleTransform<T>{
        .type = Type::Rotate,
        .a00 = cosine,
        .a01 = -sine,
        .x0 = 0,
        .a10 = sine,
        .a11 = cosine,
        .y0 = 0,
    };
}

template <typename T> Vector2D<T> SimpleTransform<T>::Apply(const Vector2D<T> &v) const
{
    return {
        .x = a00 * v.x + a01 * v.y + x0,
        .y = a10 * v.x + a11 * v.y + y0,
    };
}

template <typename T> Vector2D<T> SimpleTransform<T>::Reset(const Vector2D<T> &v) const
{
    // Since only translate and rotation are supported,
    // we can assert the inverse of transform matrix is in the following form:
    return {
        .x = a00 * v.x + a10 * v.y - x0,
        .y = a01 * v.x + a11 * v.y - y0,
    };
}

template <typename T>
inline Vector2D<T> ApplyTransformSteps(const std::vector<SimpleTransform<T>> &steps, const Vector2D<T> &v)
{
    Vector2D<T> result = v;
    for (const auto &step : steps) {
        result = step.Apply(result);
    }
    return result;
}

template <typename T>
inline Vector2D<T> ResetTransformSteps(const std::vector<SimpleTransform<T>> &steps, const Vector2D<T> &v)
{
    Vector2D<T> result = v;
    for (auto iter = steps.rbegin(); iter != steps.rend(); ++iter) {
        result = iter->Reset(result);
    }
    return result;
}

template <typename T> std::vector<SimpleTransform<T>> RotateAndFitScreen(Direction direction, const Vector2D<T> &size)
{
    std::vector<SimpleTransform<T>> result;
    if (direction == DIRECTION0) {
        return result;
    }
    result.emplace_back(SimpleTransform<T>::RotateDirection(direction));
    switch (direction) {
        case DIRECTION90:
            result.emplace_back(SimpleTransform<T>::Translate({ size.y, 0 }));
            break;
        case DIRECTION180:
            result.emplace_back(SimpleTransform<T>::Translate(size));
            break;
        case DIRECTION270:
            result.emplace_back(SimpleTransform<T>::Translate({ 0, size.x }));
            break;
        case DIRECTION0:
        default:
            break;
    }

    return result;
}

template <typename T> inline Vector2D<T> RotateRect(Direction direction, const Vector2D<T> &size)
{
    switch (direction) {
        case DIRECTION90:
        case DIRECTION270:
            return { size.y, size.x };
        case DIRECTION0:
        case DIRECTION180:
        default:
            return size;
    }
}

} // namespace MMI
} // namespace OHOS

#endif /* MMI_TRANSFORM_H */