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

#ifndef SHIFT_INFO_H
#define SHIFT_INFO_H

#include <optional>

#include "nocopyable.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {
struct ShiftWindowParam {
    int32_t sourceWindowId { -1 };
    int32_t targetWindowId { -1 };
    int32_t x { -1 };
    int32_t y { -1 };
};

struct ShiftWindowInfo {
    std::optional<WindowInfo> sourceWindowInfo;
    std::optional<WindowInfo> targetWindowInfo;
    int32_t x { -1 };
    int32_t y { -1 };
};
} // namespace MMI
} // namespace OHOS
#endif // SHIFT_INFO_H