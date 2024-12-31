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

#ifndef LONG_PRESS_EVENT_H
#define LONG_PRESS_EVENT_H

namespace OHOS {
namespace MMI {
struct LongPressRequest {
    int32_t fingerCount;
    int32_t duration;
};

struct LongPressEvent {
    int32_t fingerCount;
    int32_t duration;
    int32_t pid;
    int32_t displayId;
    int32_t displayX;
    int32_t displayY;
    int32_t result; // If the value is 0, it indicates correct reporting; non-zero indicates cancellation
    int32_t windowId;
    int32_t pointerId;
    std::string bundleName;
};
} // namespace MMI
} // namespace OHOS
#endif // LONG_PRESS_EVENT_H