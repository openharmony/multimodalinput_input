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

#ifndef TOUCHPAD_CONTROL_DISPLAY_GAIN
#define TOUCHPAD_CONTROL_DISPLAY_GAIN

namespace OHOS {
namespace MMI {
struct TouchpadCDG {
    double ppi;
    double size;
    int32_t speed;
    float zOrder;
    int32_t frequency;
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCHPAD_CONTROL_DISPLAY_GAIN