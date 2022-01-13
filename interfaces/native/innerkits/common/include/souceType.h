/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Description: Configuring the Key source type for KeyEvent Interception
 * Author: h00580190
 * Create: 2022-1-11
 * Notes: No
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

namespace OHOS {
namespace MMI {
static const int32_t SOURCETYPE_UNKNOWN = 0;
// Mouse source type. Indicates that the source of the pointer type event is a mouse-like device
static const int32_t SOURCETYPE_MOUSE = 1;
// Touch screen source type. Indicates that the source of pointer type events is a touch screen device
static const int32_t SOURCETYPE_TOUCHSCREEN = 2;
// Touchpad source type. Indicates that the source of pointer type events is a touchpad device
static const int32_t SOURCETYPE_TOUCHPAD = 3;
// Key source type. Indicates that the source of key type events is a key device
static const int32_t SOURCETYPE_KEY = 4;
} // MMI
} // OHOS