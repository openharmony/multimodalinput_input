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

#ifndef TAIHE_POINTER_UTILS_H
#define TAIHE_POINTER_UTILS_H
#include "ohos.multimodalInput.pointer.proj.hpp"
#include "ohos.multimodalInput.pointer.impl.hpp"
#include "taihe/runtime.hpp"

#include "pointer_style.h"
namespace OHOS {
namespace MMI {
class TaihePointerUtils {
public:
    static CustomCursor ConverterToCustomCursor(const ohos::multimodalInput::pointer::CustomCursor &value);
    static CursorOptions ConverterToCursorConfig(const ohos::multimodalInput::pointer::CursorConfig &value);
};

} // namespace MMI
} // namespace OHOS
#endif // TAIHE_POINTER_UTILS_H