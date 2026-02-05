/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef I_CURSOR_DRAWING_HANDLER_H
#define I_CURSOR_DRAWING_HANDLER_H

namespace OHOS {
namespace MMI {
class ICursorDrawingComponent {
public:
    ICursorDrawingComponent() = default;
    virtual ~ICursorDrawingComponent() = default;
    virtual void SetPointerLocation(int32_t x, int32_t y, uint64_t displayId) = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // I_CURSOR_DRAWING_HANDLER_H
