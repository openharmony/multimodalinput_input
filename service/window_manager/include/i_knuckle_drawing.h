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

#ifndef I_KNUCKLE_DRAWING_H
#define I_KNUCKLE_DRAWING_H

#include "pointer_event.h"
#include "old_display_info.h"

namespace OHOS {
namespace MMI {
class IKnuckleDrawing {
public:
    IKnuckleDrawing() = default;
    virtual ~IKnuckleDrawing() = default;

    virtual void Draw(const OLD::DisplayInfo& displayInfo, const std::shared_ptr<PointerEvent> &touchEvent) = 0;
    virtual void SetMultiWindowScreenId(uint64_t screenId, uint64_t displayNodeScreenId) = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // I_KNUCKLE_DRAWING_H
