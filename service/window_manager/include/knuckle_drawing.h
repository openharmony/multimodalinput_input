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

#ifndef KNUCKLE_DRAWING_H
#define KNUCKLE_DRAWING_H

#include "i_knuckle_drawing.h"
#include "knuckle_drawing_manager.h"
#ifndef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
#include "knuckle_dynamic_drawing_manager.h"
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC

namespace OHOS {
namespace MMI {
class KnuckleDrawing final : public IKnuckleDrawing {
public:
    KnuckleDrawing();
    ~KnuckleDrawing() = default;

    void Draw(const OLD::DisplayInfo& displayInfo, const std::shared_ptr<PointerEvent> &touchEvent) override;
    void SetMultiWindowScreenId(uint64_t screenId, uint64_t displayNodeScreenId) override;

private:
    std::shared_ptr<KnuckleDrawingManager> knuckleDrawingMgr_ {nullptr};
#ifndef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
    std::shared_ptr<KnuckleDynamicDrawingManager> knuckleDynamicDrawingMgr_ {nullptr};
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
};
} // namespace MMI
} // namespace OHOS

#endif // KNUCKLE_DRAWING_H
