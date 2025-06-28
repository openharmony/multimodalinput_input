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

#ifndef KNUCKLE_DRAWING_COMPONENT_H
#define KNUCKLE_DRAWING_COMPONENT_H

#include <chrono>
#include <memory>
#include "i_knuckle_drawing.h"

namespace OHOS {
namespace MMI {
class KnuckleDrawingComponent {
public:
    static KnuckleDrawingComponent &GetInstance();

    void Draw(const OLD::DisplayInfo& displayInfo, const std::shared_ptr<PointerEvent> &touchEvent);
    void SetMultiWindowScreenId(uint64_t screenId, uint64_t displayNodeScreenId);
private:
    DISALLOW_COPY_AND_MOVE(KnuckleDrawingComponent);
    KnuckleDrawingComponent() = default;
    ~KnuckleDrawingComponent();
    IKnuckleDrawing *Load();
    bool LoadKnuckleSharedLibrary();
    void Unload();
private:
    using GetKnuckleDrawingFunc = IKnuckleDrawing*(*)();
    using DestroyKnuckleDrawingFunc = void (*)(IKnuckleDrawing*);

    void *handle_ {nullptr};
    GetKnuckleDrawingFunc create_ {nullptr};
    DestroyKnuckleDrawingFunc destroy_ {nullptr};
    IKnuckleDrawing *impl_ {nullptr};
    int32_t timerId_ {-1};
    std::chrono::time_point<std::chrono::steady_clock> lastCallTime_ {std::chrono::steady_clock::now()};
};
} // namespace MMI
} // namespace OHOS
#endif // KNUCKLE_DRAWING_COMPONENT_H
