/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef POINTER_DRAWING_CONTEXT_H
#define POINTER_DRAWING_CONTEXT_H

#include <memory>

#include "pointer_style.h"
#include "old_display_info.h"

namespace OHOS {
namespace Rosen {
class RSSurfaceNode;
class RSCanvasNode;
class RSUIDirector;
class RSUIContext;
} // namespace Rosen
} // namespace OHOS

namespace OHOS {
namespace MMI {

constexpr int32_t INITIAL_COORDINATE { -1 };

struct PhysicalCoord {
    int32_t x = 0;
    int32_t y = 0;
};

struct PointerDrawingContext {
    bool hasDisplay { false };
    bool hasPointerDevice { false };
    bool mouseDisplayState { false };
    OLD::DisplayInfo displayInfo {};
    int32_t lastPhysicalX { INITIAL_COORDINATE };
    int32_t lastPhysicalY { INITIAL_COORDINATE };
    PointerStyle lastMouseStyle {};
    PointerStyle currentMouseStyle {};
    PointerStyle lastDrawPointerStyle {};
    int32_t pid { 0 };
    int32_t windowId { 0 };
    uint64_t screenId { 0 };
    uint64_t displayId { 0 };
    std::shared_ptr<Rosen::RSSurfaceNode> surfaceNode { nullptr };
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode { nullptr };
    std::shared_ptr<Rosen::RSUIDirector> rsUIDirector { nullptr };
    std::shared_ptr<Rosen::RSUIContext> rsUIContext { nullptr };
    Direction lastDirection { DIRECTION0 };
    Direction currentDirection { DIRECTION0 };
};

} // namespace MMI
} // namespace OHOS
#endif // POINTER_DRAWING_CONTEXT_H
