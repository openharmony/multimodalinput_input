/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef I_POINTER_DRAWING_MANAGER_H
#define I_POINTER_DRAWING_MANAGER_H

#include <memory>

#include "display_info.h"

namespace OHOS {
namespace MMI {
class IPointerDrawingManager {
public:
    IPointerDrawingManager() = default;
    virtual ~IPointerDrawingManager() = default;

    static std::shared_ptr<IPointerDrawingManager> GetInstance();
    virtual void DrawPointer(int32_t displayId, int32_t physicalX, int32_t physicalY) {}
    virtual void OnDisplayInfo(int32_t displayId, int32_t width, int32_t height, Direction direction) {}
    virtual bool Init()
    {
        return true;
    }
    virtual void DeletePointerVisible(int32_t pid) {}
    virtual int32_t SetPointerVisible(int32_t pid, bool visible)
    {
        return 0;
    }
    virtual bool IsPointerVisible()
    {
        return false;
    }

public:
    static inline std::shared_ptr<IPointerDrawingManager> iPointDrawMgr_ = nullptr;
};
} // namespace MMI
} // namespace OHOS
#endif // I_POINTER_DRAWING_MANAGER_H