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

#ifndef NON_POINTER_DRAWING_MANAGER_H
#define NON_POINTER_DRAWING_MANAGER_H

#include <iostream>

#include "nocopyable.h"

#include "device_observer.h"
#include "i_pointer_drawing_manager.h"
#include "struct_multimodal.h"

namespace OHOS {
namespace MMI {
class NonPointerDrawingManager : public IPointerDrawingManager,
                                 public IDeviceObserver,
                                 public std::enable_shared_from_this<NonPointerDrawingManager> {
public:
    NonPointerDrawingManager();
    virtual ~NonPointerDrawingManager();
    DISALLOW_COPY_AND_MOVE(NonPointerDrawingManager);
    
    void DrawPointer(int32_t displayId, int32_t globalX, int32_t globalY) override;
    void OnDisplayInfo(int32_t displayId, int32_t width, int32_t height) override;
    void UpdatePointerDevice(bool hasPointerDevice) override;
    bool Init() override;
};
} // namespace MMI
} // namespace OHOS
#endif // NON_POINTER_DRAWING_MANAGER_H