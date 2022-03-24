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

#ifndef FAKE_POINTER_DRAWING_MANAGER_H
#define FAKE_POINTER_DRAWING_MANAGER_H

#include <iostream>

#include "nocopyable.h"
#include "singleton.h"

#include "device_observer.h"
#include "struct_multimodal.h"

namespace OHOS {
namespace MMI {
class FakePointerDrawingManager : public DelayedSingleton<FakePointerDrawingManager>, public IDeviceObserver {
public:
    FakePointerDrawingManager();
    ~FakePointerDrawingManager();
    DISALLOW_COPY_AND_MOVE(FakePointerDrawingManager);
    
    void DrawPointer(int32_t displayId, int32_t globalX, int32_t globalY);
    void OnDisplayInfo(int32_t displayId, int32_t width, int32_t height);
    void UpdatePointerDevice(bool hasPointerDevice);
    bool Init();
};

#define FakePointerDrawMgr FakePointerDrawingManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // FAKE_POINTER_DRAWING_MANAGER_H