/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "non_pointer_drawing_manager.h"

#include <display_type.h>

#include "define_multimodal.h"
#include "input_device_manager.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "NonPointerDrawingManager" };
} // namespace
} // namespace MMI
} // namespace OHOS

namespace OHOS {
namespace MMI {
NonPointerDrawingManager::NonPointerDrawingManager() {}

NonPointerDrawingManager::~NonPointerDrawingManager() {}

void NonPointerDrawingManager::DrawPointer(int32_t displayId, int32_t globalX, int32_t globalY)
{
    MMI_HILOGD("Non display:%{public}d,globalX:%{public}d,globalY:%{public}d", displayId, globalX, globalY);
    return;
}

void NonPointerDrawingManager::OnDisplayInfo(int32_t displayId, int32_t width, int32_t height)
{
    MMI_HILOGD("Non display:%{public}d,width:%{public}d,height:%{public}d", displayId, width, height);
    return;
}

void NonPointerDrawingManager::UpdatePointerDevice(bool hasPointerDevice)
{
    MMI_HILOGD("Non hasPointerDevice:%{public}d", hasPointerDevice);
    return;
}

bool NonPointerDrawingManager::Init()
{
    CALL_LOG_ENTER;
    InputDevMgr->Attach(GetInstance());
    return true;
}
} // namespace MMI
} // namespace OHOS