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

#include "i_pointer_drawing_manager.h"

#include <common/rs_common_def.h>

#include "define_multimodal.h"
#include "pointer_device_manager.h"
#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_CURSOR

namespace OHOS {
namespace MMI {
#ifdef OHOS_BUILD_EMULATOR
class EmulatorPointerDrawingManager final : public IPointerDrawingManager {
public:
    void SetMouseDisplayState(bool state) override
    {
        mouseDisplayState_ = state;
        POINTER_DEV_MGR.mouseDisplayState = mouseDisplayState_;
    }

    bool GetMouseDisplayState() const override
    {
        return mouseDisplayState_;
    }

private:
    bool mouseDisplayState_ {false};
};
#endif

IPointerDrawingManager* IPointerDrawingManager::GetInstance()
{
#ifndef OHOS_BUILD_EMULATOR
    static IPointerDrawingManager iPointDrawMgr_;
#else
    static EmulatorPointerDrawingManager iPointDrawMgr_;
#endif
    return &iPointDrawMgr_;
}

int32_t IPointerDrawingManager::GetCursorSurfaceId(uint64_t &surfaceId)
{
    surfaceId = Rosen::INVALID_NODEID;
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS