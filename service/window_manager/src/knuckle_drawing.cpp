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

#include "knuckle_drawing.h"
#include "define_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleDrawing"

namespace OHOS {
namespace MMI {
KnuckleDrawing::KnuckleDrawing()
{
    knuckleDrawingMgr_ = std::make_shared<KnuckleDrawingManager>();
    CHKPRV(knuckleDrawingMgr_, "knuckleDrawingMgr_ is nullptr");
#ifndef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
    knuckleDynamicDrawingMgr_ = std::make_shared<KnuckleDynamicDrawingManager>();
    CHKPRV(knuckleDynamicDrawingMgr_, "knuckleDynamicDrawingMgr_ is nullptr");
    knuckleDynamicDrawingMgr_->SetKnuckleDrawingManager(knuckleDrawingMgr_);
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
}

void KnuckleDrawing::Draw(const OLD::DisplayInfo& displayInfo, const std::shared_ptr<PointerEvent> &touchEvent)
{
    CHKPRV(knuckleDrawingMgr_, "knuckleDrawingMgr_ is nullptr");
    knuckleDrawingMgr_->UpdateDisplayInfo(displayInfo);
    knuckleDrawingMgr_->KnuckleDrawHandler(touchEvent, displayInfo.rsId);
#ifndef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
    CHKPRV(knuckleDynamicDrawingMgr_, "knuckleDynamicDrawingMgr_ is nullptr");
    knuckleDynamicDrawingMgr_->UpdateDisplayInfo(displayInfo);
    knuckleDynamicDrawingMgr_->KnuckleDynamicDrawHandler(touchEvent, displayInfo.rsId);
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
}

void KnuckleDrawing::SetMultiWindowScreenId(uint64_t screenId, uint64_t displayNodeScreenId)
{
    CHKPRV(knuckleDrawingMgr_, "knuckleDrawingMgr_ is nullptr");
    knuckleDrawingMgr_->SetMultiWindowScreenId(screenId, displayNodeScreenId);
}

void KnuckleDrawing::RegisterAddTimer(AddTimerFunc addTimerFunc)
{
    CHKPRV(knuckleDrawingMgr_, "knuckleDrawingMgr_ is nullptr");
    knuckleDrawingMgr_->RegisterAddTimer(addTimerFunc);
}

extern "C" IKnuckleDrawing *GetKnuckleDrawing()
{
    return new (std::nothrow) KnuckleDrawing();
}

extern "C" void DestroyKnuckleDrawing(IKnuckleDrawing *inst)
{
    if (inst != nullptr) {
        delete inst;
    }
}
} // namespace MMI
} // namespace OHOS