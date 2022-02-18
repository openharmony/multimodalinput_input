/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "manipulation_event.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "securec.h"

namespace OHOS {
    namespace {
        using namespace OHOS::MMI;
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ManipulationEvent" };
    }

ManipulationEvent::~ManipulationEvent() {};
void ManipulationEvent::Initialize(int32_t windowId, int32_t startTime, int32_t operationState, int32_t pointerCount,
                                   fingerInfos fingersInfos[], int32_t highLevelEvent, const std::string& uuid,
                                   int32_t sourceType, uint64_t occurredTime, const std::string& deviceId,
                                   int32_t inputDeviceId,  bool isHighLevelEvent, uint16_t deviceUdevTags)
{
    if (pointerCount < 0 || pointerCount > FINGER_NUM) {
        return;
    }

    MultimodalEvent::Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
                                isHighLevelEvent, deviceUdevTags);
    startTime_ = startTime;
    operationState_ = operationState;
    pointerCount_ = pointerCount;
    if (fingersInfos != nullptr) {
        int32_t ret = memset_s(fingersInfos_, sizeof(fingerInfos) * FINGER_NUM, 0, sizeof(fingerInfos) * FINGER_NUM);
        CHK(ret == EOK, MEMSET_SEC_FUN_FAIL);
        ret = memcpy_s(fingersInfos_, sizeof(fingerInfos) * FINGER_NUM, fingersInfos,
                       sizeof(fingerInfos) * pointerCount);
        CHK(ret == EOK, MEMCPY_SEC_FUN_FAIL);
    }
}

void ManipulationEvent::Initialize(ManipulationEvent& maniPulationEvent)
{
    const MultimodalEvent* multimodalEvent = &maniPulationEvent;
    MultimodalEvent::Initialize(*multimodalEvent);
    startTime_ = maniPulationEvent.GetStartTime();
    operationState_ = maniPulationEvent.GetPhase();
    pointerCount_ = maniPulationEvent.GetPointerCount();
    int32_t ret = memcpy_s(fingersInfos_, sizeof(fingersInfos_) * FINGER_NUM, maniPulationEvent.GetFingersInfos(),
                           sizeof(fingerInfos)*FINGER_NUM);
    CHK(ret == EOK, MEMCPY_SEC_FUN_FAIL);
}

int32_t ManipulationEvent::GetStartTime() const
{
    return startTime_;
}

int32_t ManipulationEvent::GetPhase() const
{
    return operationState_;
}

MmiPoint ManipulationEvent::GetPointerPosition(int32_t index) const
{
    if (index < 0 || index >= FINGER_NUM) {
        return MmiPoint(0, 0, 0);
    }
    for (int32_t i = 0; i < pointerCount_; i++) {
        if (fingersInfos_[i].mPointerId == index) {
            return fingersInfos_[i].mMp;
        }
    }
    return MmiPoint(0, 0, 0);
}

void ManipulationEvent::SetScreenOffset(float offsetX, float offsetY)
{
    int32_t pointerCount = GetPointerCount();

    for (int32_t i = 0; i < pointerCount; i++) {
        fingersInfos_[i].mMp.Setxy(offsetX, offsetY);
    }
}

MmiPoint ManipulationEvent::GetPointerScreenPosition(int32_t index) const
{
    if (index < 0 || index >= FINGER_NUM) {
        return MmiPoint(0, 0, 0);
    }
    return fingersInfos_[index].mMp;
}

int32_t ManipulationEvent::GetPointerCount() const
{
    return pointerCount_;
}

int32_t ManipulationEvent::GetPointerId(int32_t index) const
{
    if (index < 0 || index >= FINGER_NUM) {
        return -1;
    }
    return fingersInfos_[index].mPointerId;
}

float ManipulationEvent::GetForce(int32_t index) const
{
    if (index < 0 || index >= FINGER_NUM) {
        return 0.0F;
    }
    return fingersInfos_[index].mTouchPressure;
}

float ManipulationEvent::GetRadius(int32_t index) const
{
    if (index < 0 || index >= FINGER_NUM) {
        return 0.0F;
    }
    return fingersInfos_[index].mTouchArea;
}

const fingerInfos* ManipulationEvent::GetFingersInfos() const
{
    return fingersInfos_;
}
} // namespace OHOS