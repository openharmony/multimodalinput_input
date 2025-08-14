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

#include "pointer_event.h"
#include "pointeritem_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerItemFuzzTest"

namespace OHOS {
namespace MMI {

void PointerItemGetFuncFuzzTest(PointerEvent::PointerItem &item)
{
    item.GetPointerId();
    item.GetDownTime();
    item.IsPressed();
    item.GetDisplayX();
    item.GetDisplayY();
    item.GetWindowX();
    item.GetWindowY();
    item.GetDisplayXPos();
    item.GetDisplayYPos();
    item.GetWindowXPos();
    item.GetWindowYPos();
    item.GetFixedDisplayX();
    item.GetFixedDisplayY();
    item.GetFixedDisplayXPos();
    item.GetFixedDisplayYPos();
    item.GetWidth();
    item.GetHeight();
    item.GetTiltX();
    item.GetTiltY();
    item.GetToolDisplayX();
    item.GetToolDisplayY();
    item.GetToolWindowX();
    item.GetToolWindowY();
    item.GetGlobalX();
    item.GetGlobalY();
    item.IsValidGlobalXY();
    item.GetToolWidth();
    item.GetToolHeight();
    item.GetPressure();
    item.GetMoveFlag();
    item.GetLongAxis();
    item.GetShortAxis();
    item.GetDeviceId();
    item.GetToolType();
    item.GetTargetWindowId();
    item.GetRawDx();
    item.GetRawDy();
    item.GetOriginPointerId();
    item.GetRawDisplayX();
    item.GetRawDisplayY();
    item.GetBlobId();
    item.GetTwist();
    item.IsCanceled();
    item.GetOrientation();

    Parcel parcel;
    item.WriteToParcel(parcel);
    item.ReadFromParcel(parcel);
}

void PointerItemOtherFuzzTest(FuzzedDataProvider &provider, PointerEvent::PointerItem &item)
{
    int32_t toolDisplayX = provider.ConsumeIntegral<int32_t>();
    item.SetToolDisplayX(toolDisplayX);

    int32_t toolDisplayY = provider.ConsumeIntegral<int32_t>();
    item.SetToolDisplayY(toolDisplayY);

    int32_t toolWindowX = provider.ConsumeIntegral<int32_t>();
    item.SetToolWindowX(toolWindowX);

    int32_t toolWindowY = provider.ConsumeIntegral<int32_t>();
    item.SetToolWindowY(toolWindowY);

    double globalX = provider.ConsumeFloatingPoint<double>();
    item.SetGlobalX(globalX);

    double globalY = provider.ConsumeFloatingPoint<double>();
    item.SetGlobalY(globalY);

    int32_t toolWidth = provider.ConsumeIntegral<int32_t>();
    item.SetToolWidth(toolWidth);

    int32_t toolHeight = provider.ConsumeIntegral<int32_t>();
    item.SetToolHeight(toolHeight);

    double pressure = provider.ConsumeFloatingPoint<double>();
    item.SetPressure(pressure);

    int32_t moveFlag = provider.ConsumeIntegral<int32_t>();
    item.SetMoveFlag(moveFlag);

    int32_t longAxis = provider.ConsumeIntegral<int32_t>();
    item.SetLongAxis(longAxis);

    int32_t shortAxis = provider.ConsumeIntegral<int32_t>();
    item.SetShortAxis(shortAxis);

    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    item.SetDeviceId(deviceId);

    int32_t toolType = provider.ConsumeIntegral<int32_t>();
    item.SetToolType(toolType);

    int32_t targetWindowId = provider.ConsumeIntegral<int32_t>();
    item.SetTargetWindowId(targetWindowId);

    int32_t rawDx = provider.ConsumeIntegral<int32_t>();
    item.SetRawDx(rawDx);

    int32_t rawDy = provider.ConsumeIntegral<int32_t>();
    item.SetRawDy(rawDy);

    int32_t originPointerId = provider.ConsumeIntegral<int32_t>();
    item.SetOriginPointerId(originPointerId);

    int32_t rawDisplayX = provider.ConsumeIntegral<int32_t>();
    item.SetRawDisplayX(rawDisplayX);

    int32_t rawDisplayY = provider.ConsumeIntegral<int32_t>();
    item.SetRawDisplayY(rawDisplayY);

    int32_t blobId = provider.ConsumeIntegral<int32_t>();
    item.SetBlobId(blobId);

    int32_t twist = provider.ConsumeIntegral<int32_t>();
    item.SetTwist(twist);

    bool canceled = provider.ConsumeBool();
    item.SetCanceled(canceled);

    int32_t orientation = provider.ConsumeIntegral<int32_t>();
    item.SetOrientation(orientation);
}

bool PointerItemFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    PointerEvent::PointerItem item;
    int32_t pointerId = provider.ConsumeIntegral<int32_t>();
    item.SetPointerId(pointerId);

    int64_t downTime = provider.ConsumeIntegral<int64_t>();
    item.SetDownTime(downTime);

    bool pressed = provider.ConsumeBool();
    item.SetPressed(pressed);

    int32_t displayX = provider.ConsumeIntegral<int32_t>();
    item.SetDisplayX(displayX);

    int32_t displayY = provider.ConsumeIntegral<int32_t>();
    item.SetDisplayY(displayY);

    int32_t windowX = provider.ConsumeIntegral<int32_t>();
    item.SetWindowX(windowX);

    int32_t windowY = provider.ConsumeIntegral<int32_t>();
    item.SetWindowY(windowY);

    double displayXPos = provider.ConsumeFloatingPoint<double>();
    item.SetDisplayXPos(displayXPos);

    double displayYPos = provider.ConsumeFloatingPoint<double>();
    item.SetDisplayYPos(displayYPos);

    double windowXPos = provider.ConsumeFloatingPoint<double>();
    item.SetWindowXPos(windowXPos);

    double windowYPos = provider.ConsumeFloatingPoint<double>();
    item.SetWindowYPos(windowYPos);

    int32_t fixedDisplayX = provider.ConsumeIntegral<int32_t>();
    item.SetFixedDisplayX(fixedDisplayX);

    int32_t fixedDisplayY = provider.ConsumeIntegral<int32_t>();
    item.SetFixedDisplayY(fixedDisplayY);

    double fixedDisplayXPos = provider.ConsumeFloatingPoint<double>();
    item.SetFixedDisplayXPos(fixedDisplayXPos);

    double fixedDisplayYPos = provider.ConsumeFloatingPoint<double>();
    item.SetFixedDisplayYPos(fixedDisplayYPos);

    int32_t width = provider.ConsumeIntegral<int32_t>();
    item.SetWidth(width);

    int32_t height = provider.ConsumeIntegral<int32_t>();
    item.SetHeight(height);

    double titleX = provider.ConsumeFloatingPoint<double>();
    item.SetTiltX(titleX);

    double titleY = provider.ConsumeFloatingPoint<double>();
    item.SetTiltY(titleY);

    PointerItemOtherFuzzTest(provider, item);

    PointerItemGetFuncFuzzTest(item);
    MMI_HILOGD("PointerItemFuzzTest");
    return true;
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::MMI::PointerItemFuzzTest(data, size);
    return 0;
}
