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
#include "pointerevent_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerEventFuzzTest"

namespace OHOS {
namespace MMI {
void PointEventGetFuncFuzzTest_Add(PointerEvent &pointEvent)
{
    pointEvent.IsValidCheckMouseFunc();
    pointEvent.IsValidCheckMouse();
    pointEvent.IsValidCheckTouchFunc();
    pointEvent.IsValidCheckTouch();
    pointEvent.IsValid();
    pointEvent.ClearBuffer();
    pointEvent.GetBuffer();
    pointEvent.GetDispatchTimes();
    pointEvent.GetHandlerEventType();

#ifdef OHOS_BUILD_ENABLE_ANCO
    pointEvent.GetAncoDeal();
#endif

    pointEvent.GetAutoToVirtualScreen();
    pointEvent.GetFixedMode();
    pointEvent.GetFixedModeStr();
    pointEvent.GetScrollRows();
    pointEvent.RemoveAllPointerItems();
    pointEvent.ToString();

    PointerEvent::Create();
    PointerEvent pointEvent2 = PointerEvent(pointEvent);
    pointEvent2.ToString();
}
void PointEventGetFuncFuzzTest(PointerEvent &pointEvent)
{
    Parcel parcel;
    pointEvent.WriteToParcel(parcel);
    pointEvent.Marshalling(parcel);
    pointEvent.ReadFromParcel(parcel);
    pointEvent.Unmarshalling(parcel);
    pointEvent.ReadFixedModeFromParcel(parcel);
    pointEvent.ReadAxisFromParcel(parcel);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    pointEvent.ReadEnhanceDataFromParcel(parcel);
#endif
    pointEvent.ReadBufferFromParcel(parcel);
    pointEvent.DumpPointerAction();
    pointEvent.GetPointerAction();
    pointEvent.GetThrowAngle();
    pointEvent.GetThrowSpeed();
    pointEvent.GetOriginPointerAction();
    pointEvent.GetHandOption();
    pointEvent.GetPointerId();
    pointEvent.GetPressedButtons();
    pointEvent.ClearButtonPressed();
    pointEvent.GetPointerCount();
    pointEvent.GetPointerIds();
    pointEvent.GetAllPointerItems();
    pointEvent.GetButtonId();
    pointEvent.GetFingerCount();
    pointEvent.GetZOrder();
    pointEvent.ClearAxisValue();
    pointEvent.GetVelocity();
    pointEvent.GetPressedKeys();
    pointEvent.GetAxisEventType();
    pointEvent.GetPullId();
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    pointEvent.GetEnhanceData();
#endif

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    pointEvent.GetFingerprintDistanceX();
    pointEvent.GetFingerprintDistanceY();
#endif
    PointEventGetFuncFuzzTest_Add(pointEvent);
}

void PointerEventFuzzTest_Add(FuzzedDataProvider &provider, PointerEvent &pointEvent)
{
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    uint8_t data = provider.ConsumeIntegral<uint8_t>();
    std::vector<uint8_t> enhanceData;
    enhanceData.push_back(data);
    pointEvent.SetEnhanceData(enhanceData);
#endif

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    double fingerPrintDistanceX = provider.ConsumeFloatingPoint<double>();
    pointEvent.SetFingerprintDistanceX(fingerPrintDistanceX);

    double fingerPrintDistanceY = provider.ConsumeFloatingPoint<double>();
    pointEvent.SetFingerprintDistanceY(fingerPrintDistanceY);
#endif

    uint8_t buf = provider.ConsumeIntegral<uint8_t>();
    std::vector<uint8_t> buffer;
    enhanceData.push_back(buf);
    pointEvent.SetBuffer(buffer);

    int32_t dispatchTimes = provider.ConsumeIntegral<int32_t>();
    pointEvent.SetDispatchTimes(dispatchTimes);

    int32_t pressedkey = provider.ConsumeIntegral<int32_t>();
    std::vector<int32_t> pressedKeys;
    pressedKeys.push_back(pressedkey);
    pointEvent.SetPressedKeys(pressedKeys);

    uint32_t handleEventType = provider.ConsumeIntegral<uint32_t>();
    pointEvent.SetHandlerEventType(handleEventType);

#ifdef OHOS_BUILD_ENABLE_ANCO
    bool ancodeal = provider.ConsumeBool();
    pointEvent.SetAncoDeal(ancodeal);
#endif
    bool autoToVirtualScreen = provider.ConsumeBool();
    pointEvent.SetAutoToVirtualScreen(autoToVirtualScreen);

    pointEvent.SetFixedMode(PointerEvent::FixedMode::SCREEN_MODE_UNKNOWN);

    int32_t action = provider.ConsumeIntegral<int32_t>();
    pointEvent.ActionToShortStr(action);

    int32_t scrollRows = provider.ConsumeIntegral<int32_t>();
    pointEvent.SetScrollRows(scrollRows);
}

bool PointerEventFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int32_t eventType = provider.ConsumeIntegral<int32_t>();
    PointerEvent pointEvent(eventType);
    pointEvent.Reset();

    double throwAngle = provider.ConsumeFloatingPoint<double>();
    pointEvent.SetThrowAngle(throwAngle);

    double throwSpeed = provider.ConsumeFloatingPoint<double>();
    pointEvent.SetThrowSpeed(throwSpeed);

    int32_t pointerAction = provider.ConsumeIntegral<int32_t>();
    pointEvent.SetPointerAction(pointerAction);

    int32_t originPointerAction = provider.ConsumeIntegral<int32_t>();
    pointEvent.SetOriginPointerAction(originPointerAction);

    int32_t handOption = provider.ConsumeIntegral<int32_t>();
    pointEvent.SetHandOption(handOption);

    int32_t pointerId = provider.ConsumeIntegral<int32_t>();
    pointEvent.SetPointerId(pointerId);

    PointerEvent::PointerItem item;
    pointEvent.AddPointerItem(item);
    pointEvent.UpdatePointerItem(pointerId, item);
    pointEvent.GetPointerItem(pointerId, item);
    pointEvent.GetOriginPointerItem(pointerId, item);
    pointEvent.RemovePointerItem(pointerId);

    int32_t buttonId = provider.ConsumeIntegral<int32_t>();
    pointEvent.SetButtonId(buttonId);
    pointEvent.SetButtonPressed(buttonId);
    pointEvent.IsButtonPressed(buttonId);
    pointEvent.DeleteReleaseButton(buttonId);

    int32_t fingerCount = provider.ConsumeIntegral<int32_t>();
    pointEvent.SetFingerCount(fingerCount);

    float zOrder = provider.ConsumeFloatingPoint<float>();
    pointEvent.SetZOrder(zOrder);

    double axisValue = provider.ConsumeFloatingPoint<double>();
    PointerEvent::AxisType axisType = PointerEvent::AxisType::AXIS_TYPE_UNKNOWN;
    pointEvent.SetAxisValue(axisType, axisValue);
    pointEvent.GetAxisValue(axisType);
    
    int32_t axes = provider.ConsumeIntegral<int32_t>();
    pointEvent.HasAxis(axes, axisType);
    pointEvent.ClearAxisStatus(axisType);

    double velocity = provider.ConsumeFloatingPoint<double>();
    pointEvent.SetVelocity(velocity);

    int32_t axisEventType = provider.ConsumeIntegral<int32_t>();
    pointEvent.SetAxisEventType(axisEventType);

    int32_t pullId = provider.ConsumeIntegral<int32_t>();
    pointEvent.SetPullId(pullId);

    PointerEventFuzzTest_Add(provider, pointEvent);
    
    PointEventGetFuncFuzzTest(pointEvent);
    MMI_HILOGD("PointerEventFuzzTest");
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

    OHOS::MMI::PointerEventFuzzTest(data, size);
    return 0;
}
