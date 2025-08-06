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
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerEventFuzzTest"

namespace OHOS {
namespace MMI {
#define ODDEVENFLAG 2
template<class T>
size_t GetObject(T &object, const uint8_t *data, size_t size)
{
    size_t objectSize = sizeof(object);
    if (objectSize > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, objectSize, data, objectSize);
    if (ret != EOK) {
        return 0;
    }
    return objectSize;
}

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
    pointEvent.GetAxisValue(PointerEvent::AxisType::AXIS_TYPE_UNKNOWN);
    pointEvent.ClearAxisValue();
    pointEvent.ClearAxisStatus(PointerEvent::AxisType::AXIS_TYPE_UNKNOWN);
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

void PointerEventFuzzTest_Add(const uint8_t *data, size_t size, size_t &startPos,
                              int32_t &rowsBefore, PointerEvent &pointEvent)
{
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    std::vector<uint8_t> enhanceData;
    enhanceData.push_back(rowsBefore);
    pointEvent.SetEnhanceData(enhanceData);
#endif

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetFingerprintDistanceX(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetFingerprintDistanceY(rowsBefore);
#endif

    std::vector<uint8_t> buffer;
    enhanceData.push_back(rowsBefore);
    pointEvent.SetBuffer(buffer);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetDispatchTimes(rowsBefore);

    std::vector<int32_t> pressedKeys;
    pressedKeys.push_back(rowsBefore);
    pointEvent.SetPressedKeys(pressedKeys);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetHandlerEventType(rowsBefore);

#ifdef OHOS_BUILD_ENABLE_ANCO
    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetAncoDeal(rowsBefore % ODDEVENFLAG == 0 ? true : false);
#endif
    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetAutoToVirtualScreen(rowsBefore % ODDEVENFLAG == 0 ? true : false);
    pointEvent.SetFixedMode(PointerEvent::FixedMode::SCREEN_MODE_UNKNOWN);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.ActionToShortStr(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetScrollRows(rowsBefore);
}

bool PointerEventFuzzTest(const uint8_t *data, size_t size)
{
    size_t startPos = 0;
    int32_t rowsBefore;
    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);

    PointerEvent pointEvent(rowsBefore);
    pointEvent.Reset();

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetThrowAngle(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetThrowSpeed(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetPointerAction(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetOriginPointerAction(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetHandOption(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetPointerId(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    PointerEvent::PointerItem item;
    pointEvent.AddPointerItem(item);
    pointEvent.UpdatePointerItem(rowsBefore, item);
    pointEvent.GetPointerItem(rowsBefore, item);
    pointEvent.GetOriginPointerItem(rowsBefore, item);
    pointEvent.RemovePointerItem(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetButtonPressed(rowsBefore);
    pointEvent.IsButtonPressed(rowsBefore);
    pointEvent.DeleteReleaseButton(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetButtonId(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetFingerCount(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetZOrder(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetAxisValue(PointerEvent::AxisType::AXIS_TYPE_UNKNOWN, rowsBefore);
    pointEvent.HasAxis(rowsBefore, PointerEvent::AxisType::AXIS_TYPE_UNKNOWN);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetVelocity(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetAxisEventType(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    pointEvent.SetPullId(rowsBefore);

    PointerEventFuzzTest_Add(data, size, startPos, rowsBefore, pointEvent);
    
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
