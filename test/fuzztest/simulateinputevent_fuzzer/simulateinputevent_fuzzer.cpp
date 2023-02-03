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

#include "simulateinputevent_fuzzer.h"

#include "securec.h"

#include "common_method.h"
#include "define_multimodal.h"
#include "input_manager.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "SimulateInputEventFuzzTest" };
} // namespace

bool SimulateInputEventFuzzTest(const uint8_t* data, size_t size)
{
    auto injectDownEvent = KeyEvent::Create();
    CHKPF(injectDownEvent);
    size_t startPos = 0;
    int32_t keyCode;
    startPos += GetObject<int32_t>(keyCode, data + startPos, size - startPos);
    injectDownEvent->SetKeyCode(keyCode);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    int64_t downTime;
    startPos += GetObject<int64_t>(downTime, data + startPos, size - startPos);
    KeyEvent::KeyItem kitDown;
    kitDown.SetDownTime(downTime);
    int32_t keyCodePressed;
    startPos += GetObject<int32_t>(keyCodePressed, data + startPos, size - startPos);
    kitDown.SetKeyCode(keyCodePressed);
    kitDown.SetPressed(true);
    injectDownEvent->AddPressedKeyItems(kitDown);
    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);

    auto injectUpEvent = KeyEvent::Create();
    CHKPF(injectUpEvent);
    startPos += GetObject<int64_t>(downTime, data + startPos, size - startPos);
    KeyEvent::KeyItem kitUp;
    kitUp.SetDownTime(downTime);
    kitUp.SetKeyCode(keyCodePressed);
    kitUp.SetPressed(false);
    injectUpEvent->SetKeyCode(keyCode);
    injectUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
    InputManager::GetInstance()->SimulateInputEvent(injectUpEvent);

    auto pointerDownEvent = PointerEvent::Create();
    CHKPF(pointerDownEvent);
    PointerEvent::PointerItem downitem;
    downitem.SetPointerId(0);   // test code，set the PointerId = 0
    int32_t physicalX;
    startPos += GetObject<int32_t>(physicalX, data + startPos, size - startPos);
    downitem.SetDisplayX(physicalX);   // test code，set the DisplayX = 823
    int32_t physicalY;
    startPos += GetObject<int32_t>(physicalY, data + startPos, size - startPos);
    downitem.SetDisplayY(physicalY);   // test code，set the DisplayY = 723
    int32_t pressure;
    startPos += GetObject<int32_t>(pressure, data + startPos, size - startPos);
    downitem.SetPressure(pressure);    // test code，set the Pressure = 5
    downitem.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerDownEvent->AddPointerItem(downitem);
    pointerDownEvent->SetId(std::numeric_limits<int32_t>::max());
    pointerDownEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerDownEvent->SetPointerId(0);  // test code，set the PointerId = 1
    pointerDownEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    MMI_HILOGD("Call InputManager::SimulatePointerEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerDownEvent);

    auto pointerUpEvent = PointerEvent::Create();
    CHKPF(pointerUpEvent);
    PointerEvent::PointerItem upitem;
    upitem.SetPointerId(0);   // test code，set the PointerId = 0
    upitem.SetDisplayX(physicalX);   // test code，set the DisplayX = 823
    upitem.SetDisplayY(physicalY);   // test code，set the DisplayY = 723
    upitem.SetPressure(pressure);    // test code，set the Pressure = 5
    upitem.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerUpEvent->AddPointerItem(upitem);
    pointerUpEvent->SetId(std::numeric_limits<int32_t>::max());
    pointerUpEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerUpEvent->SetPointerId(0);  // test code，set the PointerId = 1
    pointerUpEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    MMI_HILOGD("Call InputManager::SimulatePointerEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerUpEvent);
    return true;
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::SimulateInputEventFuzzTest(data, size);
    return 0;
}

