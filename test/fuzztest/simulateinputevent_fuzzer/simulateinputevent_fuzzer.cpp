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

#include "input_manager.h"
#include "define_multimodal.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "SimulateInputEventFuzzTest" };
constexpr int32_t NANOSECOND_TO_MILLISECOND = 1000000;
constexpr int32_t SEC_TO_NANOSEC = 1000000000;
} // namespace

int64_t GetNanoTime()
{
    struct timespec time = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &time);
    return static_cast<int64_t>(time.tv_sec) * SEC_TO_NANOSEC + time.tv_nsec;
}

bool SimulateInputEventFuzzTest(const uint8_t* data, size_t /* size */)
{
    auto injectDownEvent = KeyEvent::Create();
    CHKPF(injectDownEvent);
    int64_t downTime = GetNanoTime()/NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_FN);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_FN);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);

    auto injectUpEvent = KeyEvent::Create();
    CHKPF(injectUpEvent);
    downTime = GetNanoTime()/NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitUp;
    kitUp.SetKeyCode(KeyEvent::KEYCODE_FN);
    kitUp.SetPressed(false);
    kitUp.SetDownTime(downTime);
    injectUpEvent->SetKeyCode(KeyEvent::KEYCODE_FN);
    injectUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
    InputManager::GetInstance()->SimulateInputEvent(injectUpEvent);

    auto pointerDownEvent = PointerEvent::Create();
    CHKPF(pointerDownEvent);
    PointerEvent::PointerItem downitem;
    downitem.SetPointerId(0);   // test code，set the PointerId = 0
    downitem.SetGlobalX(10);   // test code，set the GlobalX = 823
    downitem.SetGlobalY(10);   // test code，set the GlobalY = 723
    downitem.SetPressure(5);    // test code，set the Pressure = 5
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
    upitem.SetGlobalX(10);   // test code，set the GlobalX = 823
    upitem.SetGlobalY(10);   // test code，set the GlobalY = 723
    upitem.SetPressure(5);    // test code，set the Pressure = 5
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

