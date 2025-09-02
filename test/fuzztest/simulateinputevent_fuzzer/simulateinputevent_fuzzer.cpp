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

#include <fuzzer/FuzzedDataProvider.h>
#include "simulateinputevent_fuzzer.h"

#include "define_multimodal.h"
#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SimulateInputEventFuzzTest"

namespace OHOS {
namespace MMI {
bool SimulateInjectEvent(FuzzedDataProvider &fdp)
{
    auto injectDownEvent = KeyEvent::Create();
    if (!injectDownEvent) {
        return false;
    }
    int32_t keyCode = fdp.ConsumeIntegral<int32_t>();
    injectDownEvent->SetKeyCode(keyCode);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem kitDown;
    kitDown.SetDownTime(fdp.ConsumeIntegral<int64_t>());
    kitDown.SetKeyCode(fdp.ConsumeIntegral<int32_t>());
    kitDown.SetPressed(true);
    injectDownEvent->AddPressedKeyItems(kitDown);
    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);

    auto injectUpEvent = KeyEvent::Create();
    if (!injectUpEvent) {
        return false;
    }
    KeyEvent::KeyItem kitUp;
    kitUp.SetDownTime(fdp.ConsumeIntegral<int64_t>());
    kitUp.SetKeyCode(kitDown.GetKeyCode());
    kitUp.SetPressed(false);
    injectUpEvent->SetKeyCode(keyCode);
    injectUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
    InputManager::GetInstance()->SimulateInputEvent(injectUpEvent);

    return true;
}

bool SimulatePointerEvent(FuzzedDataProvider &fdp)
{
    auto pointerDownEvent = PointerEvent::Create();
    if (!pointerDownEvent) {
        return false;
    }
    PointerEvent::PointerItem downitem;
    downitem.SetPointerId(0);
    downitem.SetDisplayX(fdp.ConsumeIntegral<int32_t>());
    downitem.SetDisplayY(fdp.ConsumeIntegral<int32_t>());
    downitem.SetPressure(fdp.ConsumeIntegral<int32_t>());
    downitem.SetDeviceId(1);
    pointerDownEvent->AddPointerItem(downitem);
    pointerDownEvent->SetId(fdp.ConsumeIntegral<int32_t>());
    pointerDownEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerDownEvent->SetPointerId(0);
    pointerDownEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    InputManager::GetInstance()->SimulateInputEvent(pointerDownEvent);

    auto pointerUpEvent = PointerEvent::Create();
    if (!pointerUpEvent) {
        return false;
    }
    PointerEvent::PointerItem upitem;
    upitem.SetPointerId(0);
    upitem.SetDisplayX(downitem.GetDisplayX());
    upitem.SetDisplayY(downitem.GetDisplayY());
    upitem.SetPressure(downitem.GetPressure());
    upitem.SetDeviceId(1);
    pointerUpEvent->AddPointerItem(upitem);
    pointerUpEvent->SetId(fdp.ConsumeIntegral<int32_t>());
    pointerUpEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerUpEvent->SetPointerId(0);
    pointerUpEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    InputManager::GetInstance()->SimulateInputEvent(pointerUpEvent);

    return true;
}

bool SimulateInputEventFuzzTest(FuzzedDataProvider &fdp)
{
    bool ok1 = SimulateInjectEvent(fdp);
    bool ok2 = SimulatePointerEvent(fdp);
    return ok1 || ok2;
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    OHOS::MMI::SimulateInputEventFuzzTest(fdp);
    return 0;
}