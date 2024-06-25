/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "injectevent_fuzzer.h"
#include "input_manager.h"
#include "define_multimodal.h"
#include "mmi_service.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {

template<class T>
size_t GetObject(T &object, const uint8_t *data, size_t size)
{
    size_t objectNum = sizeof(object);
    if (objectNum > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, objectNum, data, objectNum);
    if (ret != EOK) {
        return 0;
    }
    return objectNum;
}

bool InjectKeyEvent(const uint8_t* data, const size_t size, size_t &startPos)
{
    auto injectDownEvent = KeyEvent::Create();
    CHKPF(injectDownEvent);
    int32_t keyCode;
    CHECKSIZE(startPos, size);
    startPos += GetObject<int32_t>(keyCode, data + startPos, size - startPos);
    injectDownEvent->SetKeyCode(keyCode);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    int64_t downTime;
    CHECKSIZE(startPos, size);
    startPos += GetObject<int64_t>(downTime, data + startPos, size - startPos);
    KeyEvent::KeyItem kitDown;
    kitDown.SetDownTime(downTime);
    int32_t keyCodePressed;
    CHECKSIZE(startPos, size);
    startPos += GetObject<int32_t>(keyCodePressed, data + startPos, size - startPos);
    kitDown.SetKeyCode(keyCodePressed);
    kitDown.SetPressed(true);
    injectDownEvent->AddPressedKeyItems(kitDown);
    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);

    auto injectUpEvent = KeyEvent::Create();
    CHKPF(injectUpEvent);
    CHECKSIZE(startPos, size);
    startPos += GetObject<int64_t>(downTime, data + startPos, size - startPos);
    KeyEvent::KeyItem kitUp;
    kitUp.SetDownTime(downTime);
    kitUp.SetKeyCode(keyCodePressed);
    kitUp.SetPressed(false);
    injectUpEvent->SetKeyCode(keyCode);
    injectUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
    InputManager::GetInstance()->SimulateInputEvent(injectUpEvent);
    return true;
}

bool InjectTouchEvent(const uint8_t* data, const size_t size, size_t &startPos)
{
    auto pointerDownEvent = PointerEvent::Create();
    CHKPF(pointerDownEvent);
    PointerEvent::PointerItem downitem;
    downitem.SetPointerId(0);
    int32_t physicalX;
    CHECKSIZE(startPos, size);
    startPos += GetObject<int32_t>(physicalX, data + startPos, size - startPos);
    downitem.SetDisplayX(physicalX);
    int32_t physicalY;
    CHECKSIZE(startPos, size);
    startPos += GetObject<int32_t>(physicalY, data + startPos, size - startPos);
    downitem.SetDisplayY(physicalY);
    int32_t pressure;
    CHECKSIZE(startPos, size);
    startPos += GetObject<int32_t>(pressure, data + startPos, size - startPos);
    downitem.SetPressure(pressure);
    downitem.SetDeviceId(1);
    pointerDownEvent->AddPointerItem(downitem);
    pointerDownEvent->SetId(std::numeric_limits<int32_t>::max());
    pointerDownEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerDownEvent->SetPointerId(0);
    pointerDownEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    MMI_HILOGD("Call InputManager::InjectTouchEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerDownEvent);

    auto pointerUpEvent = PointerEvent::Create();
    CHKPF(pointerUpEvent);
    PointerEvent::PointerItem upitem;
    upitem.SetPointerId(0);
    upitem.SetDisplayX(physicalX);
    upitem.SetDisplayY(physicalY);
    upitem.SetPressure(pressure);
    upitem.SetDeviceId(1);
    pointerUpEvent->AddPointerItem(upitem);
    pointerUpEvent->SetId(std::numeric_limits<int32_t>::max());
    pointerUpEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerUpEvent->SetPointerId(0);
    pointerUpEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    MMI_HILOGD("Call InputManager::InjectTouchEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerUpEvent);
    return true;
}

bool InjectMouseEvent(const uint8_t* data, const size_t size, size_t &startPos)
{
    auto pointerDownEvent = PointerEvent::Create();
    CHKPF(pointerDownEvent);
    PointerEvent::PointerItem downitem;
    downitem.SetPointerId(0);
    int32_t physicalX;
    CHECKSIZE(startPos, size);
    startPos += GetObject<int32_t>(physicalX, data + startPos, size - startPos);
    downitem.SetDisplayX(physicalX);
    int32_t physicalY;
    CHECKSIZE(startPos, size);
    startPos += GetObject<int32_t>(physicalY, data + startPos, size - startPos);
    downitem.SetDisplayY(physicalY);
    int32_t pressure;
    CHECKSIZE(startPos, size);
    startPos += GetObject<int32_t>(pressure, data + startPos, size - startPos);
    downitem.SetPressure(pressure);
    downitem.SetDeviceId(1);
    pointerDownEvent->AddPointerItem(downitem);
    pointerDownEvent->SetId(std::numeric_limits<int32_t>::max());
    pointerDownEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerDownEvent->SetPointerId(0);
    pointerDownEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    MMI_HILOGD("Call InputManager::InjectMouseEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerDownEvent);

    auto pointerUpEvent = PointerEvent::Create();
    CHKPF(pointerUpEvent);
    PointerEvent::PointerItem upitem;
    upitem.SetPointerId(0);
    upitem.SetDisplayX(physicalX);
    upitem.SetDisplayY(physicalY);
    upitem.SetPressure(pressure);
    upitem.SetDeviceId(1);
    pointerUpEvent->AddPointerItem(upitem);
    pointerUpEvent->SetId(std::numeric_limits<int32_t>::max());
    pointerUpEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerUpEvent->SetPointerId(0);
    pointerUpEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    MMI_HILOGD("Call InputManager::InjectMouseEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerUpEvent);
    return true;
}

bool InjectEventFuzzTest(const uint8_t* data, const size_t size)
{
    size_t startPos = 0;
    if (InjectKeyEvent(data, size, startPos) && InjectTouchEvent(data, size, startPos) &&
        InjectMouseEvent(data, size, startPos)) {
        return true;
    }
    return false;
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::InjectEventFuzzTest(data, size);
    return 0;
}