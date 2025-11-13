/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "input_manager_util.h"

#include "event_util_test.h"
#include "input_event.h"
#include "key_event.h"
#include "pointer_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputManagerUtil"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t TIME_WAIT_FOR_OP { 100 };
constexpr int32_t NANOSECOND_TO_MILLISECOND { 1000000 };
constexpr int32_t DEFAULT_POINTER_ID { 0 };
constexpr int32_t DEFAULT_DEVICE_ID { 0 };
constexpr int32_t INDEX_FIRST { 1 };
constexpr int32_t INDEX_SECOND { 2 };
constexpr int32_t INDEX_THIRD { 3 };
constexpr int32_t MOUSE_ICON_SIZE { 64 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_2 { 50 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_3 { 53 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_4 { 200 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_5 { 503 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_6 { 520 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_7 { 523 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_8 { 550 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_9 { 593 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_10 { 600 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_11 { 610 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_12 { 623 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_13 { 10 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_15 { 40 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_16 { 546 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_17 { 555 };
constexpr int32_t POINTER_ITEM_DISPLAY_X_OFFSET_18 { 888 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_1 { 10 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_2 { 50 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_3 { 60 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_4 { 68 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_5 { 80 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_6 { 200 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_7 { 504 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_8 { 530 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_9 { 555 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_10 { 610 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_11 { 650 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_12 { 703 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_13 { 723 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_14 { 733 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_15 { 777 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_16 { 783 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_17 { 823 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_18 { 910 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_19 { 999 };
constexpr int32_t POINTER_ITEM_DISPLAY_Y_OFFSET_20 { 1259 };
constexpr int32_t POINTER_ITEM_WIDTH_OFFSET_1 { 20 };
constexpr int32_t POINTER_ITEM_WIDTH_OFFSET_2 { 50 };
constexpr int32_t POINTER_ITEM_WIDTH_OFFSET_3 { 80 };
constexpr int32_t POINTER_ITEM_HEIGHT_OFFSET_1 { 60 };
constexpr int32_t POINTER_ITEM_HEIGHT_OFFSET_2 { 80 };
constexpr int32_t POINTER_ITEM_WINDOW_X_OFFSET_1 { 20 };
constexpr int32_t POINTER_ITEM_WINDOW_X_OFFSET_2 { 55 };
constexpr int32_t POINTER_ITEM_WINDOW_X_OFFSET_3 { 67 };
constexpr int32_t POINTER_ITEM_WINDOW_X_OFFSET_4 { 70 };
constexpr int32_t POINTER_ITEM_WINDOW_X_OFFSET_5 { 80 };
constexpr int32_t POINTER_ITEM_WINDOW_X_OFFSET_6 { 120 };
constexpr int32_t POINTER_ITEM_WINDOW_X_OFFSET_7 { 300 };
constexpr int32_t POINTER_ITEM_WINDOW_X_OFFSET_8 { 323 };
constexpr int32_t POINTER_ITEM_WINDOW_X_OFFSET_9 { 701 };
constexpr int32_t POINTER_ITEM_WINDOW_X_OFFSET_10 { 720 };
constexpr int32_t POINTER_ITEM_WINDOW_X_OFFSET_11 { 740 };
constexpr int32_t POINTER_ITEM_WINDOW_Y_OFFSET_1 { 45 };
constexpr int32_t POINTER_ITEM_WINDOW_Y_OFFSET_2 { 66 };
constexpr int32_t POINTER_ITEM_WINDOW_Y_OFFSET_3 { 70 };
constexpr int32_t POINTER_ITEM_WINDOW_Y_OFFSET_4 { 90 };
constexpr int32_t POINTER_ITEM_WINDOW_Y_OFFSET_5 { 99 };
constexpr int32_t POINTER_ITEM_WINDOW_Y_OFFSET_6 { 106 };
constexpr int32_t POINTER_ITEM_WINDOW_Y_OFFSET_7 { 300 };
constexpr int32_t POINTER_ITEM_WINDOW_Y_OFFSET_8 { 453 };
constexpr int32_t POINTER_ITEM_WINDOW_Y_OFFSET_9 { 702 };
constexpr int32_t POINTER_ITEM_WINDOW_Y_OFFSET_10 { 730 };
constexpr int32_t POINTER_ITEM_WINDOW_Y_OFFSET_11 { 750 };
constexpr double POINTER_ITEM_PRESSURE_OFFSET_1 { 5.0 };
constexpr double POINTER_ITEM_PRESSURE_OFFSET_2 { 7.0 };
constexpr double POINTER_ITEM_PRESSURE_OFFSET_3 { 0.15 };
constexpr double POINTER_ITEM_PRESSURE_OFFSET_4 { 0.45 };
constexpr double POINTER_ITEM_PRESSURE_OFFSET_5 { 0.7 };
constexpr double POINTER_AXIS_VALUE_OFFSET_1 { -1.0000 };
constexpr double POINTER_AXIS_VALUE_OFFSET_2 { 30.0 };
constexpr double POINTER_AXIS_VALUE_OFFSET_3 { 40.0 };
constexpr double POINTER_ITEM_TITLE_X_OFFSET_1 { 2.12 };
constexpr double POINTER_ITEM_TITLE_X_OFFSET_2 { 12.22 };
constexpr double POINTER_ITEM_TITLE_X_OFFSET_3 { 10.0 };
constexpr double POINTER_ITEM_TITLE_Y_OFFSET_1 { 5.43 };
constexpr double POINTER_ITEM_TITLE_Y_OFFSET_2 { 15.33 };
constexpr double POINTER_ITEM_TITLE_Y_OFFSET_3 { -9.0 };
constexpr int32_t POINTER_ITEM_ID_INVALID { -1 };
constexpr int32_t POINTER_ITEM_ID_ONE { 1 };
constexpr int32_t POINTER_ITEM_ID_TWO { 2 };
constexpr int32_t POINTER_ITEM_ID_FOUR { 4 };

} // namespace

std::shared_ptr<KeyOption> InputManagerUtil::InitOption(
    const std::set<int32_t> &preKeys, int32_t finalKey, bool isFinalKeyDown, int32_t duration)
{
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyDown(isFinalKeyDown);
    keyOption->SetFinalKey(finalKey);
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKeyDownDuration(duration);
    return keyOption;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupPointerEvent001()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_7);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_13);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_1);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_11);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_18);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_2);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupPointerEvent002()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_9);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_16);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_1);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_10);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_10);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_2);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupPointerEvent003()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_3);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_14);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_1);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_12);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_17);
    item.SetPressure(0);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupPointerEvent005()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(downTime);
    item.SetPressed(true);

    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_6);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_8);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_11);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_11);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupPointerEvent006()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);
    PointerEvent::PointerItem item;
    item.SetPressed(false);
    item.SetPointerId(0);
    item.SetDownTime(0);

    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_4);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_4);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_3);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_5);

    item.SetWidth(POINTER_ITEM_WIDTH_OFFSET_2);
    item.SetPressure(0);
    item.SetDeviceId(0);
    item.SetHeight(POINTER_ITEM_HEIGHT_OFFSET_1);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupPointerEvent007()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(downTime);
    item.SetPressed(false);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_8);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_10);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_10);
    item.SetWidth(POINTER_ITEM_WIDTH_OFFSET_3);
    item.SetHeight(POINTER_ITEM_HEIGHT_OFFSET_2);
    item.SetPressure(0);
    item.SetDeviceId(0);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_11);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupPointerEvent009()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, POINTER_AXIS_VALUE_OFFSET_1);
    PointerEvent::PointerItem item;
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_7);
    item.SetDownTime(0);
    item.SetPressed(false);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_5);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_9);
    item.SetPointerId(1);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_9);
    item.SetDeviceId(0);
    item.SetWidth(POINTER_ITEM_WIDTH_OFFSET_1);
    item.SetHeight(POINTER_ITEM_HEIGHT_OFFSET_1);
    item.SetPressure(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupPointerEvent010()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, POINTER_AXIS_VALUE_OFFSET_2);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, POINTER_AXIS_VALUE_OFFSET_3);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(0);
    item.SetPressed(false);

    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_4);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_6);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_7);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_7);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupPointerEvent011()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetTiltY(POINTER_ITEM_TITLE_Y_OFFSET_1);
    item.SetPointerId(0);
    item.SetDownTime(0);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_8);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_7);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_8);
    item.SetHeight(0);
    item.SetTiltX(POINTER_ITEM_TITLE_X_OFFSET_1);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_13);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_3);
    item.SetDeviceId(1);
    item.SetWidth(0);
    pointerEvent->AddPointerItem(item);

    item.SetDownTime(0);
    item.SetPointerId(1);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_4);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_4);
    item.SetWidth(0);
    item.SetDeviceId(1);
    item.SetHeight(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_4);
    item.SetTiltX(POINTER_ITEM_TITLE_X_OFFSET_2);
    item.SetTiltY(POINTER_ITEM_TITLE_Y_OFFSET_2);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_4);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_3);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupPointerEvent012()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetDeviceId(1);
    item.SetTiltY(POINTER_ITEM_TITLE_Y_OFFSET_1);
    item.SetHeight(0);
    item.SetDownTime(0);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_13);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_8);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_7);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_8);
    item.SetWidth(0);
    item.SetTiltX(POINTER_ITEM_TITLE_X_OFFSET_1);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_3);
    item.SetPointerId(0);
    pointerEvent->AddPointerItem(item);

    item.SetDeviceId(1);
    item.SetDownTime(0);
    item.SetTiltX(POINTER_ITEM_TITLE_X_OFFSET_2);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_4);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_3);
    item.SetWidth(0);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_4);
    item.SetHeight(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_4);
    item.SetTiltY(POINTER_ITEM_TITLE_Y_OFFSET_2);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_4);
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupPointerEvent013()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_7);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_13);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_8);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_8);
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetTiltX(POINTER_ITEM_TITLE_X_OFFSET_1);
    item.SetTiltY(POINTER_ITEM_TITLE_Y_OFFSET_1);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_3);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);
    item.SetDownTime(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_4);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_4);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_4);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_3);
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetTiltX(POINTER_ITEM_TITLE_X_OFFSET_2);
    item.SetTiltY(POINTER_ITEM_TITLE_Y_OFFSET_2);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_4);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupPointerEvent014()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);
    PointerEvent::PointerItem item;
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_4);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_9);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_1);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_1);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressed(false);
    item.SetPointerId(0);
    item.SetDownTime(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupPointerEvent015()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetWidth(0);
    item.SetDeviceId(0);
    item.SetDownTime(0);
    item.SetPressed(false);

    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_4);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_20);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_6);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_6);

    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

#ifdef OHOS_BUILD_ENABLE_JOYSTICK
std::shared_ptr<PointerEvent> InputManagerUtil::SetupPointerEvent016()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    return pointerEvent;
}
#endif // OHOS_BUILD_ENABLE_JOYSTICK

std::shared_ptr<PointerEvent> InputManagerUtil::SetupMouseEvent001()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);
    PointerEvent::PointerItem item;

    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_2);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_5);
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_2);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_2);
    item.SetPointerId(0);
    item.SetDownTime(0);
    item.SetPressed(false);

    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupMouseEvent002()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);
    PointerEvent::PointerItem item;
    item.SetDownTime(0);
    item.SetPressed(false);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_15);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_3);
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetWindowX(POINTER_ITEM_WINDOW_X_OFFSET_5);
    item.SetWindowY(POINTER_ITEM_WINDOW_Y_OFFSET_4);
    item.SetPressure(0);
    item.SetPointerId(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupTouchScreenEvent001()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_13);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_1);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_1);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupTouchScreenEvent002()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_2);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_2);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_1);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

void InputManagerUtil::SetPointerItem(PointerEvent::PointerItem &item, int32_t pointerId)
{
    item.SetPointerId(pointerId);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_2);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_2);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_1);
    item.SetDeviceId(1);
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupSimulateEvent001()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);

    PointerEvent::PointerItem item;
    SetPointerItem(item, POINTER_ITEM_ID_ONE);
    pointerEvent->AddPointerItem(item);

    SetPointerItem(item, POINTER_ITEM_ID_TWO);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(POINTER_ITEM_ID_ONE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupSimulateEvent002()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);

    PointerEvent::PointerItem item;
    SetPointerItem(item, POINTER_ITEM_ID_TWO);
    pointerEvent->AddPointerItem(item);

    SetPointerItem(item, POINTER_ITEM_ID_INVALID);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(POINTER_ITEM_ID_TWO);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupSimulateEvent003()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);

    PointerEvent::PointerItem item;
    SetPointerItem(item, POINTER_ITEM_ID_INVALID);
    pointerEvent->AddPointerItem(item);

    SetPointerItem(item, POINTER_ITEM_ID_INVALID);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(POINTER_ITEM_ID_INVALID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupSimulateEvent004()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);

    PointerEvent::PointerItem item;
    SetPointerItem(item, POINTER_ITEM_ID_INVALID);
    pointerEvent->AddPointerItem(item);

    SetPointerItem(item, POINTER_ITEM_ID_INVALID);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(POINTER_ITEM_ID_FOUR);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupSimulateEvent005()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);

    PointerEvent::PointerItem item;
    SetPointerItem(item, POINTER_ITEM_ID_ONE);
    pointerEvent->AddPointerItem(item);

    SetPointerItem(item, POINTER_ITEM_ID_TWO);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(POINTER_ITEM_ID_INVALID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupSimulateEvent006()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);

    PointerEvent::PointerItem item;
    SetPointerItem(item, POINTER_ITEM_ID_INVALID);
    pointerEvent->AddPointerItem(item);

    SetPointerItem(item, POINTER_ITEM_ID_FOUR);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(POINTER_ITEM_ID_FOUR);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupSimulateEvent007()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);

    PointerEvent::PointerItem item;
    SetPointerItem(item, POINTER_ITEM_ID_ONE);
    pointerEvent->AddPointerItem(item);

    SetPointerItem(item, POINTER_ITEM_ID_INVALID);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(POINTER_ITEM_ID_INVALID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupSimulateEvent008()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);

    PointerEvent::PointerItem item;
    SetPointerItem(item, POINTER_ITEM_ID_INVALID);
    pointerEvent->AddPointerItem(item);

    SetPointerItem(item, POINTER_ITEM_ID_ONE);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(POINTER_ITEM_ID_ONE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

void InputManagerUtil::PrintPointerEventId(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_HILOGI("PointerEvent pointerId:%{public}d", pointerEvent->GetPointerId());
    auto pointerItems = pointerEvent->GetAllPointerItems();
    auto it = pointerItems.begin();
    int32_t count = 1;
    for (pointerItems.begin(); it != pointerItems.end(); ++it) {
        MMI_HILOGI("PointerItem:%{public}d, pointerId:%{public}d", count, it->GetPointerId());
        count++;
    }
}

std::shared_ptr<KeyEvent> InputManagerUtil::SetupKeyEvent001()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    kitDown.SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->AddPressedKeyItems(kitDown);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    return keyEvent;
}

std::shared_ptr<KeyEvent> InputManagerUtil::SetupKeyEvent002()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_A);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddPressedKeyItems(kitDown);

    return keyEvent;
}

std::shared_ptr<KeyEvent> InputManagerUtil::SetupKeyEvent003()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_A);
    kitDown.SetDownTime(downTime);
    kitDown.SetPressed(true);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->AddPressedKeyItems(kitDown);

    return keyEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::TestMarkConsumedStep1()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_7);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_13);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_1);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetId(std::numeric_limits<int32_t>::max() - INDEX_THIRD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerUtil::TestMarkConsumedStep2()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_12);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_13);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_1);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetId(std::numeric_limits<int32_t>::max() - INDEX_SECOND);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    return pointerEvent;
}

void InputManagerUtil::TestMarkConsumedStep3(int32_t monitorId, int32_t eventId)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_MARK_CONSUMED);
    TestMarkConsumed(monitorId, eventId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

void InputManagerUtil::TestMarkConsumedStep4()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetDeviceId(1);
    item.SetPointerId(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_17);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_15);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetId(std::numeric_limits<int32_t>::max() - INDEX_FIRST);

#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent, TestScene::EXCEPTION_TEST);
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

void InputManagerUtil::TestMarkConsumedStep5()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_16);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_12);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_1);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetId(std::numeric_limits<int32_t>::max());
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);

#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent, TestScene::EXCEPTION_TEST);
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

void InputManagerUtil::TestMarkConsumedStep6()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_18);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_19);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_1);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetId(std::numeric_limits<int32_t>::max());
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    TestUtil->SetRecvFlag(RECV_FLAG::RECV_FOCUS);
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

void InputManagerUtil::TestMarkConsumed(int32_t monitorId, int32_t eventId)
{
    AccessMonitor monitor;
    InputManager::GetInstance()->MarkConsumed(monitorId, eventId);
}

std::unique_ptr<OHOS::Media::PixelMap> InputManagerUtil::SetMouseIconTest(const std::string iconPath)
{
    CALL_DEBUG_ENTER;
    OHOS::Media::SourceOptions opts;
    opts.formatHint = "image/svg+xml";
    uint32_t ret = 0;
    auto imageSource = OHOS::Media::ImageSource::CreateImageSource(iconPath, opts, ret);
    CHKPP(imageSource);
    std::set<std::string> formats;
    ret = imageSource->GetSupportedFormats(formats);
    MMI_HILOGD("Get supported format:%{public}u", ret);

    OHOS::Media::DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {.width = MOUSE_ICON_SIZE, .height = MOUSE_ICON_SIZE};

    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, ret);
    CHKPL(pixelMap);
    return pixelMap;
}

int32_t InputManagerUtil::TestAddMonitor(std::shared_ptr<IInputEventConsumer> consumer)
{
    return InputManager::GetInstance()->AddMonitor(consumer);
}

void InputManagerUtil::TestRemoveMonitor(int32_t monitorId)
{
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

void InputManagerUtil::TestMonitor(int32_t monitorId, std::shared_ptr<PointerEvent> pointerEvent)
{
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

void InputManagerUtil::TestInterceptorIdAndPointerEvent(
    int32_t interceptorId, std::shared_ptr<PointerEvent> pointerEvent)
{
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    SimulateInputEventUtilTest(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_INTERCEPTOR

    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

void InputManagerUtil::TestInterceptorId(int32_t interceptorId1, int32_t interceptorId2)
{
    if (IsValidHandlerId(interceptorId1)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId1);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    if (IsValidHandlerId(interceptorId2)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId2);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

std::shared_ptr<PointerEvent> InputManagerUtil::SetupTabletToolEvent001()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_OFFSET_7);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_OFFSET_13);
    item.SetPressure(POINTER_ITEM_PRESSURE_OFFSET_5);
    item.SetTiltX(POINTER_ITEM_TITLE_X_OFFSET_3);
    item.SetTiltY(POINTER_ITEM_TITLE_Y_OFFSET_3);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    item.SetToolType(PointerEvent::TOOL_TYPE_PEN);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}
} // namespace MMI
} // namespace OHOS