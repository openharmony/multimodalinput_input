/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "event_log_helper.h"
#include "event_util_test.h"
#include "input_handler_type.h"
#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "system_info.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputManagerTest" };
constexpr int32_t TIME_WAIT_FOR_OP = 100;
constexpr int32_t NANOSECOND_TO_MILLISECOND = 1000000;
constexpr int32_t DEFAULT_POINTER_ID = 0;
constexpr int32_t DEFAULT_DEVICE_ID = 0;
constexpr int32_t INDEX_FIRST = 1;
constexpr int32_t INDEX_SECOND = 2;
constexpr int32_t INDEX_THIRD = 3;
} // namespace

class InputManagerTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    std::string GetEventDump();
    std::shared_ptr<PointerEvent> SetupPointerEvent001();
    std::shared_ptr<PointerEvent> SetupPointerEvent002();
    std::shared_ptr<PointerEvent> SetupPointerEvent003();
    std::shared_ptr<PointerEvent> SetupPointerEvent005();
    std::shared_ptr<PointerEvent> SetupPointerEvent006();
    std::shared_ptr<PointerEvent> SetupPointerEvent007();
    std::shared_ptr<PointerEvent> SetupPointerEvent009();
    std::shared_ptr<PointerEvent> SetupPointerEvent010();
    std::shared_ptr<PointerEvent> SetupPointerEvent011();
    std::shared_ptr<PointerEvent> SetupPointerEvent012();
    std::shared_ptr<PointerEvent> SetupPointerEvent013();
    std::shared_ptr<PointerEvent> SetupPointerEvent014();
    std::shared_ptr<PointerEvent> SetupPointerEvent015();
#ifdef OHOS_BUILD_ENABLE_JOYSTICK
    std::shared_ptr<PointerEvent> SetupPointerEvent016();
#endif // OHOS_BUILD_ENABLE_JOYSTICK
    std::shared_ptr<PointerEvent> SetupmouseEvent001();
    std::shared_ptr<PointerEvent> SetupmouseEvent002();
    std::shared_ptr<PointerEvent> SetupTouchScreenEvent001();
    std::shared_ptr<PointerEvent> SetupTouchScreenEvent002();
    std::shared_ptr<KeyEvent> SetupKeyEvent001();
    std::shared_ptr<KeyEvent> SetupKeyEvent002();
    std::shared_ptr<KeyEvent> SetupKeyEvent003();
    std::shared_ptr<PointerEvent> TestMarkConsumedStep1();
    std::shared_ptr<PointerEvent> TestMarkConsumedStep2();
    void TestMarkConsumedStep3(int32_t monitorId, int32_t eventId);
    void TestMarkConsumedStep4();
    void TestMarkConsumedStep5();
    void TestMarkConsumedStep6();
    int32_t TestAddMonitor(std::shared_ptr<IInputEventConsumer> consumer);
    void TestRemoveMonitor(int32_t monitorId);
    void TestMarkConsumed(int32_t monitorId, int32_t eventId);
    std::shared_ptr<PointerEvent> SetupTabletToolEvent001();
};

void InputManagerTest::SetUpTestCase()
{
    ASSERT_TRUE(TestUtil->Init());
}

void InputManagerTest::SetUp()
{
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_FOCUS);
}

void InputManagerTest::TearDown()
{
    TestUtil->AddEventDump("");
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

std::string InputManagerTest::GetEventDump()
{
    return TestUtil->GetEventDump();
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent001()
{
    auto pointerEvent001 = PointerEvent::Create();
    CHKPP(pointerEvent001);
    PointerEvent::PointerItem item001;
    item001.SetDeviceId(1);    // test code，set the DeviceId = 1
    item001.SetPointerId(0);   // test code，set the PointerId = 0
    item001.SetDisplayY(723);   // test code，set the DisplayY = 723
    item001.SetDisplayX(523);   // test code，set the DisplayX = 523
    item001.SetPressure(5);    // test code，set the Pressure = 5
    pointerEvent001->AddPointerItem(item001);

    item001.SetDeviceId(1);    // test code，set the DeviceId = 1
    item001.SetDisplayY(910);   // test code，set the DisplayY = 910
    item001.SetPointerId(1);   // test code，set the PointerId = 1
    item001.SetDisplayX(610);   // test code，set the DisplayX = 610
    item001.SetPressure(7);    // test code，set the Pressure = 7
    pointerEvent001->AddPointerItem(item001);

    pointerEvent001->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent001->SetPointerId(1);  // test code，set the PointerId = 1
    pointerEvent001->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent001;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent002()
{
    auto pointerEvent002 = PointerEvent::Create();
    CHKPP(pointerEvent002);
    PointerEvent::PointerItem item002;
    item002.SetPointerId(0);   // test code，set the PointerId = 0
    item002.SetDisplayX(523);   // test code，set the DisplayX = 523
    item002.SetDisplayY(723);   // test code，set the DisplayY = 723
    item002.SetPressure(5);    // test code，set the Pressure = 5
    item002.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent002->AddPointerItem(item002);

    item002.SetPointerId(1);   // test code，set the PointerId = 1
    item002.SetDisplayX(600);   // test code，set the DisplayX = 600
    item002.SetDisplayY(610);   // test code，set the DisplayY = 610
    item002.SetPressure(7);    // test code，set the Pressure = 7
    item002.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent002->AddPointerItem(item002);

    pointerEvent002->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent002->SetPointerId(1);  // test code，set the PointerId = 1
    pointerEvent002->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent002;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent003()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetDisplayX(523);   // test code，set the DisplayX = 523
    item.SetDisplayY(723);   // test code，set the DisplayY = 723
    item.SetPressure(5);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);   // test code，set the PointerId = 1
    item.SetDisplayX(623);   // test code，set the DisplayX = 623
    item.SetDisplayY(823);   // test code，set the DisplayY = 823
    item.SetPressure(0);    // test code，set the Pressure = 0
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(1);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent005()
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

    item.SetDisplayX(50);
    item.SetDisplayY(50);
    item.SetWindowX(70);
    item.SetWindowY(70);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent006()
{
    auto pointerEventForTest006 = PointerEvent::Create();
    CHKPP(pointerEventForTest006);
    pointerEventForTest006->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEventForTest006->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEventForTest006->SetPointerId(0);
    PointerEvent::PointerItem item06;
    item06.SetPointerId(0);
    item06.SetDownTime(0);
    item06.SetPressed(false);

    item06.SetDisplayX(50);
    item06.SetDisplayY(50);
    item06.SetWindowX(70);
    item06.SetWindowY(70);

    item06.SetWidth(0);
    item06.SetHeight(0);
    item06.SetPressure(0);
    item06.SetDeviceId(0);
    pointerEventForTest006->AddPointerItem(item06);
    return pointerEventForTest006;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent007()
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

    item.SetDisplayX(50);
    item.SetDisplayY(50);
    item.SetWindowX(70);
    item.SetWindowY(70);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent009()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, -1.0000);
    PointerEvent::PointerItem item009;
    item009.SetPointerId(1);
    item009.SetDownTime(0);
    item009.SetPressed(false);

    item009.SetDisplayX(50);
    item009.SetDisplayY(50);
    item009.SetWindowX(70);
    item009.SetWindowY(70);

    item009.SetWidth(0);
    item009.SetHeight(0);
    item009.SetPressure(0);
    item009.SetDeviceId(0);
    pointerEvent->AddPointerItem(item009);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent010()
{
    auto pointerEventForTest010 = PointerEvent::Create();
    CHKPP(pointerEventForTest010);
    pointerEventForTest010->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEventForTest010->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEventForTest010->SetPointerId(1);
    pointerEventForTest010->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 30.0);
    pointerEventForTest010->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, 40.0);
    PointerEvent::PointerItem item010;
    item010.SetPointerId(1);
    item010.SetDownTime(0);
    item010.SetPressed(false);

    item010.SetDisplayX(200);
    item010.SetDisplayY(200);
    item010.SetWindowX(300);
    item010.SetWindowY(300);

    item010.SetWidth(0);
    item010.SetHeight(0);
    item010.SetPressure(0);
    item010.SetDeviceId(0);
    pointerEventForTest010->AddPointerItem(item010);
    return pointerEventForTest010;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent011()
{
    auto pointerEventForTest011 = PointerEvent::Create();
    CHKPP(pointerEventForTest011);
    pointerEventForTest011->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEventForTest011->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEventForTest011->SetPointerId(1);
    PointerEvent::PointerItem item011;
    item011.SetPointerId(0);
    item011.SetDownTime(0);
    item011.SetDisplayX(523);
    item011.SetDisplayY(723);
    item011.SetWindowX(323);
    item011.SetWindowY(453);
    item011.SetWidth(0);
    item011.SetHeight(0);
    item011.SetTiltX(2.12);
    item011.SetTiltY(5.43);
    item011.SetPressure(0.15);
    item011.SetDeviceId(1);
    pointerEventForTest011->AddPointerItem(item011);

    item011.SetPointerId(1);
    item011.SetDownTime(0);
    item011.SetDisplayX(50);
    item011.SetDisplayY(50);
    item011.SetWindowX(70);
    item011.SetWindowY(70);
    item011.SetWidth(0);
    item011.SetHeight(0);
    item011.SetTiltX(12.22);
    item011.SetTiltY(15.33);
    item011.SetPressure(0.45);
    item011.SetDeviceId(1);
    pointerEventForTest011->AddPointerItem(item011);
    return pointerEventForTest011;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent012()
{
    auto pointerEventForTest012 = PointerEvent::Create();
    CHKPP(pointerEventForTest012);
    pointerEventForTest012->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEventForTest012->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEventForTest012->SetPointerId(1);
    PointerEvent::PointerItem item012;
    item012.SetPointerId(0);
    item012.SetDownTime(0);
    item012.SetDisplayX(523);
    item012.SetDisplayY(723);
    item012.SetWindowX(323);
    item012.SetWindowY(453);
    item012.SetWidth(0);
    item012.SetHeight(0);
    item012.SetTiltX(2.12);
    item012.SetTiltY(5.43);
    item012.SetPressure(0.15);
    item012.SetDeviceId(1);
    pointerEventForTest012->AddPointerItem(item012);

    item012.SetPointerId(1);
    item012.SetDownTime(0);
    item012.SetDisplayX(50);
    item012.SetDisplayY(50);
    item012.SetWindowX(70);
    item012.SetWindowY(70);
    item012.SetWidth(0);
    item012.SetHeight(0);
    item012.SetTiltX(12.22);
    item012.SetTiltY(15.33);
    item012.SetPressure(0.45);
    item012.SetDeviceId(1);
    pointerEventForTest012->AddPointerItem(item012);
    return pointerEventForTest012;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent013()
{
    auto pointerEventForTest013 = PointerEvent::Create();
    CHKPP(pointerEventForTest013);
    pointerEventForTest013->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEventForTest013->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEventForTest013->SetPointerId(1);
    PointerEvent::PointerItem item013;
    item013.SetPointerId(0);
    item013.SetDownTime(0);
    item013.SetDisplayX(523);
    item013.SetDisplayY(723);
    item013.SetWindowX(323);
    item013.SetWindowY(453);
    item013.SetWidth(0);
    item013.SetHeight(0);
    item013.SetTiltX(2.12);
    item013.SetTiltY(5.43);
    item013.SetPressure(0.15);
    item013.SetDeviceId(1);
    pointerEventForTest013->AddPointerItem(item013);

    item013.SetPointerId(1);
    item013.SetDownTime(0);
    item013.SetDisplayX(50);
    item013.SetDisplayY(50);
    item013.SetWindowX(70);
    item013.SetWindowY(70);
    item013.SetWidth(0);
    item013.SetHeight(0);
    item013.SetTiltX(12.22);
    item013.SetTiltY(15.33);
    item013.SetPressure(0.45);
    item013.SetDeviceId(1);
    pointerEventForTest013->AddPointerItem(item013);
    return pointerEventForTest013;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent014()
{
    auto pointerEventForTest014 = PointerEvent::Create();
    CHKPP(pointerEventForTest014);
    pointerEventForTest014->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEventForTest014->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEventForTest014->SetPointerId(0);
    PointerEvent::PointerItem item014;
    item014.SetDownTime(0);
    item014.SetPointerId(0);
    item014.SetPressed(false);

    item014.SetDisplayX(10);
    item014.SetWindowX(10);
    item014.SetDisplayY(10);
    item014.SetWindowY(10);

    item014.SetWidth(0);
    item014.SetPressure(0);
    item014.SetHeight(0);
    item014.SetDeviceId(0);
    pointerEventForTest014->AddPointerItem(item014);
    return pointerEventForTest014;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent015()
{
    auto pointerEventForTest015 = PointerEvent::Create();
    CHKPP(pointerEventForTest015);
    pointerEventForTest015->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEventForTest015->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEventForTest015->SetPointerId(0);
    PointerEvent::PointerItem item015;
    item015.SetPressed(false);
    item015.SetDownTime(0);
    item015.SetPointerId(0);

    item015.SetDisplayX(0);
    item015.SetDisplayY(1259);
    item015.SetWindowX(10);
    item015.SetWindowY(10);

    item015.SetWidth(0);
    item015.SetHeight(0);
    item015.SetPressure(0);
    item015.SetDeviceId(0);
    pointerEventForTest015->AddPointerItem(item015);
    return pointerEventForTest015;
}

#ifdef OHOS_BUILD_ENABLE_JOYSTICK
std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent016()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    return pointerEvent;
}
#endif // OHOS_BUILD_ENABLE_JOYSTICK

std::shared_ptr<KeyEvent> InputManagerTest::SetupKeyEvent001()
{
    std::shared_ptr<KeyEvent> keyEventForTest001 = KeyEvent::Create();
    CHKPP(keyEventForTest001);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown001;
    kitDown001.SetPressed(true);
    kitDown001.SetDownTime(downTime);
    kitDown001.SetKeyCode(KeyEvent::KEYCODE_BACK);
    keyEventForTest001->AddPressedKeyItems(kitDown001);
    keyEventForTest001->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEventForTest001->SetKeyCode(KeyEvent::KEYCODE_BACK);

    return keyEventForTest001;
}

std::shared_ptr<KeyEvent> InputManagerTest::SetupKeyEvent002()
{
    std::shared_ptr<KeyEvent> keyEventForTest002 = KeyEvent::Create();
    CHKPP(keyEventForTest002);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown002;
    kitDown002.SetKeyCode(KeyEvent::KEYCODE_BACK);
    kitDown002.SetPressed(true);
    kitDown002.SetDownTime(downTime);
    keyEventForTest002->SetKeyCode(KeyEvent::KEYCODE_BACK);
    keyEventForTest002->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEventForTest002->AddPressedKeyItems(kitDown002);

    return keyEventForTest002;
}

std::shared_ptr<KeyEvent> InputManagerTest::SetupKeyEvent003()
{
    std::shared_ptr<KeyEvent> keyEventForTest003 = KeyEvent::Create();
    CHKPP(keyEventForTest003);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown003;
    kitDown003.SetKeyCode(KeyEvent::KEYCODE_HOME);
    kitDown003.SetPressed(true);
    kitDown003.SetDownTime(downTime);
    keyEventForTest003->SetKeyCode(KeyEvent::KEYCODE_HOME);
    keyEventForTest003->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEventForTest003->AddPressedKeyItems(kitDown003);

    return keyEventForTest003;
}

std::shared_ptr<PointerEvent> InputManagerTest::TestMarkConsumedStep1()
{
    auto pointerEventForStep1 = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEventForStep1::PointerItem itemStep1;
    itemStep1.SetPointerId(0);   // test code，set the PointerId = 0
    itemStep1.SetDisplayX(523);   // test code，set the DisplayX = 523
    itemStep1.SetDisplayY(723);   // test code，set the DisplayY = 723
    itemStep1.SetPressure(5);    // test code，set the Pressure = 5
    itemStep1.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEventForStep1->AddPointerItem(itemStep1);

    pointerEventForStep1->SetId(std::numeric_limits<int32_t>::max() - INDEX_THIRD);
    pointerEventForStep1->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEventForStep1->SetPointerId(0);  // test code，set the PointerId = 1
    pointerEventForStep1->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEventForStep1);
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    return pointerEventForStep1;
}

std::shared_ptr<PointerEvent> InputManagerTest::TestMarkConsumedStep2()
{
    auto pointerEventStep2 = PointerEvent::Create();
    CHKPP(pointerEventStep2);
    PointerEvent::PointerItem itemStep2;
    itemStep2.SetPointerId(0);   // test code，set the PointerId = 0
    itemStep2.SetDisplayX(623);  // test code，set the DisplayX = 623
    itemStep2.SetDisplayY(723);   // test code，set the DisplayY = 723
    itemStep2.SetPressure(5);    // test code，set the Pressure = 5
    itemStep2.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEventStep2->AddPointerItem(itemStep2);

    pointerEventStep2->SetId(std::numeric_limits<int32_t>::max() - INDEX_SECOND);
    pointerEventStep2->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEventStep2->SetPointerId(0);  // test code，set the PointerId = 1
    pointerEventStep2->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEventStep2);
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    return pointerEventStep2;
}

void InputManagerTest::TestMarkConsumedStep3(int32_t monitorId, int32_t eventId)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_MARK_CONSUMED);
    TestMarkConsumed(monitorId, eventId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

void InputManagerTest::TestMarkConsumedStep4()
{
    auto pointerEventStep4 = PointerEvent::Create();
    CHKPV(pointerEventStep4);
    PointerEvent::PointerItem itemStep4;
    itemStep4.SetDisplayX(523);  // test code，set the DisplayX = 523
    itemStep4.SetPointerId(0);   // test code，set the PointerId = 0
    itemStep4.SetDeviceId(1);    // test code，set the DeviceId = 1
    itemStep4.SetPressure(5);    // test code，set the Pressure = 5
    itemStep4.SetDisplayY(723);   // test code，set the DisplayY = 723
    pointerEventStep4->AddPointerItem(itemStep4);

    pointerEventStep4->SetId(std::numeric_limits<int32_t>::max() - INDEX_FIRST);
    pointerEventStep4->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEventStep4->SetPointerId(0);  // test code，set the PointerId = 1
    pointerEventStep4->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEventStep4, TestScene::EXCEPTION_TEST);
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

void InputManagerTest::TestMarkConsumedStep5()
{
    auto pointerEventStep5 = PointerEvent::Create();
    CHKPV(pointerEventStep5);
    PointerEvent::PointerItem itemStep5;
    itemStep5.SetPointerId(0);   // test code，set the PointerId = 0
    itemStep5.SetDisplayX(523);  // test code，set the DisplayX = 523
    itemStep5.SetDisplayY(723);   // test code，set the DisplayY = 723
    itemStep5.SetPressure(5);    // test code，set the Pressure = 5
    itemStep5.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEventStep5->AddPointerItem(itemStep5);

    pointerEventStep5->SetId(std::numeric_limits<int32_t>::max());
    pointerEventStep5->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEventStep5->SetPointerId(0);  // test code，set the PointerId = 0
    pointerEventStep5->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEventStep5, TestScene::EXCEPTION_TEST);
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

void InputManagerTest::TestMarkConsumedStep6()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    auto pointerEventStep6 = PointerEvent::Create();
    CHKPV(pointerEventStep6);
    PointerEvent::PointerItem itemStep6;
    itemStep6.SetPointerId(0);   // test code，set the PointerId = 0
    itemStep6.SetDisplayY(723);   // test code，set the DisplayY = 723
    itemStep6.SetDeviceId(1);    // test code，set the DeviceId = 1
    itemStep6.SetDisplayX(523);   // test code，set the DisplayX = 523
    itemStep6.SetPressure(5);    // test code，set the Pressure = 5
    pointerEventStep6->AddPointerItem(itemStep6);

    pointerEventStep6->SetId(std::numeric_limits<int32_t>::max());
    pointerEventStep6->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEventStep6->SetPointerId(0);  // test code，set the PointerId = 0
    pointerEventStep6->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    TestUtil->SetRecvFlag(RECV_FLAG::RECV_FOCUS);
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEventStep6);
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupmouseEvent001()
{
    auto pointerEventForTest001 = PointerEvent::Create();
    CHKPP(pointerEventForTest001);
    pointerEventForTest001->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEventForTest001->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEventForTest001->SetPointerId(0);
    PointerEvent::PointerItem item001;
    item001.SetWidth(0);
    item001.SetPressed(false);
    item001.SetHeight(0);
    item001.SetDeviceId(0);
    item001.SetWindowX(10);
    item001.SetPointerId(0);
    item001.SetDownTime(0);
    item001.SetDisplayX(10);
    item001.SetDisplayY(10);
    item001.SetPressure(0);
    item001.SetWindowY(10);

    
    pointerEventForTest001->AddPointerItem(item001);
    return pointerEventForTest001;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupmouseEvent002()
{
    auto pointerEventForTest002 = PointerEvent::Create();
    CHKPP(pointerEventForTest002);
    pointerEventForTest002->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEventForTest002->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEventForTest002->SetPointerId(0);
    PointerEvent::PointerItem item002;
    
    item002.SetDownTime(0);
    item002.SetPressure(0);
    item002.SetPointerId(0);
    item002.SetPressed(false);
    item002.SetWindowX(70);
    item002.SetHeight(0);
    item002.SetWindowY(70);
    item002.SetDisplayX(50);
    item002.SetDisplayY(50);
    item002.SetDeviceId(0);
    item002.SetWidth(0);
    
    
    pointerEventForTest002->AddPointerItem(item002);
    return pointerEventForTest002;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupTouchScreenEvent001()
{
    auto pointerEvent001 = PointerEvent::Create();
    CHKPP(pointerEvent001);
    PointerEvent::PointerItem item;
    item.SetDisplayY(10);
    item.SetPointerId(0);
    item.SetDeviceId(1);
    item.SetDisplayX(10);
    item.SetPressure(5);
    
    pointerEvent001->SetPointerId(0);
    pointerEvent001->AddPointerItem(item);
    pointerEvent001->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent001->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent001;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupTouchScreenEvent002()
{
    auto pointerEvent002 = PointerEvent::Create();
    CHKPP(pointerEvent002);
    PointerEvent::PointerItem item;
    item.SetDisplayY(50);
    item.SetPointerId(0);
    item.SetDeviceId(1);
    item.SetDisplayX(50);
    item.SetPressure(5);
    
    pointerEvent002->AddPointerItem(item);
    pointerEvent002->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent002->SetPointerId(0);
    pointerEvent002->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent002;
}

int32_t InputManagerTest::TestAddMonitor(std::shared_ptr<IInputEventConsumer> consumer)
{
    AccessMonitor monitor;
    return InputManager::GetInstance()->AddMonitor(consumer);
}

void InputManagerTest::TestRemoveMonitor(int32_t monitorId)
{
    AccessMonitor monitor;
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

void InputManagerTest::TestMarkConsumed(int32_t monitorId, int32_t eventId)
{
    AccessMonitor monitor;
    InputManager::GetInstance()->MarkConsumed(monitorId, eventId);
}

/**
 * @tc.name: InputManagerTest_AddMonitor_001
 * @tc.desc: Verify pointerevent monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddMonitor_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto PointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGD("Add monitor success");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(PointerEventFun);
#if (defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)) && defined(OHOS_BUILD_ENABLE_MONITOR)
    ASSERT_NE(monitorId, INVALID_HANDLER_ID);
#else
    ASSERT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR ||  OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
}

/**
 * @tc.name: InputManagerTest_AddMonitor_002
 * @tc.desc: Verify keyevent monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddMonitor_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto keyEventFun = [](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGD("Add monitor success");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_MONITOR)
    ASSERT_NE(monitorId, INVALID_HANDLER_ID);
#else
    ASSERT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_KEYBOARD || OHOS_BUILD_ENABLE_MONITOR
}

/**
 * @tc.name: MultimodalEventHandler_SimulateKeyEvent_001
 * @tc.desc: Verify simulate the back key is long pressed and lifted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SimulateKeyEvent_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    KeyEvent::KeyItem kitDown;
    kitDown.SetPressed(true);
    kitDown.SetKeyCode(KeyEvent::KEYCODE_BACK);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    injectDownEvent->AddPressedKeyItems(kitDown);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    TestSimulateInputEvent(injectDownEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD

    std::shared_ptr<KeyEvent> injectUpEvent = KeyEvent::Create();
    ASSERT_TRUE(injectUpEvent != nullptr);
    downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitUp;
    kitUp.SetPressed(false);
    kitUp.SetKeyCode(KeyEvent::KEYCODE_BACK);
    kitUp.SetDownTime(downTime);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
    injectUpEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    injectUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    TestSimulateInputEvent(injectUpEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

/**
 * @tc.name: MultimodalEventHandler_SimulateKeyEvent_002
 * @tc.desc: Verify simulate the back home is pressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SimulateKeyEvent_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = -1;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_HOME);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    TestSimulateInputEvent(injectDownEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

/**
 * @tc.name: MultimodalEventHandler_SimulateKeyEvent_003
 * @tc.desc: Verify simulate the back key is pressed and lifted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SimulateKeyEvent_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = 0;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_BACK);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    TestSimulateInputEvent(injectDownEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD

    std::shared_ptr<KeyEvent> injectUpEvent = KeyEvent::Create();
    ASSERT_TRUE(injectUpEvent != nullptr);
    KeyEvent::KeyItem kitUp;
    kitUp.SetKeyCode(KeyEvent::KEYCODE_BACK);
    kitUp.SetPressed(false);
    kitUp.SetDownTime(downTime);
    injectUpEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    injectUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    TestSimulateInputEvent(injectUpEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

/**
 * @tc.name: MultimodalEventHandler_SimulateKeyEvent_004
 * @tc.desc: Verify simulate key exception event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SimulateKeyEvent_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    TestSimulateInputEvent(injectDownEvent, TestScene::EXCEPTION_TEST);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

/**
 * @tc.name: MultimodalEventHandler_SimulateKeyEvent_005
 * @tc.desc: Verify simulate the fn key is long pressed and lifted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SimulateKeyEvent_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_FN);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_FN);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    TestSimulateInputEvent(injectDownEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD

    std::shared_ptr<KeyEvent> injectUpEvent = KeyEvent::Create();
    ASSERT_TRUE(injectUpEvent != nullptr);
    downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitUp;
    kitUp.SetKeyCode(KeyEvent::KEYCODE_FN);
    kitUp.SetPressed(false);
    kitUp.SetDownTime(downTime);
    injectUpEvent->SetKeyCode(KeyEvent::KEYCODE_FN);
    injectUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    TestSimulateInputEvent(injectUpEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_001
 * @tc.desc: Verify simulate screen down event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SimulatePointerEvent_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent001() };
    ASSERT_TRUE(pointerEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_TOUCH
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_002
 * @tc.desc: Verify simulate screen move event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SimulatePointerEvent_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent002() };
    ASSERT_TRUE(pointerEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_TOUCH
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_003
 * @tc.desc: Verify simulate screen up event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePointerEvent_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent003() };
    ASSERT_TRUE(pointerEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_TOUCH
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_004
 * @tc.desc: Verify simulate screen exception event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePointerEvent_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(-1);
#ifdef OHOS_BUILD_ENABLE_TOUCH
    TestSimulateInputEvent(pointerEvent, TestScene::EXCEPTION_TEST);
#endif // OHOS_BUILD_ENABLE_TOUCH
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_005
 * @tc.desc: Verify simulate mouse down event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePointerEvent_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent005() };
    ASSERT_TRUE(pointerEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_POINTER
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_006
 * @tc.desc: Verify simulate mouse move event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePointerEvent_006, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent006() };
    ASSERT_TRUE(pointerEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_POINTER
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_007
 * @tc.desc: Verify simulate mouse up event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePointerEvent_007, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent007() };
    ASSERT_TRUE(pointerEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_POINTER
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_008
 * @tc.desc: Verify simulate mouse exception event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePointerEvent_008, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(-1);
#ifdef OHOS_BUILD_ENABLE_POINTER
    TestSimulateInputEvent(pointerEvent, TestScene::EXCEPTION_TEST);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_009
 * @tc.desc: Verify simulate mouse VERTICAL axis event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePointerEvent_009, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent009() };
    ASSERT_TRUE(pointerEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_POINTER
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_010
 * @tc.desc: Verify simulate mouse VERTICAL HORIZONTAL axis event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePointerEvent_010, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent010() };
    ASSERT_TRUE(pointerEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_POINTER
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_011
 * @tc.desc: Verify simulate mouse AXIS_BEGIN event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePointerEvent_011, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 30.0);
    PointerEvent::PointerItem item011;
    item011.SetPointerId(1);
    item011.SetDownTime(0);
    item011.SetPressed(false);

    item011.SetDisplayX(200);
    item011.SetDisplayY(200);
    item011.SetWindowY(300);
    item011.SetWindowX(300);
    
    item011.SetDeviceId(0);
    item011.SetWidth(0);
    item011.SetHeight(0);
    item011.SetPressure(0);
    
    pointerEvent->AddPointerItem(item011);

#ifdef OHOS_BUILD_ENABLE_POINTER
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_012
 * @tc.desc: Verify simulate mouse AXIS_UPDATE event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePointerEvent_012, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEventForTest012 = PointerEvent::Create();
    ASSERT_TRUE(pointerEventForTest012 != nullptr);
    pointerEventForTest012->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEventForTest012->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEventForTest012->SetPointerId(1);
    pointerEventForTest012->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 30.0);
    PointerEvent::PointerItem item012;
    item012.SetPointerId(1);
    item012.SetDownTime(0);
    item012.SetPressed(false);

    item012.SetDisplayX(200);
    item012.SetDisplayY(200);
    item012.SetWindowX(300);
    item012.SetWindowY(300);

    item012.SetWidth(0);
    item012.SetHeight(0);
    item012.SetPressure(0);
    item012.SetDeviceId(0);
    pointerEventForTest012->AddPointerItem(item012);

#ifdef OHOS_BUILD_ENABLE_POINTER
    TestSimulateInputEvent(pointerEventForTest012);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_013
 * @tc.desc: Verify simulate mouse AXIS_END event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePointerEvent_013, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEventForTest013 = PointerEvent::Create();
    ASSERT_TRUE(pointerEventForTest013 != nullptr);
    pointerEventForTest013->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEventForTest013->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    pointerEventForTest013->SetPointerId(1);
    pointerEventForTest013->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 30.0);
    PointerEvent::PointerItem item013;
    item013.SetPointerId(1);
    item013.SetDownTime(0);
    item013.SetPressed(false);

    item013.SetDisplayX(200);
    item013.SetDisplayY(200);
    item013.SetWindowX(300);
    item013.SetWindowY(300);

    item013.SetWidth(0);
    item013.SetHeight(0);
    item013.SetPressure(0);
    item013.SetDeviceId(0);
    pointerEventForTest013->AddPointerItem(item013);

#ifdef OHOS_BUILD_ENABLE_POINTER
    TestSimulateInputEvent(pointerEventForTest013);
#endif // OHOS_BUILD_ENABLE_POINTER
}

#ifdef OHOS_BUILD_ENABLE_JOYSTICK
/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_014
 * @tc.desc: Dispatch joystick event dispatch to focus window
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePointerEvent_014, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent016() };
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_JOYSTICK

/**
 * @tc.name: InputManagerTest_MouseEventEnterAndLeave_001
 * @tc.desc: Verify that the mouse moves away from the window
 * @tc.type: FUNC
 * @tc.require: I5HMF3 I5HMEF
 */
HWTEST_F(InputManagerTest, InputManagerTest_MouseEventEnterAndLeave_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent014() };
    ASSERT_TRUE(pointerEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_POINTER
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: InputManagerTest_MouseEventEnterAndLeave_002
 * @tc.desc: Verify return mouse away from the window
 * @tc.type: FUNC
 * @tc.require: I5HMF3 I5HMEF
 */
HWTEST_F(InputManagerTest, InputManagerTest_MouseEventEnterAndLeave_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEvent> keyEvent { SetupKeyEvent002() };
    ASSERT_TRUE(keyEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    TestSimulateInputEvent(keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

/**
 * @tc.name: InputManagerTest_MouseEventEnterAndLeave_003
 * @tc.desc: Verify that the home button and mouse leave the window
 * @tc.type: FUNC
 * @tc.require: I5HMF3 I5HMEF
 */
HWTEST_F(InputManagerTest, InputManagerTest_MouseEventEnterAndLeave_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEvent> keyEvent { SetupKeyEvent003() };
    ASSERT_TRUE(keyEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    TestSimulateInputEvent(keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

/**
 * @tc.name: InputManagerTest_MouseEventEnterAndLeave_004
 * @tc.desc: Verify that the mouse moves to the navigation bar to leave the window
 * @tc.type: FUNC
 * @tc.require: I5HMF3 I5HMEF
 */
HWTEST_F(InputManagerTest, InputManagerTest_MouseEventEnterAndLeave_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent015() };
    ASSERT_TRUE(pointerEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_POINTER
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePencil2Event_001
 * @tc.desc: Verify simulate pencil2 down event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePencil2Event_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent011() };
    ASSERT_TRUE(pointerEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_TOUCH
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePencil2Event_002
 * @tc.desc: Verify simulate pencil2 move event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePencil2Event_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent012() };
    ASSERT_TRUE(pointerEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_TOUCH
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePencil2Event_003
 * @tc.desc: Verify simulate pencil2 up event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_SimulatePencil2Event_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent013() };
    ASSERT_TRUE(pointerEvent != nullptr);
#ifdef OHOS_BUILD_ENABLE_TOUCH
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
}

/**
 * @tc.name: InputManager_Pencil2InputEvent_004
 * @tc.desc: Verify simulate exception event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_Pencil2InputEvent_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(-1);
#ifdef OHOS_BUILD_ENABLE_TOUCH
    TestSimulateInputEvent(pointerEvent, TestScene::EXCEPTION_TEST);
#endif // OHOS_BUILD_ENABLE_TOUCH
}

/**
 * @tc.name: InputManager_NotResponse_001
 * @tc.desc: detection of not response
 * @tc.type: FUNC
 * @tc.require:AR000GJG6G
 */
HWTEST_F(InputManagerTest, InputManager_NotResponse_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetPressure(5);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}

/**
 * @tc.name: InputManager_NotResponse_002
 * @tc.desc: detection of not response
 * @tc.type: FUNC
 * @tc.require:SR000GGN6G
 */
HWTEST_F(InputManagerTest, InputManager_NotResponse_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPressure(5);
    item.SetPointerId(0);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}

/**
 * @tc.name: InputManagerTest_SubscribeKeyEvent_001
 * @tc.desc: Verify invalid parameter.
 * @tc.type: FUNC
 * @tc.require:SR000GGQL4  AR000GJNGN
 * @tc.author: yangguang
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::set<int32_t> preKeys;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(KeyEvent::KEYCODE_VOLUME_MUTE);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(0);
    int32_t response = -1;
    response = InputManager::GetInstance()->SubscribeKeyEvent(keyOption, nullptr);
    EXPECT_TRUE(response < 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->UnsubscribeKeyEvent(response);
}

/**
 * @tc.name: InputManagerTest_SubscribeKeyEvent_02
 * @tc.desc: Verify subscribe power key event.
 * @tc.type: FUNC
 * @tc.require:SR000GGQL4  AR000GJNGN
 * @tc.author: zhaoxueyuan
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_02, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    ASSERT_TRUE(MMIEventHdl.InitClient());
    // 电源键长按按下订阅
    std::set<int32_t> preKeys;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(KeyEvent::KEYCODE_POWER);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(2000);
    int32_t subscribeId1 = -1;
    subscribeId1 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption,
        [](std::shared_ptr<KeyEvent> keyEvent) {
        EventLogHelper::PrintEventData(keyEvent);
        MMI_HILOGD("Subscribe key event KEYCODE_POWER down trigger callback");
    });
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    EXPECT_TRUE(subscribeId1 >= 0);
#else
    EXPECT_TRUE(subscribeId1 < 0);
#endif // OHOS_BUILD_ENABLE_KEYBOARD

    // 电源键抬起订阅
    std::shared_ptr<KeyOption> keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetPreKeys(preKeys);
    keyOption2->SetFinalKey(KeyEvent::KEYCODE_POWER);
    keyOption2->SetFinalKeyDown(false);
    keyOption2->SetFinalKeyDownDuration(0);
    int32_t subscribeId2 = -1;
    subscribeId2 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption2,
        [](std::shared_ptr<KeyEvent> keyEvent) {
        EventLogHelper::PrintEventData(keyEvent);
        MMI_HILOGD("Subscribe key event KEYCODE_POWER up trigger callback");
    });
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    EXPECT_TRUE(subscribeId2 >= 0);
#else
    EXPECT_TRUE(subscribeId2 < 0);
#endif // OHOS_BUILD_ENABLE_KEYBOARD

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId1);
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId2);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

/**
 * @tc.name: InputManagerTest_SubscribeKeyEvent_03
 * @tc.desc: Verify subscribe volume up key event.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_03, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    ASSERT_TRUE(MMIEventHdl.InitClient());
    std::set<int32_t> preKeys;
    std::shared_ptr<KeyOption> keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPreKeys(preKeys);
    keyOption1->SetFinalKey(KeyEvent::KEYCODE_VOLUME_UP);
    keyOption1->SetFinalKeyDown(true);
    keyOption1->SetFinalKeyDownDuration(10);
    int32_t subscribeId1 = -1;
    subscribeId1 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption1,
        [](std::shared_ptr<KeyEvent> keyEvent) {
        EventLogHelper::PrintEventData(keyEvent);
        MMI_HILOGD("Subscribe key event KEYCODE_VOLUME_UP down trigger callback");
    });
    std::shared_ptr<KeyOption> keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetPreKeys(preKeys);
    keyOption2->SetFinalKey(KeyEvent::KEYCODE_VOLUME_UP);
    keyOption2->SetFinalKeyDown(false);
    keyOption2->SetFinalKeyDownDuration(0);
    int32_t subscribeId2 = -1;
    subscribeId2 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption2,
        [](std::shared_ptr<KeyEvent> keyEvent) {
        EventLogHelper::PrintEventData(keyEvent);
        MMI_HILOGD("Subscribe key event KEYCODE_VOLUME_UP up trigger callback");
    });
    std::shared_ptr<KeyOption> keyOption3 = std::make_shared<KeyOption>();
    keyOption3->SetPreKeys(preKeys);
    keyOption3->SetFinalKey(KeyEvent::KEYCODE_VOLUME_UP);
    keyOption3->SetFinalKeyDown(true);
    keyOption3->SetFinalKeyDownDuration(0);
    int32_t subscribeId3 = -1;
    subscribeId3 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption3,
        [](std::shared_ptr<KeyEvent> keyEvent) {
        EventLogHelper::PrintEventData(keyEvent);
        MMI_HILOGD("Subscribe key event KEYCODE_VOLUME_UP down trigger callback");
    });
    std::shared_ptr<KeyOption> keyOption4 = std::make_shared<KeyOption>();
    keyOption4->SetPreKeys(preKeys);
    keyOption4->SetFinalKey(KeyEvent::KEYCODE_VOLUME_UP);
    keyOption4->SetFinalKeyDown(false);
    keyOption4->SetFinalKeyDownDuration(0);
    int32_t subscribeId4 = -1;
    subscribeId4 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption4,
        [](std::shared_ptr<KeyEvent> keyEvent) {
        EventLogHelper::PrintEventData(keyEvent);
        MMI_HILOGD("Subscribe key event KEYCODE_VOLUME_UP up trigger callback");
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId1);
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId2);
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId3);
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId4);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

/**
 * @tc.name: TestGetKeystrokeAbility_001
 * @tc.desc: Verify SupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestGetKeystrokeAbility_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::vector<int32_t> keyCodes = {17, 22, 2055};
    InputManager::GetInstance()->SupportKeys(0, keyCodes, [](std::vector<bool> keystrokeAbility) {
        MMI_HILOGD("TestGetKeystrokeAbility_001 callback ok");
    });
    MMI_HILOGD("Stop TestGetKeystrokeAbility_001");
}

/**
 * @tc.name: TestInputEventInterceptor_001
 * @tc.desc: Verify mouse down event interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetDownTime(10010);
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetPressed(true);
    pointerEvent->AddPointerItem(item);
    item.SetDisplayY(723);
    item.SetDisplayX(523);
    item.SetDeviceId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_INTERCEPTOR

    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_002
 * @tc.desc: Verify mouse move event interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetDeviceId(1);
    item.SetDownTime(10010);
    pointerEvent->AddPointerItem(item);
    item.SetPressed(true);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_INTERCEPTOR

    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_003
 * @tc.desc: Verify mouse up event interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(10010);
    item.SetPressed(true);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_INTERCEPTOR

    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_004
 * @tc.desc: Verify multiple interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10010);
    item.SetPressed(true);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);

    const std::vector<int32_t>::size_type N_TEST_CASES { 3 };
    std::vector<int32_t> ids(N_TEST_CASES);
    auto interceptor = GetPtr<InputEventCallback>();

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        ids[i] = InputManager::GetInstance()->AddInterceptor(interceptor);
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
#else
        EXPECT_EQ(ids[i], ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    for (const auto &id : ids) {
        std::string sPointerEs = InputManagerTest::GetEventDump();
        MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
        ASSERT_TRUE(!sPointerEs.empty());
#else
        ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_INTERCEPTOR
        if (IsValidHandlerId(id)) {
            InputManager::GetInstance()->RemoveInterceptor(id);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_005
 * @tc.desc: Verify mouse button interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    PointerEvent::PointerItem item;
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    item.SetPressed(true);
    item.SetDisplayX(200);
    item.SetDisplayY(300);
    pointerEvent->AddPointerItem(item);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_INTERCEPTOR

    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_006
 * @tc.desc: Verify touchscreen interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_006, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetDisplayX(523);   // test code，set the DisplayX = 523
    item.SetDisplayY(723);   // test code，set the DisplayY = 723
    item.SetPressure(5);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);
    item.SetPointerId(1);   // test code，set the PointerId = 1
    item.SetDisplayX(710);   // test code，set the DisplayX = 710
    item.SetDisplayY(910);   // test code，set the DisplayY = 910
    item.SetPressure(7);    // test code，set the Pressure = 7
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(1);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_INTERCEPTOR

    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_007
 * @tc.desc: Verify key interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_007, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_BACK);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    TestSimulateInputEvent(injectDownEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD

    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_008
 * @tc.desc: Verify touchscreen interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_008, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10010);
    item.SetPressed(true);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId = InputManager::GetInstance()->AddInterceptor(interceptor);
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::string sPointerEs = InputManagerTest::GetEventDump();
    MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    ASSERT_TRUE(!sPointerEs.empty());
#else
    ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_INTERCEPTOR
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_009
 * @tc.desc: Verify mouse interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_009, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10010);
    item.SetPressed(true);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId = InputManager::GetInstance()->AddInterceptor(interceptor);
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::string sPointerEs = InputManagerTest::GetEventDump();
    MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    ASSERT_TRUE(!sPointerEs.empty());
#else
    ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_INTERCEPTOR
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_010
 * @tc.desc: Verify volume key interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_010, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);

    std::string sPointerEs = InputManagerTest::GetEventDump();
    MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    ASSERT_TRUE(!sPointerEs.empty());
#else
    ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_INTERCEPTOR
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_011
 * @tc.desc: Verify space key interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_011, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_SPACE);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_SPACE);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);

    std::string sPointerEs = InputManagerTest::GetEventDump();
    MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    ASSERT_TRUE(!sPointerEs.empty());
#else
    ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_INTERCEPTOR
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_012
 * @tc.desc: Verify keyevent interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_012, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto fun = [](std::shared_ptr<KeyEvent> keyEvent) {
        MMI_HILOGD("Add interceptor success");
    };
    int32_t interceptorId = InputManager::GetInstance()->AddInterceptor(fun);
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    ASSERT_NE(interceptorId, INVALID_HANDLER_ID);
#else
    ASSERT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_INTERCEPTOR
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
    }
}

/**
 * @tc.name: InputManagerTest_OnAddScreenMonitor_001
 * @tc.desc: Verify touchscreen down event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddScreenMonitor_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = SetupPointerEvent001();
    ASSERT_TRUE(pointerEvent != nullptr);

    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerTest_OnAddScreenMonitor_002
 * @tc.desc: Verify touchscreen move event multiple monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddScreenMonitor_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_MONITOR);
    const std::vector<int32_t>::size_type N_TEST_CASES { 3 };
    std::vector<int32_t> ids(N_TEST_CASES);
    std::vector<std::shared_ptr<InputEventCallback>> cbs(N_TEST_CASES);

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        cbs[i] = GetPtr<InputEventCallback>();
        ASSERT_TRUE(cbs[i] != nullptr);
        ids[i] = TestAddMonitor(cbs[i]);
#ifdef OHOS_BUILD_ENABLE_MONITOR
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
#else
        EXPECT_EQ(ids[i], ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    auto pointerEvent = SetupPointerEvent002();
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    for (const auto &id : ids) {
        std::string sPointerEs = InputManagerTest::GetEventDump();
        MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
        ASSERT_TRUE(!sPointerEs.empty());
#else
        ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
        if (IsValidHandlerId(id)) {
            TestRemoveMonitor(id);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerTest_OnAddScreenMonitor_003
 * @tc.desc: Verify touchscreen up event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddScreenMonitor_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = SetupPointerEvent003();
    ASSERT_TRUE(pointerEvent != nullptr);

    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerTest_OnAddScreenMonitor_004
 * @tc.desc: Verify touchscreen MarkConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddScreenMonitor_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    TestMarkConsumedStep1();
    auto pointerEvent = TestMarkConsumedStep2();

    TestMarkConsumedStep3(monitorId, callbackPtr->GetLastEventId());

    TestMarkConsumedStep4();
    TestMarkConsumedStep5();

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerTest_OnAddScreenMonitor_005
 * @tc.desc:  Verify touchscreen MarkConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddScreenMonitor_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    auto pointerEvent = TestMarkConsumedStep1();

    TestMarkConsumedStep3(monitorId, callbackPtr->GetLastEventId());

    TestMarkConsumedStep4();
    TestMarkConsumedStep6();

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerTest_OnAddTouchPadMonitor_001
 * @tc.desc: Verify touchpad down event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10010);
    item.SetPressed(true);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerTest_OnAddTouchPadMonitor_002
 * @tc.desc: Verify touchpad move event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10010);
    item.SetPressed(true);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerTest_OnAddTouchPadMonitor_003
 * @tc.desc: Verify touchpad up event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetDownTime(10010);
    item.SetPointerId(0);
    item.SetPressed(true);
    item.SetDisplayY(723);
    item.SetDisplayX(523);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerTest_OnAddTouchPadMonitor_004
 * @tc.desc: Verify touchpad multiple monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_MONITOR);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPressed(true);
    item.SetPointerId(0);
    item.SetDownTime(10010);
    item.SetDisplayX(523);
    item.SetDeviceId(1);
    item.SetDisplayY(723);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    const std::vector<int32_t>::size_type N_TEST_CASES { 3 };
    std::vector<int32_t> ids(N_TEST_CASES);
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        ids[i] = TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
#else
        EXPECT_EQ(ids[i], ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    for (const auto &id : ids) {
        std::string sPointerEs = InputManagerTest::GetEventDump();
        MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
        ASSERT_TRUE(!sPointerEs.empty());
#else
        ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR
        if (IsValidHandlerId(id)) {
            TestRemoveMonitor(id);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerTest_OnAddTouchPadMonitor_005
 * @tc.desc: Verify touchpad monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDeviceId(1);
    item.SetDownTime(10010);
    item.SetPressed(true);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);

    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManager_TouchPadSimulateInputEvent_001
 * @tc.desc: Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId { TestAddMonitor(callbackPtr) };
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t actionTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item {};
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetActionTime(actionTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManager_TouchPadSimulateInputEvent_002
 * @tc.desc: Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId { TestAddMonitor(callbackPtr) };
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t actionTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item {};
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetDisplayX(700);
    item.SetDisplayY(610);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetActionTime(actionTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManager_TouchPadSimulateInputEvent_003
 * @tc.desc: Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId { TestAddMonitor(callbackPtr) };
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t actionTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item {};
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(actionTime);
    item.SetPressed(false);
    item.SetDisplayX(50);
    item.SetDisplayY(50);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetActionTime(actionTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManager_TouchPadSimulateInputEvent_004
 * @tc.desc: Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId { TestAddMonitor(callbackPtr) };
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t actionTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item {};
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    item.SetPointerId(1);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetDisplayX(540);
    item.SetDisplayY(740);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    item.SetPointerId(2);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetDisplayX(560);
    item.SetDisplayY(760);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetActionTime(actionTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerTest_AddMouseMonitor_001
 * @tc.desc: Verify mouse down event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    auto pointerEvent = SetupPointerEvent005();
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerTest_AddMouseMonitor_002
 * @tc.desc: Verify mouse move event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    auto pointerEvent = SetupPointerEvent006();
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent, TestScene::EXCEPTION_TEST);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR
}

/**
 * @tc.name: InputManagerTest_AddMouseMonitor_003
 * @tc.desc: Verify mouse up event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    auto pointerEvent = SetupPointerEvent007();
    ASSERT_TRUE(pointerEvent != nullptr);
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerTest_AddMouseMonitor_004
 * @tc.desc: Verify monitor upper limit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_MONITOR);
    const std::vector<int32_t>::size_type N_TEST_CASES { MAX_N_INPUT_HANDLERS - 1 };
    std::vector<int32_t> ids;
    int32_t maxMonitor = 0;

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        auto callbackPtr = GetPtr<InputEventCallback>();
        ASSERT_TRUE(callbackPtr != nullptr);
        maxMonitor = TestAddMonitor(callbackPtr);
        if (IsValidHandlerId(maxMonitor)) {
            ids.push_back(maxMonitor);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }

    auto pointerEvent = SetupPointerEvent007();
    ASSERT_TRUE(pointerEvent != nullptr);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    maxMonitor = 0;
    for (const auto &id : ids) {
        if (!InputManagerTest::GetEventDump().empty()) {
            maxMonitor++;
        }
        if (IsValidHandlerId(id)) {
            TestRemoveMonitor(id);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    ASSERT_EQ(maxMonitor, ids.size());
#else
    ASSERT_EQ(maxMonitor, 0);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR
}

/**
 * @tc.name: InputManagerTest_OnAddKeyboardMonitor_001
 * @tc.desc: Verify Keyboard multiple monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddKeyboardMonitor_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_MONITOR);
    const std::vector<int32_t>::size_type N_TEST_CASES { 3 };
    std::vector<int32_t> ids;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        int32_t id = TestAddMonitor(callbackPtr);
        if (IsValidHandlerId(id)) {
            ids.push_back(id);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }

    auto injectEvent = SetupKeyEvent001();
    ASSERT_TRUE(injectEvent != nullptr);
    InputManager::GetInstance()->SimulateInputEvent(injectEvent);

    for (const auto &id : ids) {
        std::string sPointerEs = InputManagerTest::GetEventDump();
        MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_MONITOR)
        ASSERT_TRUE(!sPointerEs.empty());
#else
        ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_MONITOR
        if (IsValidHandlerId(id)) {
            TestRemoveMonitor(id);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerTest_OnAddKeyboardMonitor_002
 * @tc.desc: Verify Keyboard multiple monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddKeyboardMonitor_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    const std::vector<int32_t>::size_type N_TEST_CASES { 3 };
    std::vector<int32_t> ids;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        int32_t id = TestAddMonitor(callbackPtr);
        if (IsValidHandlerId(id)) {
            ids.push_back(id);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }

    auto injectEvent = SetupKeyEvent001();
    ASSERT_TRUE(injectEvent != nullptr);
    injectEvent->SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    InputManager::GetInstance()->SimulateInputEvent(injectEvent);

    for (const auto &id : ids) {
        std::string sPointerEs = InputManagerTest::GetEventDump();
        MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
        ASSERT_TRUE(sPointerEs.empty());
        if (IsValidHandlerId(id)) {
            TestRemoveMonitor(id);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerTest_RemoteControlAutoRepeat
 * @tc.desc: After the key is pressed, repeatedly trigger the key to press the input
 * @tc.type: FUNC
 * @tc.require: I530XB
 */
HWTEST_F(InputManagerTest, InputManagerTest_RemoteControlAutoRepeat, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_A);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    TestSimulateInputEvent(injectDownEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    std::shared_ptr<KeyEvent> injectUpEvent = KeyEvent::Create();
    ASSERT_TRUE(injectUpEvent != nullptr);
    downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitUp;
    kitUp.SetKeyCode(KeyEvent::KEYCODE_A);
    kitUp.SetPressed(false);
    kitUp.SetDownTime(downTime);
    injectUpEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    injectUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    TestSimulateInputEvent(injectUpEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

/**
 * @tc.name: InputManagerTest_MoveMouse_01
 * @tc.desc: Verify move mouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_MoveMouse_01, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    InputManager::GetInstance()->MoveMouse(50, 50);
}

/**
 * @tc.name: InputManagerTest_MoveMouse_02
 * @tc.desc: Verify move mouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_MoveMouse_02, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    InputManager::GetInstance()->MoveMouse(-1000, 100);
}

static int32_t deviceIDtest = 0;
static void GetKeyboardTypeCallback(int32_t keyboardType)
{
    switch (keyboardType) {
        case KEYBOARD_TYPE_NONE: {
            MMI_HILOGD("deviceIDtest:%{public}d-->KeyboardType:%{public}s", deviceIDtest, "None");
            break;
            }
        case KEYBOARD_TYPE_UNKNOWN: {
            MMI_HILOGD("deviceIDtest:%{public}d-->KeyboardType:%{public}s", deviceIDtest, "unknown");
            break;
        }
        case KEYBOARD_TYPE_ALPHABETICKEYBOARD: {
            MMI_HILOGD("deviceIDtest:%{public}d-->KeyboardType:%{public}s", deviceIDtest, "alphabetickeyboard");
            break;
        }
        case KEYBOARD_TYPE_DIGITALKEYBOARD: {
            MMI_HILOGD("deviceIDtest:%{public}d-->KeyboardType:%{public}s", deviceIDtest, "digitalkeyboard");
            break;
        }
        case KEYBOARD_TYPE_HANDWRITINGPEN: {
            MMI_HILOGD("deviceIDtest:%{public}d-->KeyboardType:%{public}s", deviceIDtest, "handwritingpen");
            break;
        }
        case KEYBOARD_TYPE_REMOTECONTROL: {
            MMI_HILOGD("deviceIDtest:%{public}d-->KeyboardType:%{public}s", deviceIDtest, "remotecontrol");
            break;
        }
        default: {
            MMI_HILOGW("Error obtaining keyboard type");
            break;
        }
    }
}

/**
 * @tc.name: InputManagerTest_GetKeyboardType
 * @tc.desc: Verify Get Keyboard Type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_GetKeyboardType, TestSize.Level1)
{
    MMI_HILOGD("Start InputManagerTest_GetKeyboardType");
    for (int32_t i = 0; i < 20; ++i)
    {
        deviceIDtest = i;
        InputManager::GetInstance()->GetKeyboardType(i, GetKeyboardTypeCallback);
        MMI_HILOGD("i:%{public}d", i);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    MMI_HILOGD("Stop InputManagerTest_GetKeyboardType");
}

HWTEST_F(InputManagerTest, InputManagerTest_GetProcCpuUsage, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SYSTEM_INFO::CpuInfo cpuInfo;
    const std::string process_name = "multimodalinput";
    auto usage = cpuInfo.GetProcCpuUsage(process_name);
    MMI_HILOGD("The CPU usage of the %{public}s process is %{public}.2f", process_name.c_str(), usage);
    ASSERT_TRUE(usage < SYSTEM_INFO::CPU_USAGE_LOAD && usage != SYSTEM_INFO::CPU_USAGE_UNKONW);
}

/**
 * @tc.name: InputManagerTest_SetWindowInputEventConsumer_001
 * @tc.desc: Verify pointerEvent report eventHandler
 * @tc.type: FUNC
 * @tc.require: I5HMDY
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetWindowInputEventConsumer_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto runner = AppExecFwk::EventRunner::Create(true);
    ASSERT_TRUE(runner != nullptr);
    auto eventHandler = std::make_shared<AppExecFwk::EventHandler>(runner);
    ASSERT_TRUE(eventHandler != nullptr);
    uint64_t runnerThreadId = 0;

    auto fun = [&runnerThreadId]() {
        runnerThreadId = GetThisThreadId();
        MMI_HILOGD("Create eventHandler is threadId:%{public}" PRIu64, runnerThreadId);
        ASSERT_TRUE(runnerThreadId != 0);
    };
    eventHandler->PostSyncTask(fun, AppExecFwk::EventHandler::Priority::IMMEDIATE);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    auto consumer = GetPtr<WindowEventConsumer>();
    ASSERT_TRUE(consumer != nullptr);
    MMI::InputManager::GetInstance()->SetWindowInputEventConsumer(consumer, eventHandler);
    auto pointerEvent = SetupPointerEvent005();
    ASSERT_TRUE(pointerEvent != nullptr);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    uint64_t consumerThreadId = consumer->GetConsumerThreadId();
#ifdef OHOS_BUILD_ENABLE_POINTER
    EXPECT_EQ(runnerThreadId, consumerThreadId);
#else
    ASSERT_TRUE(runnerThreadId != consumerThreadId);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: InputManagerTest_SetWindowInputEventConsumer_002
 * @tc.desc: Verify keyEvent report eventHandler
 * @tc.type: FUNC
 * @tc.require: I5HMDY
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetWindowInputEventConsumer_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    const std::string threadTest = "threadNameTest";
    auto runner = AppExecFwk::EventRunner::Create(threadTest);
    ASSERT_TRUE(runner != nullptr);
    auto eventHandler = std::make_shared<AppExecFwk::EventHandler>(runner);
    ASSERT_TRUE(eventHandler != nullptr);
    uint64_t runnerThreadId = 0;

    auto fun = [&runnerThreadId]() {
        runnerThreadId = GetThisThreadId();
        MMI_HILOGD("Create eventHandler is threadId:%{public}" PRIu64, runnerThreadId);
        ASSERT_TRUE(runnerThreadId != 0);
    };
    eventHandler->PostSyncTask(fun, AppExecFwk::EventHandler::Priority::IMMEDIATE);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    auto consumer = GetPtr<WindowEventConsumer>();
    ASSERT_TRUE(consumer != nullptr);
    MMI::InputManager::GetInstance()->SetWindowInputEventConsumer(consumer, eventHandler);
    auto keyEvent = SetupKeyEvent001();
    ASSERT_TRUE(keyEvent != nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    uint64_t consumerThreadId = consumer->GetConsumerThreadId();
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    EXPECT_EQ(runnerThreadId, consumerThreadId);
#else
    ASSERT_TRUE(runnerThreadId != consumerThreadId);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

/**
 * @tc.name: InputManagerTest_SetPointerVisible_001
 * @tc.desc: Sets whether the pointer icon is visible
 * @tc.type: FUNC
 * @tc.require: I530VT
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetPointerVisible_001, TestSize.Level1)
{
    bool isVisible { true };
    if (InputManager::GetInstance()->SetPointerVisible(isVisible) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->IsPointerVisible() == isVisible);
    }
}

/**
 * @tc.name: InputManagerTest_SetPointerVisible_002
 * @tc.desc: Sets whether the pointer icon is visible
 * @tc.type: FUNC
 * @tc.require: I530VT
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetPointerVisible_002, TestSize.Level1)
{
    bool isVisible { false };
    if (InputManager::GetInstance()->SetPointerVisible(isVisible) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->IsPointerVisible() == isVisible);
    }
}

/**
 * @tc.name: InputManagerTest_SetPointSpeed_001
 * @tc.desc: Abnormal speed value processing
 * @tc.type: FUNC
 * @tc.require: I530XP I530UX
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetPointSpeed_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    const int32_t speed = -1;
    InputManager::GetInstance()->SetPointerSpeed(speed);
    int32_t speed1;
    InputManager::GetInstance()->GetPointerSpeed(speed1);
    ASSERT_EQ(speed1, 1);
    InputManager::GetInstance()->MoveMouse(-2000, -2000);
    InputManager::GetInstance()->MoveMouse(50, 50);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(100, 150);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(300, 350);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(400, 450);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(500, 550);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(700, 1000);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name: InputManagerTest_SetPointSpeed_002
 * @tc.desc: Normal speed value processing
 * @tc.type: FUNC
 * @tc.require: I530XP I530UX
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetPointSpeed_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    const int32_t speed = 1;
    InputManager::GetInstance()->SetPointerSpeed(speed);
    int32_t speed1;
    InputManager::GetInstance()->GetPointerSpeed(speed1);
    ASSERT_EQ(speed1, speed);
    InputManager::GetInstance()->MoveMouse(-2000, -2000);
    InputManager::GetInstance()->MoveMouse(50, 50);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(100, 150);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(300, 350);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(400, 450);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(500, 550);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(700, 1000);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name: InputManagerTest_SetPointSpeed_003
 * @tc.desc: Normal speed value processing
 * @tc.type: FUNC
 * @tc.require: I530XP I530UX
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetPointSpeed_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    const int32_t speed = 4;
    InputManager::GetInstance()->SetPointerSpeed(speed);
    int32_t speed1;
    InputManager::GetInstance()->GetPointerSpeed(speed1);
    ASSERT_EQ(speed1, speed);
    InputManager::GetInstance()->MoveMouse(-2000, -2000);
    InputManager::GetInstance()->MoveMouse(50, 50);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(100, 150);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(300, 350);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(400, 450);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(500, 550);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(700, 1000);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name: InputManagerTest_SetPointSpeed_004
 * @tc.desc: Normal speed value processing
 * @tc.type: FUNC
 * @tc.require: I530XP I530UX
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetPointSpeed_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    const int32_t speed = 11;
    InputManager::GetInstance()->SetPointerSpeed(speed);
    int32_t speed1;
    InputManager::GetInstance()->GetPointerSpeed(speed1);
    ASSERT_EQ(speed1, speed);
    InputManager::GetInstance()->MoveMouse(-2000, -2000);
    InputManager::GetInstance()->MoveMouse(50, 50);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(100, 150);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(300, 350);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(400, 450);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(500, 550);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(700, 1000);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name: InputManagerTest_SetPointSpeed_005
 * @tc.desc: Abnormal speed value processing
 * @tc.type: FUNC
 * @tc.require: I530XP I530UX
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetPointSpeed_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    const int32_t speed = 20;
    InputManager::GetInstance()->SetPointerSpeed(speed);
    int32_t speed1;
    InputManager::GetInstance()->GetPointerSpeed(speed1);
    ASSERT_EQ(speed1, 11);
    InputManager::GetInstance()->MoveMouse(-2000, -2000);
    InputManager::GetInstance()->MoveMouse(50, 50);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(100, 150);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(300, 350);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(400, 450);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(500, 550);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(700, 1000);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name: InputManagerTest_SetPointerStyle_001
 * @tc.desc: Sets the pointer style of the window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetPointerStyle_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    uint32_t windowId = window->GetWindowId();
    int32_t pointerStyle;
    if (InputManager::GetInstance()->SetPointerStyle(windowId, MOUSE_ICON::CROSS) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle, MOUSE_ICON::CROSS);
    }
}

/**
 * @tc.name: InputManagerTest_FunctionKeyState_001
 * @tc.desc: Set NumLock for the keyboard enablement state to true
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(InputManagerTest, InputManagerTest_FunctionKeyState_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    InputManager::GetInstance()->SetFunctionKeyState(KeyEvent::NUM_LOCK_FUNCTION_KEY, true);
    InputManager::GetInstance()->GetFunctionKeyState(KeyEvent::NUM_LOCK_FUNCTION_KEY);
}

/**
 * @tc.name: InputManagerTest_FunctionKeyState_002
 * @tc.desc: Set NumLock for the keyboard enablement state to false
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(InputManagerTest, InputManagerTest_FunctionKeyState_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    InputManager::GetInstance()->SetFunctionKeyState(KeyEvent::NUM_LOCK_FUNCTION_KEY, false);
    bool result = InputManager::GetInstance()->GetFunctionKeyState(KeyEvent::NUM_LOCK_FUNCTION_KEY);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: InputManagerTest_FunctionKeyState_003
 * @tc.desc: Set ScrollLock for the keyboard enablement state to true
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(InputManagerTest, InputManagerTest_FunctionKeyState_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    InputManager::GetInstance()->SetFunctionKeyState(KeyEvent::SCROLL_LOCK_FUNCTION_KEY, true);
    InputManager::GetInstance()->GetFunctionKeyState(KeyEvent::SCROLL_LOCK_FUNCTION_KEY);
}

/**
 * @tc.name: InputManagerTest_FunctionKeyState_004
 * @tc.desc: Set ScrollLock for the keyboard enablement state to false
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(InputManagerTest, InputManagerTest_FunctionKeyState_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    InputManager::GetInstance()->SetFunctionKeyState(KeyEvent::SCROLL_LOCK_FUNCTION_KEY, false);
    bool result = InputManager::GetInstance()->GetFunctionKeyState(KeyEvent::SCROLL_LOCK_FUNCTION_KEY);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: InputManagerTest_FunctionKeyState_005
 * @tc.desc: Set CapsLock for the keyboard enablement state to true
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(InputManagerTest, InputManagerTest_FunctionKeyState_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    InputManager::GetInstance()->SetFunctionKeyState(KeyEvent::CAPS_LOCK_FUNCTION_KEY, true);
    InputManager::GetInstance()->GetFunctionKeyState(KeyEvent::CAPS_LOCK_FUNCTION_KEY);
}

/**
 * @tc.name: InputManagerTest_FunctionKeyState_006
 * @tc.desc: Set CapsLock for the keyboard enablement state to false
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(InputManagerTest, InputManagerTest_FunctionKeyState_006, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    InputManager::GetInstance()->SetFunctionKeyState(KeyEvent::CAPS_LOCK_FUNCTION_KEY, false);
    bool result = InputManager::GetInstance()->GetFunctionKeyState(KeyEvent::CAPS_LOCK_FUNCTION_KEY);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: InputManagerTest_FunctionKeyState_007
 * @tc.desc: Set other function keys
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(InputManagerTest, InputManagerTest_FunctionKeyState_007, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    InputManager::GetInstance()->SetFunctionKeyState(KeyEvent::UNKOWN_FUNCTION_KEY, true);
    bool result = InputManager::GetInstance()->GetFunctionKeyState(KeyEvent::UNKOWN_FUNCTION_KEY);
    ASSERT_FALSE(result);
    
    InputManager::GetInstance()->SetFunctionKeyState(KeyEvent::UNKOWN_FUNCTION_KEY, false);
    result = InputManager::GetInstance()->GetFunctionKeyState(KeyEvent::UNKOWN_FUNCTION_KEY);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: InputManagerTest_TouchScreenHotArea_001
 * @tc.desc: Touch event Search window by defaultHotAreas
 * @tc.type: FUNC
 * @tc.require: I5HMCB
 */
HWTEST_F(InputManagerTest, InputManagerTest_TouchScreenHotArea_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupTouchScreenEvent001() };
    ASSERT_TRUE(pointerEvent != nullptr);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    ASSERT_EQ(pointerEvent->GetSourceType(), PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
}

/**
 * @tc.name: InputManagerTest_TouchScreenHotArea_002
 * @tc.desc: Touch event Search window by pointerHotAreas
 * @tc.type: FUNC
 * @tc.require: I5HMCB
 */
HWTEST_F(InputManagerTest, InputManagerTest_TouchScreenHotArea_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupTouchScreenEvent002() };
    ASSERT_TRUE(pointerEvent != nullptr);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    ASSERT_EQ(pointerEvent->GetSourceType(), PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
}

/**
 * @tc.name: InputManagerTest_MouseHotArea_001
 * @tc.desc: Mouse event Search window by pointerHotAreas
 * @tc.type: FUNC
 * @tc.require: I5HMCB
 */
HWTEST_F(InputManagerTest, InputManagerTest_MouseHotArea_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupmouseEvent001() };
    ASSERT_TRUE(pointerEvent != nullptr);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    ASSERT_EQ(pointerEvent->GetSourceType(), PointerEvent::SOURCE_TYPE_MOUSE);
}

/**
 * @tc.name: InputManagerTest_MouseHotArea_002
 * @tc.desc: Mouse event Search window by pointerHotAreas
 * @tc.type: FUNC
 * @tc.require: I5HMCB
 */
HWTEST_F(InputManagerTest, InputManagerTest_MouseHotArea_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent { SetupmouseEvent002() };
    ASSERT_TRUE(pointerEvent != nullptr);
    ASSERT_EQ(pointerEvent->GetSourceType(), PointerEvent::SOURCE_TYPE_MOUSE);
}

/**
 * @tc.name: InputManagerTest_UpdateDisplayInfo
 * @tc.desc: Update window information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_UpdateDisplayInfo, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = 0;
    displayGroupInfo.width = 0;
    displayGroupInfo.height = 0;
    InputManager::GetInstance()->UpdateDisplayInfo(displayGroupInfo);
    ASSERT_TRUE(displayGroupInfo.displaysInfo.empty());
}

/**
 * @tc.name: InputManagerTest_SetInputDevice
 * @tc.desc: Set input device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetInputDevice, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::string dhid("");
    std::string screenId("");
    int32_t ret = InputManager::GetInstance()->SetInputDevice(dhid, screenId);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    ASSERT_EQ(ret, RET_ERR);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

/**
 * @tc.name: InputManagerTest_RegisterCooperateListener_001
 * @tc.desc: Register cooperate listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_RegisterCooperateListener_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<IInputDeviceCooperateListener> consumer = nullptr;
    int32_t ret = InputManager::GetInstance()->RegisterCooperateListener(consumer);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    ASSERT_EQ(ret, RET_ERR);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

/**
 * @tc.name: InputManagerTest_RegisterCooperateListener_002
 * @tc.desc: Register cooperate listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_RegisterCooperateListener_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    class InputDeviceCooperateListenerTest : public IInputDeviceCooperateListener {
    public:
        InputDeviceCooperateListenerTest() : IInputDeviceCooperateListener() {}
        void OnCooperateMessage(const std::string &deviceId, CooperationMessage msg) override
        {
            MMI_HILOGD("RegisterCooperateListenerTest");
        };
    };
    std::shared_ptr<InputDeviceCooperateListenerTest> consumer = std::make_shared<InputDeviceCooperateListenerTest>();
    int32_t ret = InputManager::GetInstance()->RegisterCooperateListener(consumer);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COOPERATE
    ret = InputManager::GetInstance()->UnregisterCooperateListener(consumer);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

/**
 * @tc.name: InputManagerTest_UnregisterCooperateListener
 * @tc.desc: Unregister cooperate listener
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(InputManagerTest, InputManagerTest_UnregisterCooperateListener, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<IInputDeviceCooperateListener> consumer = nullptr;
    int32_t ret = InputManager::GetInstance()->UnregisterCooperateListener(consumer);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

/**
 * @tc.name: InputManagerTest_EnableInputDeviceCooperate
 * @tc.desc: Enable input device cooperate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_EnableInputDeviceCooperate, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    bool enabled = false;
    auto fun = [](std::string listener, CooperationMessage cooperateMessages) {
        MMI_HILOGD("Enable input device cooperate success");
    };
    int32_t ret = InputManager::GetInstance()->EnableInputDeviceCooperate(enabled, fun);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

/**
 * @tc.name: InputManagerTest_StartInputDeviceCooperate
 * @tc.desc: Start input device cooperate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_StartInputDeviceCooperate, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::string sinkDeviceId("");
    int32_t srcInputDeviceId = -1;
    auto fun = [](std::string listener, CooperationMessage cooperateMessages) {
        MMI_HILOGD("Start input device cooperate success");
    };
    int32_t ret = InputManager::GetInstance()->StartInputDeviceCooperate(sinkDeviceId, srcInputDeviceId, fun);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    ASSERT_NE(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

/**
 * @tc.name: InputManagerTest_StopDeviceCooperate
 * @tc.desc: Stop device cooperate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_StopDeviceCooperate, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto fun = [](std::string listener, CooperationMessage cooperateMessages) {
        MMI_HILOGD("Start input device cooperate success");
    };
    int32_t ret = InputManager::GetInstance()->StopDeviceCooperate(fun);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    ASSERT_NE(ret, ERROR_UNSUPPORT);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

/**
 * @tc.name: InputManagerTest_GetInputDeviceCooperateState
 * @tc.desc: Get input device cooperate state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_GetInputDeviceCooperateState, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    const std::string deviceId("");
    auto fun = [](bool inputdevice) {
        MMI_HILOGD("Get inputdevice state success");
    };
    int32_t ret = InputManager::GetInstance()->GetInputDeviceCooperateState(deviceId, fun);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

/**
 * @tc.name: InputManagerTest_GetDevice_001
 * @tc.desc: Verify the fetch device info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_GetDevice_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t deviceId = 0;
    auto callback = [](std::shared_ptr<InputDevice> inputDevice) {
        MMI_HILOGD("Get device success");
        ASSERT_TRUE(inputDevice != nullptr);
    };
    int32_t ret = InputManager::GetInstance()->GetDevice(deviceId, callback);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputManagerTest_GetDevice_002
 * @tc.desc: Verify the fetch device info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_GetDevice_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t deviceId = -1;
    auto callback = [](std::shared_ptr<InputDevice> inputDevice) {
        MMI_HILOGD("Get device success");
        ASSERT_TRUE(inputDevice != nullptr);
    };
    int32_t ret = InputManager::GetInstance()->GetDevice(deviceId, callback);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: InputManagerTest_GetDeviceIds
 * @tc.desc: Verify the fetch device list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_GetDeviceIds, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto callback = [](std::vector<int32_t> ids) {
        MMI_HILOGD("Get device success");
    };
    int32_t ret = InputManager::GetInstance()->GetDeviceIds(callback);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputManagerTest_SetAnrObserver
 * @tc.desc: Verify the observer for events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetAnrObserver, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    class IAnrObserverTest : public IAnrObserver {
    public:
        IAnrObserverTest() : IAnrObserver() {}
        virtual ~IAnrObserverTest() {}
        void OnAnr(int32_t pid) const override
        {
            MMI_HILOGD("Set anr success");
        };
    };

    std::shared_ptr<IAnrObserverTest> observer = std::make_shared<IAnrObserverTest>();
    InputManager::GetInstance()->SetAnrObserver(observer);
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupTabletToolEvent001()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(DEFAULT_POINTER_ID);   // test code，set the PointerId = 0
    item.SetDisplayX(523);   // test code，set the DisplayX = 523
    item.SetDisplayY(723);   // test code，set the DisplayY = 723
    item.SetPressure(0.7);    // test code，set the Pressure = 0.7
    item.SetTiltX(10.0);     // test code，set the TiltX = 10.0
    item.SetTiltY(-9.0);     // test code，set the TiltX = -9.0
    item.SetDeviceId(DEFAULT_DEVICE_ID);    // test code，set the DeviceId = 0
    item.SetToolType(PointerEvent::TOOL_TYPE_PEN);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);  // test code，set the PointerId = 0
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

#ifdef OHOS_BUILD_ENABLE_MONITOR
/**
 * @tc.name: InputManagerTest_MonitorTabletToolEvent_001
 * @tc.desc: Verify monitoring tablet tool down event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_MonitorTabletToolEvent_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = TestAddMonitor(callbackPtr);
    EXPECT_TRUE(IsValidHandlerId(monitorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#ifdef OHOS_BUILD_ENABLE_TOUCH
    auto pointerEvent = SetupTabletToolEvent001();
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent(pointerEvent);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}
#endif // OHOS_BUILD_ENABLE_MONITOR

#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
/**
 * @tc.name: InputManagerTest_InterceptTabletToolEvent_001
 * @tc.desc: Verify intercepting tablet tool event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_InterceptTabletToolEvent_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#ifdef OHOS_BUILD_ENABLE_TOUCH
    auto pointerEvent = SetupTabletToolEvent001();
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent(pointerEvent);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH

    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
} // namespace MMI
} // namespace OHOS
