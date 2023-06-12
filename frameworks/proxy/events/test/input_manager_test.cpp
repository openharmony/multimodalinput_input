/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <cstdio>

#include "event_log_helper.h"
#include "event_util_test.h"
#include "input_handler_type.h"
#include "input_manager_impl.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "pixel_map.h"
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
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
static constexpr uint32_t DATA_ARRY_LEN = 16;
static constexpr uint32_t MAX_HMAC_SIZE = 64;
static constexpr uint32_t SHA384_KEY_LEN = 48;

enum HmacAlg : int32_t {
    HMAC_SHA384 = 1,
};
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
} // namespace

class InputManagerTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    std::string GetEventDump();
    std::shared_ptr<KeyOption> InitOption(const std::set<int32_t> &preKeys,
        int32_t finalKey, bool isFinalKeyDown, int32_t duration);
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
    std::unique_ptr<OHOS::Media::PixelMap> SetMouseIconTest(const std::string iconPath);
    void TestMarkConsumedStep3(int32_t monitorId, int32_t eventId);
    void TestMarkConsumedStep4();
    void TestMarkConsumedStep5();
    void TestMarkConsumedStep6();
    int32_t TestAddMonitor(std::shared_ptr<IInputEventConsumer> consumer);
    void TestRemoveMonitor(int32_t monitorId);
    void TestMarkConsumed(int32_t monitorId, int32_t eventId);
    void TestMonitor(int32_t monitorId, std::shared_ptr<PointerEvent> pointerEvent);
    void TestInterceptorIdAndPointerEvent(int32_t interceptorId, std::shared_ptr<PointerEvent> pointerEvent);
    void TestInterceptorId(int32_t interceptorId1, int32_t interceptorId2);
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

std::unique_ptr<OHOS::Media::PixelMap> InputManagerTest::SetMouseIconTest(const std::string iconPath)
{
    CALL_DEBUG_ENTER;
    OHOS::Media::SourceOptions opts;
    opts.formatHint = "image/svg+xml";
    uint32_t ret = 0;
    auto imageSource = OHOS::Media::ImageSource::CreateImageSource(iconPath, opts, ret);
    CHKPP(imageSource);
    std::set<std::string> formats;
    ret = imageSource->GetSupportedFormats(formats);
    MMI_HILOGD("Get supported format ret:%{public}u", ret);

    OHOS::Media::DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {
        .width = 64,
        .height = 64
    };

    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, ret);
    if (pixelMap == nullptr) {
        MMI_HILOGE("The pixelMap is nullptr");
    }
    return pixelMap;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent001()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetPressure(5);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);
    item.SetDisplayX(610);
    item.SetDisplayY(910);
    item.SetPressure(7);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent002()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(593);
    item.SetDisplayY(783);
    item.SetPressure(5);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);
    item.SetDisplayX(600);
    item.SetDisplayY(610);
    item.SetPressure(7);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent003()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(53);
    item.SetDisplayY(733);
    item.SetPressure(5);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);
    item.SetDisplayX(623);
    item.SetDisplayY(823);
    item.SetPressure(0);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(1);
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

    item.SetDisplayX(520);
    item.SetDisplayY(530);
    item.SetWindowX(740);
    item.SetWindowY(750);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent006()
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

    item.SetDisplayX(25);
    item.SetDisplayY(68);
    item.SetWindowX(67);
    item.SetWindowY(99);

    item.SetWidth(50);
    item.SetPressure(0);
    item.SetDeviceId(0);
    item.SetHeight(60);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
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
    item.SetDisplayX(550);
    item.SetWindowX(720);
    item.SetWindowY(730);
    item.SetWidth(80);
    item.SetHeight(80);
    item.SetPressure(0);
    item.SetDeviceId(0);
    item.SetDisplayY(650);
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
    PointerEvent::PointerItem item;
    item.SetDisplayY(504);
    item.SetDownTime(0);
    item.SetPressed(false);
    item.SetDisplayX(503);
    item.SetWindowX(701);
    item.SetPointerId(1);
    item.SetWindowY(702);
    item.SetDeviceId(0);
    item.SetWidth(20);
    item.SetHeight(60);
    item.SetPressure(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent010()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 30.0);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, 40.0);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(0);
    item.SetPressed(false);

    item.SetDisplayX(200);
    item.SetDisplayY(200);
    item.SetWindowX(300);
    item.SetWindowY(300);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent011()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetTiltY(5.43);
    item.SetPointerId(0);
    item.SetDownTime(0);
    item.SetWindowY(453);
    item.SetDisplayX(523);
    item.SetWindowX(323);
    item.SetHeight(0);
    item.SetTiltX(2.12);
    item.SetDisplayY(723);
    item.SetPressure(0.15);
    item.SetDeviceId(1);
    item.SetWidth(0);
    pointerEvent->AddPointerItem(item);

    item.SetDownTime(0);
    item.SetPointerId(1);
    item.SetDisplayY(50);
    item.SetWindowX(70);
    item.SetWidth(0);
    item.SetDeviceId(1);
    item.SetHeight(0);
    item.SetDisplayX(50);
    item.SetTiltX(12.22);
    item.SetTiltY(15.33);
    item.SetPressure(0.45);
    item.SetWindowY(70);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent012()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetDeviceId(1);
    item.SetTiltY(5.43);
    item.SetHeight(0);
    item.SetDownTime(0);
    item.SetDisplayY(723);
    item.SetWindowX(323);
    item.SetDisplayX(523);
    item.SetWindowY(453);
    item.SetWidth(0);
    item.SetTiltX(2.12);
    item.SetPressure(0.15);
    item.SetPointerId(0);
    pointerEvent->AddPointerItem(item);

    item.SetDeviceId(1);
    item.SetDownTime(0);
    item.SetTiltX(12.22);
    item.SetWindowX(70);
    item.SetWindowY(70);
    item.SetWidth(0);
    item.SetDisplayY(50);
    item.SetHeight(0);
    item.SetDisplayX(50);
    item.SetTiltY(15.33);
    item.SetPressure(0.45);
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent013()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(0);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetWindowX(323);
    item.SetWindowY(453);
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetTiltX(2.12);
    item.SetTiltY(5.43);
    item.SetPressure(0.15);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);
    item.SetDownTime(0);
    item.SetDisplayX(50);
    item.SetDisplayY(50);
    item.SetWindowX(70);
    item.SetWindowY(70);
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetTiltX(12.22);
    item.SetTiltY(15.33);
    item.SetPressure(0.45);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent014()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);
    PointerEvent::PointerItem item;
    item.SetDisplayX(100);
    item.SetDisplayY(555);
    item.SetWindowX(20);
    item.SetWindowY(45);

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

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent015()
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

    item.SetDisplayX(50);
    item.SetDisplayY(1259);
    item.SetWindowX(120);
    item.SetWindowY(106);

    pointerEvent->AddPointerItem(item);
    return pointerEvent;
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
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    kitDown.SetKeyCode(KeyEvent::KEYCODE_BACK);
    keyEvent->AddPressedKeyItems(kitDown);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    return keyEvent;
}

std::shared_ptr<KeyEvent> InputManagerTest::SetupKeyEvent002()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_BACK);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddPressedKeyItems(kitDown);

    return keyEvent;
}

std::shared_ptr<KeyEvent> InputManagerTest::SetupKeyEvent003()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_HOME);
    kitDown.SetDownTime(downTime);
    kitDown.SetPressed(true);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
    keyEvent->AddPressedKeyItems(kitDown);

    return keyEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::TestMarkConsumedStep1()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetPressure(5);
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

std::shared_ptr<PointerEvent> InputManagerTest::TestMarkConsumedStep2()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(623);
    item.SetDisplayY(723);
    item.SetPressure(5);
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

void InputManagerTest::TestMarkConsumedStep3(int32_t monitorId, int32_t eventId)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_MARK_CONSUMED);
    TestMarkConsumed(monitorId, eventId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

void InputManagerTest::TestMarkConsumedStep4()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetDeviceId(1);
    item.SetPointerId(0);
    item.SetDisplayX(555);
    item.SetDisplayY(777);
    item.SetPressure(5);
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

void InputManagerTest::TestMarkConsumedStep5()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(546);
    item.SetDisplayY(703);
    item.SetPressure(5);
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

void InputManagerTest::TestMarkConsumedStep6()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(888);
    item.SetDisplayY(999);
    item.SetPressure(5);
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

std::shared_ptr<PointerEvent> InputManagerTest::SetupmouseEvent001()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);
    PointerEvent::PointerItem item;

    item.SetDisplayX(50);
    item.SetDisplayY(80);
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    item.SetWindowX(55);
    item.SetWindowY(66);
    item.SetPointerId(0);
    item.SetDownTime(0);
    item.SetPressed(false);

    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupmouseEvent002()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);
    PointerEvent::PointerItem item;
    item.SetDownTime(0);
    item.SetPressed(false);
    item.SetDisplayX(40);
    item.SetDisplayY(60);
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetWindowX(80);
    item.SetWindowY(90);
    item.SetPressure(0);
    item.SetPointerId(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupTouchScreenEvent001()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(10);
    item.SetDisplayY(10);
    item.SetPressure(5);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupTouchScreenEvent002()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(50);
    item.SetDisplayY(50);
    item.SetPressure(5);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
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

void InputManagerTest::TestMonitor(int32_t monitorId, std::shared_ptr<PointerEvent> pointerEvent)
{
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

void InputManagerTest::TestInterceptorIdAndPointerEvent(int32_t interceptorId,
    std::shared_ptr<PointerEvent> pointerEvent)
{
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

void InputManagerTest::TestInterceptorId(int32_t interceptorId1, int32_t interceptorId2)
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

/**
 * @tc.name: InputManagerTest_AddMonitor_001
 * @tc.desc: Verify pointerevent monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    KeyEvent::KeyItem kitDown;
    kitDown.SetDownTime(downTime);
    kitDown.SetPressed(true);
    kitDown.SetKeyCode(KeyEvent::KEYCODE_BACK);
    injectDownEvent->AddPressedKeyItems(kitDown);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
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
    injectUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    injectUpEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = 0;
    KeyEvent::KeyItem kitDown;
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    kitDown.SetKeyCode(KeyEvent::KEYCODE_BACK);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    injectDownEvent->AddPressedKeyItems(kitDown);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    TestSimulateInputEvent(injectDownEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD

    std::shared_ptr<KeyEvent> injectUpEvent = KeyEvent::Create();
    ASSERT_TRUE(injectUpEvent != nullptr);
    KeyEvent::KeyItem kitUp;
    kitUp.SetKeyCode(KeyEvent::KEYCODE_BACK);
    kitUp.SetDownTime(downTime);
    kitUp.SetPressed(false);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
    injectUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    injectUpEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    kitUp.SetDownTime(downTime);
    kitUp.SetPressed(false);
    injectUpEvent->SetKeyCode(KeyEvent::KEYCODE_FN);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
    injectUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 30.0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    pointerEvent->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetDownTime(0);
    item.SetPressed(false);
    item.SetPointerId(1);

    item.SetWindowY(300);
    item.SetDisplayY(200);
    item.SetWindowX(300);
    item.SetDisplayX(200);

    item.SetDeviceId(0);
    item.SetPressure(0);
    item.SetWidth(0);
    item.SetHeight(0);
    pointerEvent->AddPointerItem(item);

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
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 30.0);
    pointerEvent->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetDownTime(0);
    item.SetPressed(false);
    item.SetPointerId(1);

    item.SetDisplayY(400);
    item.SetDisplayX(400);
    item.SetWindowY(600);
    item.SetWindowX(600);

    item.SetPressure(0);
    item.SetHeight(0);
    item.SetDeviceId(0);
    item.SetWidth(0);
    pointerEvent->AddPointerItem(item);

#ifdef OHOS_BUILD_ENABLE_POINTER
    TestSimulateInputEvent(pointerEvent);
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
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 30.0);
    PointerEvent::PointerItem item;
    item.SetDownTime(0);
    item.SetPointerId(1);
    item.SetPressed(false);

    item.SetDeviceId(0);
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);

    item.SetDisplayX(700);
    item.SetDisplayY(500);
    item.SetWindowX(211);
    item.SetWindowY(311);

    pointerEvent->AddPointerItem(item);

#ifdef OHOS_BUILD_ENABLE_POINTER
    TestSimulateInputEvent(pointerEvent);
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPressure(5);
    item.SetPointerId(0);
    item.SetDisplayX(456);
    item.SetDisplayY(123);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
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
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetDisplayY(258);
    item.SetDisplayX(147);
    item.SetPressure(5);
    item.SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}

std::shared_ptr<KeyOption> InputManagerTest::InitOption(const std::set<int32_t> &preKeys,
    int32_t finalKey, bool isFinalKeyDown, int32_t duration)
{
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyDown(isFinalKeyDown);
    keyOption->SetFinalKey(finalKey);
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKeyDownDuration(duration);
    return keyOption;
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
    CALL_TEST_DEBUG;
    std::set<int32_t> preKeys;
    std::shared_ptr<KeyOption> keyOption = InitOption(preKeys, KeyEvent::KEYCODE_VOLUME_MUTE, true, 0);
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
    CALL_TEST_DEBUG;
    ASSERT_TRUE(MMIEventHdl.InitClient());
    // 电源键长按按下订阅
    std::set<int32_t> preKeys;
    std::shared_ptr<KeyOption> keyOption = InitOption(preKeys, KeyEvent::KEYCODE_POWER, true, 2000);
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
    std::shared_ptr<KeyOption> keyOption2 = InitOption(preKeys, KeyEvent::KEYCODE_POWER, false, 0);
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
    CALL_TEST_DEBUG;
    ASSERT_TRUE(MMIEventHdl.InitClient());
    std::set<int32_t> preKeys;
    std::shared_ptr<KeyOption> keyOption1 = InitOption(preKeys, KeyEvent::KEYCODE_VOLUME_UP, true, 10);
    int32_t subscribeId1 = -1;
    subscribeId1 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption1,
        [](std::shared_ptr<KeyEvent> keyEvent) {
        EventLogHelper::PrintEventData(keyEvent);
        MMI_HILOGD("Subscribe key event KEYCODE_VOLUME_UP down trigger callback");
    });
    std::shared_ptr<KeyOption> keyOption2 = InitOption(preKeys, KeyEvent::KEYCODE_VOLUME_UP, false, 0);
    int32_t subscribeId2 = -1;
    subscribeId2 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption2,
        [](std::shared_ptr<KeyEvent> keyEvent) {
        EventLogHelper::PrintEventData(keyEvent);
        MMI_HILOGD("Subscribe key event KEYCODE_VOLUME_UP up trigger callback");
    });
    std::shared_ptr<KeyOption> keyOption3 = InitOption(preKeys, KeyEvent::KEYCODE_VOLUME_UP, true, 0);
    int32_t subscribeId3 = -1;
    subscribeId3 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption3,
        [](std::shared_ptr<KeyEvent> keyEvent) {
        EventLogHelper::PrintEventData(keyEvent);
        MMI_HILOGD("Subscribe key event KEYCODE_VOLUME_UP down trigger callback");
    });
    std::shared_ptr<KeyOption> keyOption4 = InitOption(preKeys, KeyEvent::KEYCODE_VOLUME_UP, false, 0);
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
 * @tc.name: InputManagerTest_SubscribeKeyEvent_04
 * @tc.desc: Verify subscribe key event.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> preKeys;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(-1);
    int32_t subscribeId = -1;
    subscribeId = InputManager::GetInstance()->SubscribeKeyEvent(keyOption,
        [](std::shared_ptr<KeyEvent> keyEvent) {
        EventLogHelper::PrintEventData(keyEvent);
        MMI_HILOGD("Subscribe key event KEYCODE_POWER down trigger callback");
    });
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    EXPECT_TRUE(subscribeId >= 0);
#else
    EXPECT_TRUE(subscribeId < 0);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
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
    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);
    ASSERT_EQ(injectDownEvent->GetKeyAction(), KeyEvent::KEY_ACTION_DOWN);
}

/**
 * @tc.name: TestGetKeystrokeAbility_001
 * @tc.desc: Verify SupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestGetKeystrokeAbility_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> keyCodes = { 17, 22, 2055 };
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
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPressed(true);
    item.SetDisplayY(723);
    item.SetDisplayX(523);
    item.SetDeviceId(1);
    item.SetDownTime(10010);
    item.SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
    TestInterceptorIdAndPointerEvent(interceptorId, pointerEvent);
}

/**
 * @tc.name: TestInputEventInterceptor_002
 * @tc.desc: Verify mouse move event interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetDeviceId(1);
    item.SetDisplayY(723);
    item.SetPressed(true);
    item.SetDisplayX(523);
    item.SetDownTime(10010);
    item.SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
    TestInterceptorIdAndPointerEvent(interceptorId, pointerEvent);
}

/**
 * @tc.name: TestInputEventInterceptor_003
 * @tc.desc: Verify mouse up event interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetDisplayY(723);
    item.SetDisplayX(523);
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(10010);
    item.SetDeviceId(1);
    item.SetPressed(true);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
    TestInterceptorIdAndPointerEvent(interceptorId, pointerEvent);
}

/**
 * @tc.name: TestInputEventInterceptor_004
 * @tc.desc: Verify multiple interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10008);
    item.SetPressed(true);
    item.SetDeviceId(1);
    item.SetDisplayX(623);
    item.SetDisplayY(943);
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

    for (size_t i = 0; i < ids.size(); ++i) {
        std::string sPointerEs = InputManagerTest::GetEventDump();
        MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
        if (i == 0) {
            ASSERT_TRUE(!sPointerEs.empty());
        } else {
            ASSERT_TRUE(sPointerEs.empty());
        }
#else
        ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_INTERCEPTOR
        if (IsValidHandlerId(ids[i])) {
            InputManager::GetInstance()->RemoveInterceptor(ids[i]);
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
    CALL_TEST_DEBUG;
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
    item.SetDisplayX(500);
    item.SetDisplayY(600);
    pointerEvent->AddPointerItem(item);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
    TestInterceptorIdAndPointerEvent(interceptorId, pointerEvent);
}

/**
 * @tc.name: TestInputEventInterceptor_006
 * @tc.desc: Verify touchscreen interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(222);
    item.SetDisplayY(357);
    item.SetPressure(5);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    item.SetPointerId(1);
    item.SetDisplayX(710);
    item.SetDisplayY(910);
    item.SetPressure(7);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(1);
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
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_BACK);
    kitDown.SetDownTime(downTime);
    kitDown.SetPressed(true);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
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
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetDownTime(10007);
    item.SetPointerId(0);
    item.SetDeviceId(1);
    item.SetPressed(true);
    item.SetDisplayX(528);
    item.SetDisplayY(757);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->AddPointerItem(item);

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
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10006);
    item.SetPressed(true);
    item.SetDisplayX(543);
    item.SetDisplayY(863);
    item.SetDeviceId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);

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
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetDownTime(downTime);
    kitDown.SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    kitDown.SetPressed(true);
    kitDown.SetDeviceId(1);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

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
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_SPACE);
    kitDown.SetDownTime(downTime);
    kitDown.SetDeviceId(1);
    kitDown.SetPressed(true);
    injectDownEvent->AddPressedKeyItems(kitDown);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_SPACE);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    auto interceptor = GetPtr<InputEventCallback>();
    uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor, 400, touchTags) };
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);

    std::string sPointerEs = InputManagerTest::GetEventDump();
    MMI_HILOGD("PriorityLevel Test:sPointerEs:%{public}s", sPointerEs.c_str());
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
 * @tc.desc: Verify mouse interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10005);
    item.SetPressed(true);
    item.SetDisplayX(852);
    item.SetDisplayY(367);
    item.SetDeviceId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->AddPointerItem(item);

    auto interceptor = GetPtr<InputEventCallback>();
    uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
    int32_t interceptorId = InputManager::GetInstance()->AddInterceptor(interceptor, 400, touchTags);
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
 * @tc.name: TestInputEventInterceptor_013
 * @tc.desc: Verify mouse interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPressed(true);
    item.SetPointerId(0);
    item.SetDownTime(10004);
    item.SetDisplayX(111);
    item.SetDeviceId(1);
    item.SetDisplayY(222);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    auto interceptor1 = GetPtr<PriorityHighCallback>();
    auto interceptor2 = GetPtr<PriorityMiddleCallback>();
    uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
    int32_t interceptorId1 { InputManager::GetInstance()->AddInterceptor(interceptor1, 400, touchTags) };
    int32_t interceptorId2 { InputManager::GetInstance()->AddInterceptor(interceptor2, 500, touchTags) };
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId1));
    EXPECT_TRUE(IsValidHandlerId(interceptorId2));
#else
    EXPECT_EQ(interceptorId1, ERROR_UNSUPPORT);
    EXPECT_EQ(interceptorId2, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    for (size_t i = 0; i < 2; ++i) {
        std::string sPointerEs = InputManagerTest::GetEventDump();
        MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
    #if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
        if (i == 0) {
            EXPECT_EQ(sPointerEs, "Call high interceptor");
        } else {
            ASSERT_TRUE(sPointerEs.empty());
        }
    #else
        ASSERT_TRUE(sPointerEs.empty());
    #endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_INTERCEPTOR
    }

    TestInterceptorId(interceptorId1, interceptorId2);
}

/**
 * @tc.name: TestInputEventInterceptor_014
 * @tc.desc: Verify space key interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetDeviceId(1);
    kitDown.SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    auto interceptor2 = GetPtr<PriorityMiddleCallback>();
    auto interceptor1 = GetPtr<PriorityHighCallback>();
    uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
    int32_t interceptorId2 { InputManager::GetInstance()->AddInterceptor(interceptor2, 500, touchTags) };
    int32_t interceptorId1 { InputManager::GetInstance()->AddInterceptor(interceptor1, 400, touchTags) };
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId1));
    EXPECT_TRUE(IsValidHandlerId(interceptorId2));
#else
    EXPECT_EQ(interceptorId1, ERROR_UNSUPPORT);
    EXPECT_EQ(interceptorId2, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);
    for (size_t i = 0; i < 2; ++i) {
        std::string sPointerEs = InputManagerTest::GetEventDump();
        MMI_HILOGD("PriorityLevel Test:sPointerEs:%{public}s", sPointerEs.c_str());
    #if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
        if (i == 0) {
            EXPECT_EQ(sPointerEs, "Call high interceptor");
        } else {
            ASSERT_TRUE(sPointerEs.empty());
        }
    #else
        ASSERT_TRUE(sPointerEs.empty());
    #endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_INTERCEPTOR
    }

    TestInterceptorId(interceptorId1, interceptorId2);
}

/**
 * @tc.name: TestInputEventInterceptor_015
 * @tc.desc: Verify space key interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetPressed(true);
    kitDown.SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    kitDown.SetDeviceId(1);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    auto interceptor1 = GetPtr<PriorityHighCallback>();
    auto interceptor2 = GetPtr<PriorityMiddleCallback>();
    uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
    int32_t interceptorId1 { InputManager::GetInstance()->AddInterceptor(interceptor1, 500, touchTags) };
    int32_t interceptorId2 { InputManager::GetInstance()->AddInterceptor(interceptor2, 600, touchTags) };
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId1));
    EXPECT_TRUE(IsValidHandlerId(interceptorId2));
#else
    EXPECT_EQ(interceptorId1, ERROR_UNSUPPORT);
    EXPECT_EQ(interceptorId2, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    if (IsValidHandlerId(interceptorId1)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId1);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);
    for (size_t i = 0; i < 3; ++i) {
        std::string sPointerEs = InputManagerTest::GetEventDump();
        MMI_HILOGD("PriorityLevel Test:sPointerEs:%{public}s", sPointerEs.c_str());
    #if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
        if (i == 0) {
            EXPECT_EQ(sPointerEs, "Call middle interceptor");
        } else {
            ASSERT_TRUE(sPointerEs.empty());
        }
    #else
        ASSERT_TRUE(sPointerEs.empty());
    #endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_INTERCEPTOR
    }

    if (IsValidHandlerId(interceptorId2)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId2);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_016
 * @tc.desc: Verify keyevent interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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

    TestMonitor(monitorId, pointerEvent);
}

/**
 * @tc.name: InputManagerTest_OnAddScreenMonitor_002
 * @tc.desc: Verify touchscreen move event multiple monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddScreenMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
 * @tc.name: InputManagerTest_OnAddTouchPadMonitor_001
 * @tc.desc: Verify touchpad down event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetDownTime(10003);
    item.SetPressed(true);
    item.SetDisplayX(222);
    item.SetDeviceId(1);
    item.SetDisplayY(333);
    item.SetPointerId(0);
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

    TestMonitor(monitorId, pointerEvent);
}

/**
 * @tc.name: InputManagerTest_OnAddTouchPadMonitor_002
 * @tc.desc: Verify touchpad move event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10001);
    item.SetDisplayX(444);
    item.SetPressed(true);
    item.SetDeviceId(1);
    item.SetDisplayY(555);
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

    TestMonitor(monitorId, pointerEvent);
}

/**
 * @tc.name: InputManagerTest_OnAddTouchPadMonitor_003
 * @tc.desc: Verify touchpad up event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetDownTime(9999);
    item.SetPointerId(0);
    item.SetPressed(true);
    item.SetDisplayY(777);
    item.SetDeviceId(1);
    item.SetDisplayX(666);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
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

    TestMonitor(monitorId, pointerEvent);
}

/**
 * @tc.name: InputManagerTest_OnAddTouchPadMonitor_004
 * @tc.desc: Verify touchpad multiple monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_MONITOR);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetDownTime(10009);
    item.SetDeviceId(1);
    item.SetPointerId(0);
    item.SetPressed(true);
    item.SetDisplayX(555);
    item.SetDisplayY(793);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
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
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetDownTime(10010);
    item.SetPointerId(0);
    item.SetDeviceId(1);
    item.SetPressed(true);
    item.SetDisplayX(923);
    item.SetDisplayY(223);
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

    TestMonitor(monitorId, pointerEvent);
}

/**
 * @tc.name: InputManager_TouchPadSimulateInputEvent_001
 * @tc.desc: Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId { TestAddMonitor(callbackPtr) };
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t stepTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item {};
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(stepTime);
    item.SetPressed(true);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetActionTime(stepTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    TestMonitor(monitorId, pointerEvent);
}

/**
 * @tc.name: InputManager_TouchPadSimulateInputEvent_002
 * @tc.desc: Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId { TestAddMonitor(callbackPtr) };
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t measureTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item {};
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(measureTime);
    item.SetPressed(true);
    item.SetDisplayX(90);
    item.SetDisplayY(666);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetActionTime(measureTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    TestMonitor(monitorId, pointerEvent);
}

/**
 * @tc.name: InputManager_TouchPadSimulateInputEvent_003
 * @tc.desc: Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId { TestAddMonitor(callbackPtr) };
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t deedTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item {};
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(deedTime);
    item.SetPressed(false);
    item.SetDisplayX(505);
    item.SetDisplayY(505);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetActionTime(deedTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    TestMonitor(monitorId, pointerEvent);
}

/**
 * @tc.name: InputManager_TouchPadSimulateInputEvent_004
 * @tc.desc: Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    item.SetDisplayX(123);
    item.SetDisplayY(223);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    item.SetPointerId(1);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetDisplayX(640);
    item.SetDisplayY(840);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    item.SetPointerId(2);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetDisplayX(660);
    item.SetDisplayY(860);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetActionTime(actionTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    TestMonitor(monitorId, pointerEvent);
}

/**
 * @tc.name: InputManagerTest_AddMouseMonitor_001
 * @tc.desc: Verify mouse down event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    TestMonitor(monitorId, pointerEvent);
}

/**
 * @tc.name: InputManagerTest_AddMouseMonitor_003
 * @tc.desc: Verify mouse up event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    TestMonitor(monitorId, pointerEvent);
}

/**
 * @tc.name: InputManagerTest_AddMouseMonitor_004
 * @tc.desc: Verify monitor upper limit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    SYSTEM_INFO::CpuInfo cpuInfo;
    const std::string process_name = "multimodalinput";
    auto usage = cpuInfo.GetProcCpuUsage(process_name);
    MMI_HILOGD("The CPU usage of the %{public}s process is %{public}.2f", process_name.c_str(), usage);
    ASSERT_TRUE(usage < SYSTEM_INFO::CPU_USAGE_LOAD && usage != SYSTEM_INFO::CPU_USAGE_UNKNOWN);
}

/**
 * @tc.name: InputManagerTest_SetWindowInputEventConsumer_001
 * @tc.desc: Verify pointerEvent report eventHandler
 * @tc.type: FUNC
 * @tc.require: I5HMDY
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetWindowInputEventConsumer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto runner = AppExecFwk::EventRunner::Create("cooperateHdrTest");
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    uint32_t windowId = window->GetWindowId();
    PointerStyle pointerStyle;
    pointerStyle.id = MOUSE_ICON::CROSS;
    if (InputManager::GetInstance()->SetPointerStyle(windowId, pointerStyle) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle.id, MOUSE_ICON::CROSS);
    }
}

/**
 * @tc.name: InputManagerTest_SetPointerStyle_002
 * @tc.desc: Sets the pointer style of the window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetPointerStyle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t windowId = -1;
    PointerStyle pointerStyle;
    pointerStyle.id = MOUSE_ICON::CROSS;
    if (InputManager::GetInstance()->SetPointerStyle(windowId, pointerStyle) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle.id, MOUSE_ICON::CROSS);
    }
}

/**
 * @tc.name: InputManagerTest_SetMouseScrollRows_001
 * @tc.desc: Sets mouse scroll rows
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetMouseScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t rows = 1;
    ASSERT_TRUE(InputManager::GetInstance()->SetMouseScrollRows(rows) == RET_OK);
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_GetMouseScrollRows_001
 * @tc.desc: Sets mouse scroll rows
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerTest, InputManagerTest_GetMouseScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t rows = 50;
    int32_t newRows = 3;
    if (InputManager::GetInstance()->SetMouseScrollRows(rows) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetMouseScrollRows(newRows) == RET_OK);
        ASSERT_EQ(rows, newRows);
    }
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_SetMousePrimaryButton_001
 * @tc.desc: Sets mouse primary button
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetMousePrimaryButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t primaryButton = 1;
    ASSERT_TRUE(InputManager::GetInstance()->SetMousePrimaryButton(primaryButton) == RET_OK);
    primaryButton = 0;
    ASSERT_TRUE(InputManager::GetInstance()->SetMousePrimaryButton(primaryButton) == RET_OK);
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_SetMousePrimaryButton_002
 * @tc.desc: Sets mouse primary button
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetMousePrimaryButton_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t primaryButton = -1;
    ASSERT_TRUE(InputManager::GetInstance()->SetMousePrimaryButton(primaryButton) == RET_ERR);
}

/**
 * @tc.name: InputManagerTest_GetMousePrimaryButton_001
 * @tc.desc: Gets mouse primary button
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerTest, InputManagerTest_GetMousePrimaryButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t primaryButton = 1;
    if (InputManager::GetInstance()->SetMousePrimaryButton(primaryButton) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetMousePrimaryButton(primaryButton) == RET_OK);
        ASSERT_EQ(primaryButton, PrimaryButton::RIGHT_BUTTON);
    }
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_SetHoverScrollState_001
 * @tc.desc: Sets mouse hover scroll state in inactive window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetHoverScrollState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_TRUE(InputManager::GetInstance()->SetHoverScrollState(false) == RET_OK);
    InputManager::GetInstance()->SetHoverScrollState(true);
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_SetHoverScrollState_002
 * @tc.desc: Sets mouse hover scroll state in inactive window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetHoverScrollState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_TRUE(InputManager::GetInstance()->SetHoverScrollState(true) == RET_OK);
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_GetHoverScrollState_001
 * @tc.desc: Gets mouse hover scroll state in inactive window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerTest, InputManagerTest_GetHoverScrollState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool state = true;
    if (InputManager::GetInstance()->SetHoverScrollState(state) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetHoverScrollState(state) == RET_OK);
        ASSERT_TRUE(state);
    }
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_FunctionKeyState_001
 * @tc.desc: Set NumLock for the keyboard enablement state to true
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(InputManagerTest, InputManagerTest_FunctionKeyState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    InputManager::GetInstance()->SetFunctionKeyState(KeyEvent::UNKNOWN_FUNCTION_KEY, true);
    bool result = InputManager::GetInstance()->GetFunctionKeyState(KeyEvent::UNKNOWN_FUNCTION_KEY);
    ASSERT_FALSE(result);

    InputManager::GetInstance()->SetFunctionKeyState(KeyEvent::UNKNOWN_FUNCTION_KEY, false);
    result = InputManager::GetInstance()->GetFunctionKeyState(KeyEvent::UNKNOWN_FUNCTION_KEY);
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = 0;
    displayGroupInfo.width = 0;
    displayGroupInfo.height = 0;
    InputManager::GetInstance()->UpdateDisplayInfo(displayGroupInfo);
    ASSERT_TRUE(displayGroupInfo.displaysInfo.empty());
}

#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
/**
 * @tc.name: InputManagerTest_SetEnhanceConfig_001
 * @tc.desc: Set Secutity component enhance config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetEnhanceConfig_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputManager::GetInstance()->SetEnhanceConfig(nullptr);
}

/**
 * @tc.name: InputManagerTest_SetEnhanceConfig_002
 * @tc.desc: Set Secutity component enhance config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetEnhanceConfig_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Security::SecurityComponentEnhance::SecCompEnhanceCfg secCompEnhanceCfg;
    secCompEnhanceCfg.enable = false;
    InputManager::GetInstance()->SetEnhanceConfig(&secCompEnhanceCfg);
}

/**
 * @tc.name: InputManagerTest_SetEnhanceConfig_003
 * @tc.desc: Set Secutity component enhance config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetEnhanceConfig_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Security::SecurityComponentEnhance::SecCompEnhanceCfg secCompEnhanceCfg;
    secCompEnhanceCfg.enable = true;
    secCompEnhanceCfg.alg = static_cast<Security::SecurityComponentEnhance::HmacAlg>(HMAC_SHA384 + 1);
    InputManager::GetInstance()->SetEnhanceConfig(&secCompEnhanceCfg);
    delete[] secCompEnhanceCfg.key.data;
}

/**
 * @tc.name: InputManagerTest_SetEnhanceConfig_004
 * @tc.desc: Set Secutity component enhance config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetEnhanceConfig_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Security::SecurityComponentEnhance::SecCompEnhanceCfg secCompEnhanceCfg;
    secCompEnhanceCfg.enable = true;
    secCompEnhanceCfg.key.data = nullptr;
    secCompEnhanceCfg.alg = Security::SecurityComponentEnhance::HMAC_SHA384;
    InputManager::GetInstance()->SetEnhanceConfig(&secCompEnhanceCfg);
}

/**
 * @tc.name: InputManagerTest_SetEnhanceConfig_005
 * @tc.desc: Set Secutity component enhance config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetEnhanceConfig_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Security::SecurityComponentEnhance::SecCompEnhanceCfg secCompEnhanceCfg;
    secCompEnhanceCfg.enable = true;
    secCompEnhanceCfg.key.data = new (std::nothrow) uint8_t[DATA_ARRY_LEN];
    ASSERT_NE(secCompEnhanceCfg.key.data, nullptr);
    secCompEnhanceCfg.alg = Security::SecurityComponentEnhance::HMAC_SHA384;
    secCompEnhanceCfg.key.size = 0;
    InputManager::GetInstance()->SetEnhanceConfig(&secCompEnhanceCfg);
    delete[] secCompEnhanceCfg.key.data;
}

/**
 * @tc.name: InputManagerTest_SetEnhanceConfig_006
 * @tc.desc: Set Secutity component enhance config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetEnhanceConfig_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Security::SecurityComponentEnhance::SecCompEnhanceCfg secCompEnhanceCfg;
    secCompEnhanceCfg.enable = true;
    secCompEnhanceCfg.key.data = new (std::nothrow) uint8_t[DATA_ARRY_LEN];
    ASSERT_NE(secCompEnhanceCfg.key.data, nullptr);
    secCompEnhanceCfg.alg = Security::SecurityComponentEnhance::HMAC_SHA384;
    secCompEnhanceCfg.key.size = MAX_HMAC_SIZE + 1;
    InputManager::GetInstance()->SetEnhanceConfig(&secCompEnhanceCfg);
    delete[] secCompEnhanceCfg.key.data;
}

/**
 * @tc.name: InputManagerTest_SetEnhanceConfig_007
 * @tc.desc: Set Secutity component enhance config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetEnhanceConfig_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Security::SecurityComponentEnhance::SecCompEnhanceCfg secCompEnhanceCfg;
    secCompEnhanceCfg.enable = true;
    secCompEnhanceCfg.key.data = new (std::nothrow) uint8_t[DATA_ARRY_LEN];
    ASSERT_NE(secCompEnhanceCfg.key.data, nullptr);
    secCompEnhanceCfg.alg = Security::SecurityComponentEnhance::HMAC_SHA384;
    secCompEnhanceCfg.key.size = SHA384_KEY_LEN;
    InputManager::GetInstance()->SetEnhanceConfig(&secCompEnhanceCfg);
    delete[] secCompEnhanceCfg.key.data;
}
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT

/**
 * @tc.name: InputManagerTest_GetDevice_001
 * @tc.desc: Verify the fetch device info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_GetDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    auto callback = [](std::vector<int32_t> ids) {
        MMI_HILOGD("Get device success");
    };
    int32_t ret = InputManager::GetInstance()->GetDeviceIds(callback);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputManagerTest_EventTypeToString
 * @tc.desc: Verify inputevent interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_EventTypeToString, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    auto ret = inputEvent->EventTypeToString(InputEvent::EVENT_TYPE_BASE);
    ASSERT_STREQ(ret, "base");
    ret =  inputEvent->EventTypeToString(InputEvent::EVENT_TYPE_KEY);
    ASSERT_STREQ(ret, "key");
    ret =  inputEvent->EventTypeToString(InputEvent::EVENT_TYPE_AXIS);
    ASSERT_STREQ(ret, "axis");
    ret =  inputEvent->EventTypeToString(-1);
    ASSERT_STREQ(ret, "unknown");
}

/**
 * @tc.name: InputManagerTest_InputDeviceInterface_001
 * @tc.desc: Verify inputdevice interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_InputDeviceInterface_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    ASSERT_NE(inputDevice, nullptr);
    inputDevice->SetId(0);
    ASSERT_EQ(inputDevice->GetId(), 0);
    inputDevice->SetName("name");
    ASSERT_STREQ(inputDevice->GetName().c_str(), "name");
    inputDevice->SetType(0);
    ASSERT_EQ(inputDevice->GetType(), 0);
    inputDevice->SetBus(0);
    ASSERT_EQ(inputDevice->GetBus(), 0);
    inputDevice->SetVersion(0);
    ASSERT_EQ(inputDevice->GetVersion(), 0);
    inputDevice->SetProduct(0);
    ASSERT_EQ(inputDevice->GetProduct(), 0);
    inputDevice->SetVendor(0);
    ASSERT_EQ(inputDevice->GetVendor(), 0);
    inputDevice->SetPhys("phys");
    ASSERT_STREQ(inputDevice->GetPhys().c_str(), "phys");
    inputDevice->SetUniq("uniq");
    ASSERT_STREQ(inputDevice->GetUniq().c_str(), "uniq");
}

/**
 * @tc.name: InputManagerTest_InputDeviceInterface_002
 * @tc.desc: Verify inputdevice interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_InputDeviceInterface_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    ASSERT_NE(inputDevice, nullptr);
    InputDevice::AxisInfo axis;
    axis.SetAxisType(0);
    axis.SetMinimum(0);
    axis.SetMaximum(1);
    axis.SetFuzz(0);
    axis.SetFlat(1);
    axis.SetResolution(0);
    inputDevice->AddAxisInfo(axis);
    auto iter = inputDevice->GetAxisInfo();
    ASSERT_EQ(iter[0].GetAxisType(), 0);
    ASSERT_EQ(iter[0].GetMinimum(), 0);
    ASSERT_EQ(iter[0].GetMaximum(), 1);
    ASSERT_EQ(iter[0].GetFuzz(), 0);
    ASSERT_EQ(iter[0].GetFlat(), 1);
    ASSERT_EQ(iter[0].GetResolution(), 0);
}

/**
 * @tc.name: InputManagerTest_SetAnrObserver
 * @tc.desc: Verify the observer for events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetAnrObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetPressure(0.7);
    item.SetTiltX(10.0);
    item.SetTiltY(-9.0);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    item.SetToolType(PointerEvent::TOOL_TYPE_PEN);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
/**
 * @tc.name: InputManagerTest_InterceptTabletToolEvent_001
 * @tc.desc: Verify intercepting tablet tool event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_InterceptTabletToolEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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

#ifdef OHOS_BUILD_ENABLE_TOUCH
HWTEST_F(InputManagerTest, AppendExtraData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = GetPtr<InputEventConsumer>();
    ASSERT_TRUE(consumer != nullptr);
    const std::string threadTest = "EventUtilTest";
    auto runner = AppExecFwk::EventRunner::Create(threadTest);
    ASSERT_TRUE(runner != nullptr);
    auto eventHandler = std::make_shared<AppExecFwk::EventHandler>(runner);
    MMI::InputManager::GetInstance()->SetWindowInputEventConsumer(consumer, eventHandler);
    std::vector<uint8_t> buffer(512, 1);
    ExtraData extraData;
    extraData.appended = true;
    extraData.buffer = buffer;
    extraData.sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    extraData.pointerId = 1;
    InputManager::GetInstance()->AppendExtraData(extraData);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    auto pointerEvent = SetupPointerEvent001();
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent(pointerEvent, TestScene::EXCEPTION_TEST);

    extraData.appended = false;
    extraData.buffer.clear();
    extraData.pointerId = -1;
    InputManager::GetInstance()->AppendExtraData(extraData);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
HWTEST_F(InputManagerTest, AppendExtraData_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<uint8_t> buffer(512, 1);
    ExtraData extraData;
    extraData.appended = true;
    extraData.buffer = buffer;
    extraData.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    InputManager::GetInstance()->AppendExtraData(extraData);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    auto pointerEvent = SetupPointerEvent006();
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent(pointerEvent, TestScene::EXCEPTION_TEST);

    extraData.appended = false;
    extraData.buffer.clear();
    InputManager::GetInstance()->AppendExtraData(extraData);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER


/**
 * @tc.name: InputManagerTest_EnableInputDevice_001
 * @tc.desc: Enable input device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_EnableInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto ret = InputManager::GetInstance()->EnableInputDevice(false);
    ASSERT_EQ(ret, RET_OK);
    ret = InputManager::GetInstance()->EnableInputDevice(true);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputManagerTest_SetTouchpadScrollSwitch_001
 * @tc.desc: Set touch pad scroll switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetTouchpadScrollSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    ASSERT_TRUE(InputManager::GetInstance()->SetTouchpadScrollSwitch(flag) == RET_OK);
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_GetTouchpadScrollSwitch_001
 * @tc.desc: Get touch pad scroll switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_GetTouchpadScrollSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = true;
    InputManager::GetInstance()->SetTouchpadScrollSwitch(flag);
    bool newFlag = true;
    ASSERT_TRUE(InputManager::GetInstance()->GetTouchpadScrollSwitch(newFlag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_SetTouchpadScrollDirection_001
 * @tc.desc: Set touch pad scroll direct switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetTouchpadScrollDirection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool state = false;
    ASSERT_TRUE(InputManager::GetInstance()->SetTouchpadScrollDirection(state) == RET_OK);
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_GetTouchpadScrollDirection_001
 * @tc.desc: Get touch pad scroll direct switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_GetTouchpadScrollDirection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool state = true;
    InputManager::GetInstance()->SetTouchpadScrollDirection(state);
    bool newState = true;
    ASSERT_TRUE(InputManager::GetInstance()->GetTouchpadScrollDirection(newState) == RET_OK);
    ASSERT_TRUE(state == newState);
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_SetTouchpadTapSwitch_001
 * @tc.desc: Set touch pad tap switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetTouchpadTapSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    ASSERT_TRUE(InputManager::GetInstance()->SetTouchpadTapSwitch(flag) == RET_OK);
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_GetTouchpadTapSwitch_001
 * @tc.desc: Get touch pad tap switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_GetTouchpadTapSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = true;
    InputManager::GetInstance()->SetTouchpadTapSwitch(flag);
    bool newFlag = true;
    ASSERT_TRUE(InputManager::GetInstance()->GetTouchpadTapSwitch(newFlag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_SetTouchpadPointerSpeed_001
 * @tc.desc: Set touch pad pointer speed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetTouchpadPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t speed = 4;
    ASSERT_TRUE(InputManager::GetInstance()->SetTouchpadPointerSpeed(speed) == RET_OK);
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_GetTouchpadPointerSpeed_001
 * @tc.desc: Get touch pad scroll switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_GetTouchpadPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t speed = 5;
    InputManager::GetInstance()->SetTouchpadPointerSpeed(speed);
    int32_t newSpeed = 9;
    ASSERT_TRUE(InputManager::GetInstance()->GetTouchpadPointerSpeed(newSpeed) == RET_OK);
    ASSERT_TRUE(speed == newSpeed);
    const char *mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    ASSERT_TRUE(remove(mouseFileName) == RET_OK);
}

/**
 * @tc.name: InputManagerTest_SetMouseIcon_001
 * @tc.desc: Set the mouse icon for linux window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetMouseIcon_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    uint32_t windowId = window->GetWindowId();
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    PointerStyle pointerStyle;
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    ASSERT_TRUE(pixelMap != nullptr);
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    if (InputManager::GetInstance()->SetMouseIcon(windowId, (void*)pixelMap.get()) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle.id, MOUSE_ICON::DEVELOPER_DEFINED_ICON);
    } else {
        ASSERT_TRUE(false); // errors occur
    }
}

/**
 * @tc.name: InputManagerTest_SetMouseIcon_002
 * @tc.desc: Set the mouse icon for linux window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetMouseIcon_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    uint32_t windowId = window->GetWindowId();
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/Zoom_Out.svg";
    PointerStyle pointerStyle;
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    ASSERT_TRUE(pixelMap != nullptr);
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    if (InputManager::GetInstance()->SetMouseIcon(windowId, (void*)pixelMap.get()) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle.id, MOUSE_ICON::DEVELOPER_DEFINED_ICON);
    } else {
        ASSERT_TRUE(false); // errors occur
    }
}

/**
 * @tc.name: InputManagerTest_SetMouseIcon_003
 * @tc.desc: Set the mouse icon for linux window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerTest, InputManagerTest_SetMouseIcon_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    uint32_t windowId = window->GetWindowId();
    PointerStyle pointerStyle;
    pointerStyle.id = MOUSE_ICON::DEFAULT;
    int32_t ret = InputManager::GetInstance()->SetPointerStyle(windowId, pointerStyle);
    ASSERT_TRUE(ret == RET_OK);
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/Zoom_Out.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    ASSERT_TRUE(pixelMap != nullptr);
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ret = InputManager::GetInstance()->SetMouseIcon(-1, (void*)pixelMap.get());
    ASSERT_EQ(ret, RET_ERR);
    ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
    ASSERT_EQ(pointerStyle.id, MOUSE_ICON::DEFAULT);
}

} // namespace MMI
} // namespace OHOS
