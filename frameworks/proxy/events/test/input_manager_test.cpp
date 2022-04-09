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

#include <bitset>
#include <cinttypes>
#include <regex>
#include <sstream>

#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "run_shell_util.h"
#include "proto.h"

#include "input_event.h"
#include "input_event_monitor_manager.h"
#include "input_handler_type.h"
#include "input_manager.h"
#include "interceptor_manager.h"
#include "multimodal_event_handler.h"
#include "mmi_client.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t DEFAULT_DEVICE_ID = 1;
constexpr int32_t DEFAULT_POINTER_ID = 0;
constexpr int32_t NANOSECOND_TO_MILLISECOND = 1000000;
constexpr int32_t SEC_TO_NANOSEC = 1000000000;
constexpr int32_t TIME_WAIT_FOR_OP = 500;
constexpr int32_t TIME_WAIT_FOR_LOG = 100;
constexpr int32_t N_TRIES_FOR_LOG = 10;
constexpr int32_t INDEX_FIRST = 1;
constexpr int32_t INDEX_SECOND = 2;
constexpr int32_t INDEX_THIRD = 3;
constexpr int32_t MASK_BASE = 10;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputManagerTest" };
} // namespace

class InputManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    static int64_t GetNanoTime();
    static bool FindCommand(const std::string &log, const std::string &command);
    static std::vector<std::string> SearchLog(const std::string &command, bool noWait = false);
    static std::vector<std::string> SearchLog(const std::string &command,
    const std::vector<std::string> &excludes, bool noWait = false);
    static std::string DumpPointerItem(const PointerEvent::PointerItem &item);
    static std::string DumpPointerEvent(const std::shared_ptr<PointerEvent> &pointE);
    static std::shared_ptr<PointerEvent> SetupPointerEvent001();
    static std::shared_ptr<PointerEvent> SetupPointerEvent002();
    static std::shared_ptr<PointerEvent> SetupPointerEvent003();
    static std::shared_ptr<PointerEvent> SetupPointerEvent006();
    static std::shared_ptr<PointerEvent> SetupPointerEvent007();
    static std::shared_ptr<PointerEvent> SetupPointerEvent008();
    static std::shared_ptr<PointerEvent> SetupPointerEvent009();
    static std::shared_ptr<PointerEvent> SetupPointerEvent012();
    static void TestSimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent);
    static void TestSimulateInputEvent_2(std::shared_ptr<PointerEvent> pointerEvent);
    static std::string DumpPointerItem2(const PointerEvent::PointerItem &item);
    static std::string DumpPointerEvent2(const std::shared_ptr<PointerEvent> &pointE);
    static void TestInputEventInterceptor(std::shared_ptr<PointerEvent> pointerEvent);
    static void TestInputEventInterceptor2(std::shared_ptr<PointerEvent> pointerEvent);
    std::shared_ptr<PointerEvent> TestMarkConsumedStep1();
    std::shared_ptr<PointerEvent> TestMarkConsumedStep2();
    void TestMarkConsumedStep3(int32_t monitorId, int32_t eventId);
    void TestMarkConsumedStep4();
    void TestMarkConsumedStep5();
    void TestMarkConsumedStep6();
    static void KeyMonitorCallBack(std::shared_ptr<KeyEvent> keyEvent);
    static void TouchPadMonitorCallBack(std::shared_ptr<PointerEvent> pointerEvent);

private:
    static RunShellUtil runCommand_;
};

RunShellUtil InputManagerTest::runCommand_ { };

int64_t InputManagerTest::GetNanoTime()
{
    struct timespec time = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &time);
    return static_cast<int64_t>(time.tv_sec) * SEC_TO_NANOSEC + time.tv_nsec;
}

class InputEventCallback : public IInputEventConsumer {
public:
    virtual void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override
    {
        MMI_HILOGD("keyCode:%{public}d", keyEvent->GetKeyCode());
    }
    virtual void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
    {
        MMI_HILOGD("PointerEvent received.");
    }
    virtual void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override {}
    static std::shared_ptr<InputEventCallback> GetPtr();
};

std::shared_ptr<InputEventCallback> InputEventCallback::GetPtr()
{
    return std::make_shared<InputEventCallback>();
}

bool InputManagerTest::FindCommand(const std::string &log, const std::string &command)
{
    std::ostringstream sCmd;
    std::string::size_type spos { 0 }, tpos;
    while (spos < command.size()) {
        tpos = command.find("\\", spos);
        if (tpos != std::string::npos) {
            if (((tpos + 1) < command.size()) &&
                (('{' == command[tpos + 1]) || ('}' == command[tpos + 1]))) {
                sCmd << command.substr(spos, tpos - spos);
            } else {
                sCmd << command.substr(spos, tpos - spos + 1);
            }
            spos = tpos + 1;
        } else {
            sCmd << command.substr(spos);
            spos = command.size();
        }
    }

    std::regex pattern(sCmd.str());
    return std::regex_search(log, pattern);
}

std::vector<std::string> InputManagerTest::SearchLog(const std::string &command, bool noWait)
{
    std::vector<std::string> excludes;
    return SearchLog(command, excludes, noWait);
}

std::vector<std::string> InputManagerTest::SearchLog(const std::string &command,
    const std::vector<std::string> &excludes, bool noWait)
{
    int32_t nTries { N_TRIES_FOR_LOG };
    std::vector<std::string> results;

    while (true) {
        std::vector<std::string> logs;
        (void)runCommand_.RunShellCommand(command, logs);
        for (const std::string& s : logs) {
            if (FindCommand(s, command) &&
                (std::find(excludes.cbegin(), excludes.cend(), s) == excludes.cend())) {
                results.push_back(s);
            }
        }
        if (noWait || !results.empty() || (--nTries <= 0)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_LOG));
    }
    return results;
}

std::shared_ptr<PointerEvent> InputManagerTest::TestMarkConsumedStep1()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetGlobalX(823);   // test code，set the GlobalX = 823
    item.SetGlobalY(723);   // test code，set the GlobalY = 723
    item.SetPressure(5);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetId(std::numeric_limits<int32_t>::max() - INDEX_THIRD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    MMI_HILOGD("Call InputManager::SimulatePointerEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::TestMarkConsumedStep2()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetGlobalX(1023);  // test code，set the GlobalX = 823
    item.SetGlobalY(723);   // test code，set the GlobalY = 723
    item.SetPressure(5);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetId(std::numeric_limits<int32_t>::max() - INDEX_SECOND);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    MMI_HILOGD("Call InputManager::SimulatePointerEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    return pointerEvent;
}

void InputManagerTest::TestMarkConsumedStep3(int32_t monitorId, int32_t eventId)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    std::string command {
        "ClientMsgHandler: in OnPointerEvent, #[[:digit:]]\\{1,\\}, "
        "Operation canceled"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    MMI_HILOGD("Call InputManager::MarkConsumed");
    InputManager::GetInstance()->MarkConsumed(monitorId, eventId);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

void InputManagerTest::TestMarkConsumedStep4()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetGlobalX(1123);  // test code，set the GlobalX = 823
    item.SetGlobalY(723);   // test code，set the GlobalY = 723
    item.SetPressure(5);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetId(std::numeric_limits<int32_t>::max() - INDEX_FIRST);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    std::string command {
        "InputHandlerManagerGlobal: in HandleEvent, #[[:digit:]]\\{1,\\}, "
        "Pointer event was monitor"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    MMI_HILOGD("Call InputManager::SimulatePointerEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

void InputManagerTest::TestMarkConsumedStep5()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetGlobalX(0);  // test code，set the GlobalX = 823
    item.SetGlobalY(0);   // test code，set the GlobalY = 723
    item.SetPressure(0);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetId(std::numeric_limits<int32_t>::max());
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(0);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    std::string command {
        "InputHandlerManagerGlobal: in HandleEvent, #[[:digit:]]\\{1,\\}, "
        "Pointer event was monitor"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    MMI_HILOGD("Call InputManager::SimulatePointerEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

void InputManagerTest::TestMarkConsumedStep6()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetGlobalX(823);   // test code，set the GlobalX = 823
    item.SetGlobalY(723);   // test code，set the GlobalY = 723
    item.SetPressure(5);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetId(std::numeric_limits<int32_t>::max());
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    std::string command {
        "InputManagerImpl: in OnPointerEvent, #[[:digit:]]\\{1,\\}, "
        "Pointer event received, processing"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    MMI_HILOGD("Call InputManager::SimulatePointerEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

/**
 * @tc.name:MultimodalEventHandler_InjectKeyEvent_001
 * @tc.desc:Verify inject key Back
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_InjectKeyEvent_001, TestSize.Level1)
{
    std::string command = "Inject keyCode:2, action:2";
    std::vector<std::string> slogs {SearchLog(command, true)};
    int64_t downTime = GetNanoTime()/NANOSECOND_TO_MILLISECOND;
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_NE(injectDownEvent, nullptr);
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_BACK);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);

    std::shared_ptr<KeyEvent> injectUpEvent = KeyEvent::Create();
    ASSERT_NE(injectUpEvent, nullptr);
    downTime = GetNanoTime()/NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitUp;
    kitUp.SetKeyCode(KeyEvent::KEYCODE_BACK);
    kitUp.SetPressed(false);
    kitUp.SetDownTime(downTime);
    injectUpEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    injectUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
    InputManager::GetInstance()->SimulateInputEvent(injectUpEvent);
    std::vector<std::string> tlogs {SearchLog(command, slogs)};
    EXPECT_TRUE(!tlogs.empty());
}

/**
 * @tc.name:MultimodalEventHandler_InjectKeyEvent_002
 * @tc.desc:Verify inject key home
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_InjectKeyEvent_002, TestSize.Level1)
{
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_NE(injectDownEvent, nullptr);
    int64_t downTime = -1;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_HOME);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);
}

/**
 * @tc.name:MultimodalEventHandler_InjectKeyEvent_003
 * @tc.desc:Verify inject key down
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_InjectKeyEvent_003, TestSize.Level1)
{
    std::string command = "Inject keyCode:2, action:2";
    std::vector<std::string> slogs {SearchLog(command, true)};
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_NE(injectDownEvent, nullptr);
    int64_t downTime = 0;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_BACK);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);

    std::shared_ptr<KeyEvent> injectUpEvent = KeyEvent::Create();
    ASSERT_NE(injectUpEvent, nullptr);
    KeyEvent::KeyItem kitUp;
    kitUp.SetKeyCode(KeyEvent::KEYCODE_BACK);
    kitUp.SetPressed(false);
    kitUp.SetDownTime(downTime);
    injectUpEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    injectUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
    InputManager::GetInstance()->SimulateInputEvent(injectUpEvent);
    std::vector<std::string> tlogs {SearchLog(command, slogs)};
    EXPECT_TRUE(!tlogs.empty());
}

/**
 * @tc.name:MultimodalEventHandler_InjectKeyEvent_004
 * @tc.desc:Verify inject key unknown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_InjectKeyEvent_004, TestSize.Level1)
{
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_NE(injectDownEvent, nullptr);
    int64_t downTime = GetNanoTime()/NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    MMI_HILOGD("MMIEventHdl.InjectEvent begin");
    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);
    MMI_HILOGD("MMIEventHdl.InjectEvent end");
}

/**
 * @tc.name:MultimodalEventHandler_InjectKeyEvent_005
 * @tc.desc:Verify inject key fn
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, MultimodalEventHandler_InjectKeyEvent_005, TestSize.Level1)
{
    std::string command = "Inject keyCode:0, action:2";
    std::vector<std::string> slogs {SearchLog(command, true)};
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_NE(injectDownEvent, nullptr);
    int64_t downTime = GetNanoTime()/NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_FN);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_FN);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    if (injectDownEvent == nullptr) {
        MMI_HILOGD("injectDownEvent is nullptr!");
    }
    MMI_HILOGD("MMIEventHdl.InjectEvent begin!");
    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);
    MMI_HILOGD("MMIEventHdl.InjectEvent end!");

    std::shared_ptr<KeyEvent> injectUpEvent = KeyEvent::Create();
    ASSERT_NE(injectUpEvent, nullptr);
    downTime = GetNanoTime()/NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitUp;
    kitUp.SetKeyCode(KeyEvent::KEYCODE_FN);
    kitUp.SetPressed(false);
    kitUp.SetDownTime(downTime);
    injectUpEvent->SetKeyCode(KeyEvent::KEYCODE_FN);
    injectUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
    InputManager::GetInstance()->SimulateInputEvent(injectUpEvent);
    std::vector<std::string> tlogs {SearchLog(command, slogs)};
    EXPECT_TRUE(!tlogs.empty());
}

std::string InputManagerTest::DumpPointerItem(const PointerEvent::PointerItem &item)
{
    std::ostringstream strm;
    strm << "ClientMsgHandler: in OnPointerEvent, #[[:digit:]]\\{1,\\}, DownTime:" << item.GetDownTime()
         << ",IsPressed:" << std::boolalpha << item.IsPressed() << ",GlobalX:" << item.GetGlobalX()
         << ",GlobalY:" << item.GetGlobalY()
         << ",LocalX:-\\{0,1\\}[[:digit:]]\\{1,\\},LocalY:-\\{0,1\\}[[:digit:]]\\{1,\\}"
         << ",Width:" << item.GetWidth() << ",Height:" << item.GetHeight()
         << ",Pressure:" << item.GetPressure();
    return strm.str();
}

std::string InputManagerTest::DumpPointerEvent(const std::shared_ptr<PointerEvent> &pointerEvent)
{
    const int precision = 2;
    std::ostringstream strm;
    strm << "ClientMsgHandler: in OnPointerEvent, #[[:digit:]]\\{1,\\}"
         << ", EventType:" << pointerEvent->GetEventType()
         << ",ActionTime:" << pointerEvent->GetActionTime()
         << ",Action:" << pointerEvent->GetAction()
         << ",ActionStartTime:" << pointerEvent->GetActionStartTime()
         << ",Flag:" << pointerEvent->GetFlag()
         << ",PointerAction:" << pointerEvent->DumpPointerAction()
         << ",SourceType:" << pointerEvent->DumpSourceType()
         << ",VerticalAxisValue:" << std::fixed << std::setprecision(precision)
         << pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)
         << ",HorizontalAxisValue:" << std::fixed << std::setprecision(precision)
         << pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL);
    return strm.str();
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent001()
{
    auto pointerEvent = PointerEvent::Create();
    if (pointerEvent == nullptr) {
        MMI_HILOGD("out of memory.");
        return pointerEvent;
    }
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetGlobalX(823);   // test code，set the GlobalX = 823
    item.SetGlobalY(723);   // test code，set the GlobalY = 723
    item.SetPressure(5);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);   // test code，set the PointerId = 1
    item.SetGlobalX(1010);   // test code，set the GlobalX = 1010
    item.SetGlobalY(910);   // test code，set the GlobalY = 910
    item.SetPressure(7);    // test code，set the Pressure = 7
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(1);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent002()
{
    auto pointerEvent = PointerEvent::Create();
    if (pointerEvent == nullptr) {
        MMI_HILOGD("out of memory.");
        return pointerEvent;
    }
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetGlobalX(823);   // test code，set the GlobalX = 823
    item.SetGlobalY(723);   // test code，set the GlobalY = 723
    item.SetPressure(5);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);   // test code，set the PointerId = 1
    item.SetGlobalX(1000);   // test code，set the GlobalX = 1000
    item.SetGlobalY(610);   // test code，set the GlobalY = 610
    item.SetPressure(7);    // test code，set the Pressure = 7
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(1);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent003()
{
    auto pointerEvent = PointerEvent::Create();
    if (pointerEvent == nullptr) {
        MMI_HILOGD("out of memory.");
        return pointerEvent;
    }
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetGlobalX(823);   // test code，set the GlobalX = 823
    item.SetGlobalY(723);   // test code，set the GlobalY = 723
    item.SetPressure(5);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);   // test code，set the PointerId = 1
    item.SetGlobalX(0);   // test code，set the GlobalX = 0
    item.SetGlobalY(0);   // test code，set the GlobalY = 0
    item.SetPressure(0);    // test code，set the Pressure = 0
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(1);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

void InputManagerTest::TestSimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_LOG_ENTER;
    PointerEvent::PointerItem item;
    pointerEvent->GetPointerItem(0, item);
    std::string sItem1 { DumpPointerItem(item) };
    std::vector<std::string> sLogItem1s { SearchLog(sItem1, true) };
    MMI_HILOGD("sItem1:%{public}s", sItem1.c_str());

    pointerEvent->GetPointerItem(1, item);
    std::string sItem2 { DumpPointerItem(item) };
    std::vector<std::string> sLogItem2s { SearchLog(sItem2, true) };
    MMI_HILOGD("sItem2:%{public}s", sItem2.c_str());

    std::string sPointeE { DumpPointerEvent(pointerEvent) };
    std::vector<std::string> sLogPointerEs { SearchLog(sPointeE, true) };
    MMI_HILOGD("sPointerE:%{public}s", sPointeE.c_str());

    std::string sCmd {
        "InputManagerImpl: in OnPointerEvent, #[[:digit:]]\\{1,\\}, "
        "Pointer event received, processing"
    };
    std::vector<std::string> sLogs { SearchLog(sCmd, true) };

    MMI_HILOGD("Call InputManager::SimulateInputEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    int32_t nTries { N_TRIES_FOR_LOG };
    std::bitset<4> states { };

    while (true) {
        if (!states.test(0)) {
            std::vector<std::string> tLogPointerEs { SearchLog(sPointeE, sLogPointerEs, true) };
            if (!tLogPointerEs.empty()) {
                states.set(0);
            }
        }
        if (!states.test(1)) {
            std::vector<std::string> tLogItem1s { SearchLog(sItem1, sLogItem1s, true) };
            if (!tLogItem1s.empty()) {
                states.set(1);
            }
        }
        if (!states.test(2)) {
            std::vector<std::string> tLogItem2s { SearchLog(sItem2, sLogItem2s, true) };
            if (!tLogItem2s.empty()) {
                states.set(2);
            }
        }
        if (!states.test(3)) {
            std::vector<std::string> tLogs { SearchLog(sCmd, sLogs, true) };
            if (!tLogs.empty()) {
                states.set(3);
            }
        }
        if (states.all() || (--nTries <= 0)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_LOG));
    }
    EXPECT_TRUE(states.all());
    EXPECT_TRUE(states.test(0));
    EXPECT_TRUE(states.test(1));
    EXPECT_TRUE(states.test(2));
    EXPECT_TRUE(states.test(3));
}

/**
 * @tc.name:InputManager_SimulateInputEvent_001
 * @tc.desc:Verify Simulate pointer down event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_001, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManager_SimulateInputEvent_001");
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent001() };
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent(pointerEvent);
}

/**
 * @tc.name:InputManager_SimulateInputEvent_002
 * @tc.desc:Verify Simulate pointer move event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_002, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManager_SimulateInputEvent_002");
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent002() };
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent(pointerEvent);
}

/**
 * @tc.name:InputManager_SimulateInputEvent_003
 * @tc.desc:Verify Simulate pointer up event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_003, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManager_SimulateInputEvent_003");
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent002() };
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent(pointerEvent);
}

/**
 * @tc.name:InputManager_SimulateInputEvent_004
 * @tc.desc:Verify Simulate pointer event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_004, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManager_SimulateInputEvent_004");
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(-1);

    std::string command {
        "InputWindowsManager: in UpdateTouchScreenTarget, #[[:digit:]]\\{1,\\}, "
        "Can.t find pointer item, pointer:"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    MMI_HILOGD("Call InputManager::SimulateInputEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

void InputManagerTest::TestSimulateInputEvent_2(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_LOG_ENTER;
    PointerEvent::PointerItem item;
    pointerEvent->GetPointerItem(1, item);
    std::string sItem1 { DumpPointerItem(item) };
    std::vector<std::string> sLogItem1s { SearchLog(sItem1, true) };
    MMI_HILOGD("sItem1:%{public}s", sItem1.c_str());

    std::string sPointeE { DumpPointerEvent(pointerEvent) };
    std::vector<std::string> sLogPointerEs { SearchLog(sPointeE, true) };
    MMI_HILOGD("sPointerE:%{public}s", sPointeE.c_str());

    std::string sCmd {
        "InputManagerImpl: in OnPointerEvent, #[[:digit:]]\\{1,\\}, "
        "Pointer event received, processing"
    };
    std::vector<std::string> sLogs { SearchLog(sCmd, true) };

    MMI_HILOGD("Call InputManager::SimulateInputEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    int32_t nTries { N_TRIES_FOR_LOG };
    // 这里主要测试以下两方面：
    //   (1) 客户端可以成功接收到事件；
    //   (2) 客户端接收到的事件结构的各个字段与初始设置的值一致；
    // 为此，这里有三项测试：
    //   (1) PointerEvent记录的按下手指的数据的各字段与设置的值是一致的；
    //   (2) PointerEvent结构各字段的值与设置的值是一致的；
    //   (3) 客户端成功接收到PointerEvent事件；
    // 这三项测试各自成功与否依次由states[0]、states[1]和states[2]标识；
    std::bitset<3> states { };

    while (true) {
        if (!states.test(0)) {
            // 搜索日志，匹配PointerEvent事件结构的数据；
            std::vector<std::string> tLogPointerEs { SearchLog(sPointeE, sLogPointerEs, true) };
            if (!tLogPointerEs.empty()) {
                states.set(0);
            }
        }
        if (!states.test(1)) {
            // 搜索日志，匹配按下手指的数据；
            std::vector<std::string> tLogItem1s { SearchLog(sItem1, sLogItem1s, true) };
            if (!tLogItem1s.empty()) {
                states.set(1);
            }
        }
        if (!states.test(2)) {
            // 搜索标识客户端成功接收到事件的关键性日志；
            std::vector<std::string> tLogs { SearchLog(sCmd, sLogs, true) };
            if (!tLogs.empty()) {
                states.set(2);
            }
        }
        if (states.all() || (--nTries <= 0)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_LOG));
    }
    EXPECT_TRUE(states.all());
    EXPECT_TRUE(states.test(0));
    EXPECT_TRUE(states.test(1));
    EXPECT_TRUE(states.test(2));
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent006()
{
    auto pointerEvent = PointerEvent::Create();
    if (pointerEvent == nullptr) {
        MMI_HILOGD("out of memory.");
        return pointerEvent;
    }
    int64_t downTime = GetNanoTime()/NANOSECOND_TO_MILLISECOND;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(downTime);
    item.SetPressed(true);

    item.SetGlobalX(10);
    item.SetGlobalY(10);
    item.SetLocalX(20);
    item.SetLocalY(20);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent007()
{
    auto pointerEvent = PointerEvent::Create();
    if (pointerEvent == nullptr) {
        MMI_HILOGD("out of memory.");
        return pointerEvent;
    }
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(0);
    item.SetPressed(false);

    item.SetGlobalX(50);
    item.SetGlobalY(50);
    item.SetLocalX(70);
    item.SetLocalY(70);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent008()
{
    auto pointerEvent = PointerEvent::Create();
    if (pointerEvent == nullptr) {
        MMI_HILOGD("out of memory.");
        return pointerEvent;
    }
    int64_t downTime = GetNanoTime()/NANOSECOND_TO_MILLISECOND;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(downTime);
    item.SetPressed(false);

    item.SetGlobalX(50);
    item.SetGlobalY(50);
    item.SetLocalX(70);
    item.SetLocalY(70);

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
    if (pointerEvent == nullptr) {
        MMI_HILOGD("out of memory.");
        return pointerEvent;
    }
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, -1.0000);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(0);
    item.SetPressed(false);

    item.SetGlobalX(50);
    item.SetGlobalY(50);
    item.SetLocalX(70);
    item.SetLocalY(70);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

/**
 * @tc.name:InputManager_SimulateInputEvent_006
 * @tc.desc:Verify simulate mouse event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_006, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManager_SimulateInputEvent_006");
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent006() };
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent_2(pointerEvent);
}

/**
 * @tc.name:InputManager_SimulateInputEvent_007
 * @tc.desc:Verify simulate mouse event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_007, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManager_SimulateInputEvent_007");
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent007() };
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent_2(pointerEvent);
}

/**
 * @tc.name:InputManager_SimulateInputEvent_008
 * @tc.desc:Verify simulate mouse event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_008, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManager_SimulateInputEvent_008");
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent008() };
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent_2(pointerEvent);
}

/**
 * @tc.name:InputManager_SimulateInputEvent_009
 * @tc.desc:Verify simulate mouse event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_009, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManager_SimulateInputEvent_009");
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent009() };
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent_2(pointerEvent);
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent012()
{
    auto pointerEvent = PointerEvent::Create();
    if (pointerEvent == nullptr) {
        MMI_HILOGD("out of memory.");
        return pointerEvent;
    }
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 30.0);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, 40.0);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(0);
    item.SetPressed(false);

    item.SetGlobalX(200);
    item.SetGlobalY(200);
    item.SetLocalX(300);
    item.SetLocalY(300);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}

/**
 * @tc.name:InputManager_SimulateInputEvent_012
 * @tc.desc:Verify simulate mouse event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_012, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManager_SimulateInputEvent_012");
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent012() };
    ASSERT_TRUE(pointerEvent != nullptr);
    TestSimulateInputEvent_2(pointerEvent);
}

/**
 * @tc.name:InputManager_SimulateInputEvent_013
 * @tc.desc:Verify simulate mouse event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_013, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManager_SimulateInputEvent_013");
    std::string command = "PointerAction:axis-begin";
    std::vector<std::string> sLogs { SearchLog(command, true) };

    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 30.0);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(0);
    item.SetPressed(false);

    item.SetGlobalX(200);
    item.SetGlobalY(200);
    item.SetLocalX(300);
    item.SetLocalY(300);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    MMI_HILOGD("Inject POINTER_ACTION_AXIS_BEGIN");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

/**
 * @tc.name:InputManager_SimulateInputEvent_014
 * @tc.desc:Verify simulate mouse event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_014, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManager_SimulateInputEvent_014");
    std::string command = "PointerAction:axis-update";
    std::vector<std::string> sLogs { SearchLog(command, true) };

    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 30.0);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(0);
    item.SetPressed(false);

    item.SetGlobalX(200);
    item.SetGlobalY(200);
    item.SetLocalX(300);
    item.SetLocalY(300);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    MMI_HILOGD("Inject POINTER_ACTION_AXIS_UPDATE");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

/**
 * @tc.name:InputManager_SimulateInputEvent_015
 * @tc.desc:Verify simulate mouse event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_015, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManager_SimulateInputEvent_015");
    std::string command = "PointerAction:axis-end";
    std::vector<std::string>  sLogs { SearchLog(command, true) };

    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 30.0);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(0);
    item.SetPressed(false);

    item.SetGlobalX(200);
    item.SetGlobalY(200);
    item.SetLocalX(300);
    item.SetLocalY(300);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);

    MMI_HILOGD("Inject POINTER_ACTION_AXIS_END");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}


/**
 * @tc.name:InputManager_ANR_TEST
 * @tc.desc: detection of ANR
 * @tc.type: FUNC
 * @tc.require:AR000GJG6G
 */
HWTEST_F(InputManagerTest, InputManager_ANR_TEST_001, TestSize.Level1)
{
    MMI_HILOGD("start InputManager_ANR_TEST_001");
    std::this_thread::sleep_for(std::chrono::milliseconds(20000));
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetPressure(5);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(-1);
    pointerEvent->SetPointerId(0);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    MMI_HILOGD("InputManager_ANR_TEST_001 wait 2s");
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    item.SetPointerId(1);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetPressure(5);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(-1);
    pointerEvent->SetPointerId(1);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    MMI_HILOGD("InputManager_ANR_TEST_001 wait 5s");
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));

    item.SetPointerId(2);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetPressure(5);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(-1);
    pointerEvent->SetPointerId(2);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}

/**
 * @tc.name:InputManager_ANR_TEST
 * @tc.desc: detection of ANR
 * @tc.type: FUNC
 * @tc.require:SR000GGN6G
 */
HWTEST_F(InputManagerTest, InputManager_ANR_TEST_002, TestSize.Level1)
{
    MMI_HILOGD("start InputManager_ANR_TEST_002");
    std::this_thread::sleep_for(std::chrono::milliseconds(20000));
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetPressure(5);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(-1);
    pointerEvent->SetPointerId(0);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    MMI_HILOGD("InputManager_ANR_TEST_001 wait 2s");
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    item.SetPointerId(1);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetPressure(5);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(-1);
    pointerEvent->SetPointerId(1);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    MMI_HILOGD("InputManager_ANR_TEST_001 wait 5s");
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));

    item.SetPointerId(2);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetPressure(5);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(-1);
    pointerEvent->SetPointerId(2);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}

void InputManagerTest::KeyMonitorCallBack(std::shared_ptr<KeyEvent> keyEvent)
{
    MMI_HILOGD("KeyMonitorCallBack: keyCode:%{public}d,keyAction:%{public}d,action:%{public}d,"
               "actionTime:%{public}" PRId64 "", keyEvent->GetKeyCode(), keyEvent->GetKeyAction(),
             keyEvent->GetAction(), keyEvent->GetActionTime());
    EXPECT_EQ(keyEvent->GetKeyCode(), KeyEvent::KEYCODE_BACK);
    EXPECT_EQ(keyEvent->GetKeyAction(), KeyEvent::KEY_ACTION_UP);
    EXPECT_EQ(keyEvent->GetAction(), KeyEvent::KEY_ACTION_UP);
    EXPECT_EQ(keyEvent->GetDeviceId(), 0);
}

/**
 * @tc.name:InputManagerTest_AddHandler_001
 * @tc.desc:Verify monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddHandler_001, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManagerTest_AddHandler_001");
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    std::string command {
        "InputHandlerManagerGlobal: in AddMonitor, #[[:digit:]]\\{1,\\}, "
        "Service AddMonitor Success"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    MMI_HILOGD("InputManagerTest_AddHandler_001");
    int32_t id1 = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(id1));

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    if (IsValidHandlerId(id1)) {
        InputManager::GetInstance()->RemoveMonitor(id1);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name:InputManagerTest_AddHandler_002
 * @tc.desc:Verify monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddHandler_002, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManagerTest_AddHandler_002");
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    int32_t id1 = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(id1));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    std::string command {
        "InputHandlerManagerGlobal: in RemoveMonitor, #[[:digit:]]\\{1,\\}, "
        "Service RemoveMonitor Success"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };
    MMI_HILOGD("InputManagerTest_AddHandler_002");
    if (IsValidHandlerId(id1)) {
        InputManager::GetInstance()->RemoveMonitor(id1);
    }
    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

/**
 * @tc.name:InputManagerTest_AddHandler_003
 * @tc.desc:Verify monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddHandler_003, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManagerTest_AddHandler_003");
    const std::vector<int32_t>::size_type N_TEST_CASES { 3 };
    std::vector<int32_t> ids(N_TEST_CASES);
    std::vector<std::shared_ptr<InputEventCallback>> cbs(N_TEST_CASES);

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        cbs[i] = InputEventCallback::GetPtr();
        EXPECT_TRUE(cbs[i] != nullptr);
        ids[i] = InputManager::GetInstance()->AddMonitor(cbs[i]);
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    std::string command {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "PointerEvent received"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    auto pointerEvent = SetupPointerEvent001();
    MMI_HILOGD("InputManagerTest_AddHandler_003");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    int32_t nTries { N_TRIES_FOR_LOG };
    std::vector<std::string> rLogs;

    while (true) {
        std::vector<std::string> tLogs { SearchLog(command, sLogs, true) };
        rLogs.insert(rLogs.end(), tLogs.begin(), tLogs.end());
        if ((rLogs.size() >= N_TEST_CASES) || (--nTries <= 0)) {
            break;
        }
        sLogs.insert(sLogs.end(), tLogs.begin(), tLogs.end());
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_LOG));
    }
    EXPECT_TRUE(rLogs.size() >= N_TEST_CASES);

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        if (IsValidHandlerId(ids[i])) {
            InputManager::GetInstance()->RemoveMonitor(ids[i]);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }
}

/**
 * @tc.name:InputManagerTest_AddHandler_004
 * @tc.desc:Verify monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddHandler_004, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManagerTest_AddHandler_004");
    std::string command {
        "InputHandlerManager: in AddHandler, #[[:digit:]]\\{1,\\}, "
        "The number of handlers exceeds the maximum"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    const std::vector<int32_t>::size_type N_TEST_CASES { MAX_N_INPUT_HANDLERS };
    std::vector<int32_t> ids(N_TEST_CASES);
    std::shared_ptr<InputEventCallback> cb = InputEventCallback::GetPtr();
    EXPECT_TRUE(cb != nullptr);

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        ids[i] = InputManager::GetInstance()->AddMonitor(cb);
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
    MMI_HILOGD("InputManagerTest_AddHandler_004");
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(cb);
    EXPECT_TRUE(!IsValidHandlerId(monitorId));

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        if (IsValidHandlerId(ids[i])) {
            InputManager::GetInstance()->RemoveMonitor(ids[i]);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }
}

/**
 * @tc.name:InputManagerTest_AddHandler_005
 * @tc.desc:Verify monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddHandler_005, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManagerTest_AddHandler_005");
    RunShellUtil runCommand;
    std::shared_ptr<InputEventCallback> cb = InputEventCallback::GetPtr();
    EXPECT_TRUE(cb != nullptr);
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(cb);
    EXPECT_TRUE(IsValidHandlerId(monitorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    MMI_HILOGD("InputManagerTest_AddHandler_005");
    TestMarkConsumedStep1();
    auto pointerEvent = TestMarkConsumedStep2();
    TestMarkConsumedStep3(monitorId / MASK_BASE, pointerEvent->GetId());
    TestMarkConsumedStep4();
    TestMarkConsumedStep5();

    if (IsValidHandlerId(monitorId)) {
        InputManager::GetInstance()->RemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name:InputManagerTest_AddHandler_006
 * @tc.desc:Verify monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddHandler_006, TestSize.Level1)
{
    CALL_LOG_ENTER;
    MMI_HILOGD("start InputManagerTest_AddHandler_006");
    RunShellUtil runCommand;
    std::shared_ptr<InputEventCallback> cb = InputEventCallback::GetPtr();
    EXPECT_TRUE(cb != nullptr);
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(cb);
    EXPECT_TRUE(IsValidHandlerId(monitorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    MMI_HILOGD("InputManagerTest_AddHandler_006");
    auto pointerEvent = TestMarkConsumedStep1();
    TestMarkConsumedStep3(monitorId / MASK_BASE, pointerEvent->GetId());
    TestMarkConsumedStep4();
    TestMarkConsumedStep6();

    if (IsValidHandlerId(monitorId)) {
        InputManager::GetInstance()->RemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name:InputManagerTest_SubscribeKeyEvent_008
 * @tc.desc:Verify invalid parameter.
 * @tc.type: FUNC
 * @tc.require:SR000GGQL4  AR000GJNGN
 * @tc.author: yangguang
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_008, TestSize.Level1)
{
    MMI_HILOGD("start InputManagerTest_SubscribeKeyEvent_008");
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
}

/**
 * @tc.name:InputManagerTest_SubscribeKeyEvent_010
 * @tc.desc:Verify subscribe power key event.
 * @tc.type: FUNC
 * @tc.require:SR000GGQL4  AR000GJNGN
 * @tc.author: zhaoxueyuan
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_010, TestSize.Level1)
{
    if (!MMIEventHdl.StartClient()) {
        MMI_HILOGD("get mmi client failed");
        return;
    }
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
        MMI_HILOGD("KeyEvent:%{public}d,KeyCode:%{public}d,ActionTime:%{public}" PRId64 ","
                   "ActionStartTime:%{public}" PRId64 ",Action:%{public}d,KeyAction:%{public}d,"
                   "EventType:%{public}d,flag:%{public}u",
                   keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                   keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                   keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_HILOGD("subscribe key event KEYCODE_POWER down trigger callback");
    });
    EXPECT_TRUE(subscribeId1 >= 0);

    // 电源键抬起订阅
    std::shared_ptr<KeyOption> keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetPreKeys(preKeys);
    keyOption2->SetFinalKey(KeyEvent::KEYCODE_POWER);
    keyOption2->SetFinalKeyDown(false);
    keyOption2->SetFinalKeyDownDuration(0);
    int32_t subscribeId2 = -1;
    subscribeId2 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption2,
        [](std::shared_ptr<KeyEvent> keyEvent) {
        MMI_HILOGD("KeyEvent:%{public}d,KeyCode:%{public}d,ActionTime:%{public}" PRId64 ","
                   "ActionStartTime:%{public}" PRId64 ",Action:%{public}d,KeyAction:%{public}d,"
                   "EventType:%{public}d,flag:%{public}u",
                   keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                   keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                   keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_HILOGD("subscribe key event KEYCODE_POWER up trigger callback");
    });
    EXPECT_TRUE(subscribeId2 >= 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(10000));
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId1);
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId2);
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));
}

class InputEventInterceptor : public IInputEventConsumer {
public:
    virtual void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override { }
    virtual void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override;
    virtual void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override {}
    static std::shared_ptr<IInputEventConsumer> GetPtr();
};

void InputEventInterceptor::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    std::vector<int32_t> pointerIds { pointerEvent->GetPointersIdList() };
    MMI_HILOGD("Pointer event intercepted:");
    MMI_HILOGD("eventType:%{public}s,actionTime:%{public}" PRId64 ","
               "action:%{public}d,actionStartTime:%{public}" PRId64 ","
               "flag:%{public}u,pointerAction:%{public}s,sourceType:%{public}s,"
               "VerticalAxisValue:%{public}.2f,HorizontalAxisValue:%{public}.2f,"
               "pointerCount:%{public}zu",
               InputEvent::EventTypeToString(pointerEvent->GetEventType()), pointerEvent->GetActionTime(),
               pointerEvent->GetAction(), pointerEvent->GetActionStartTime(),
               pointerEvent->GetFlag(), pointerEvent->DumpPointerAction(),
               pointerEvent->DumpSourceType(),
               pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
               pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL),
               pointerIds.size());
    for (int32_t pointerId : pointerIds) {
        PointerEvent::PointerItem item;
        if (!pointerEvent->GetPointerItem(pointerId, item)) {
            MMI_HILOGE("Can't find the pointer item data, pointer:%{public}d, errCode:%{public}d",
                       pointerId, PARAM_INPUT_FAIL);
            return;
        }

        MMI_HILOGD("downTime:%{public}" PRId64 ",isPressed:%{public}s,"
                   "globalX:%{public}d,globalY:%{public}d,pressure:%{public}d",
                   item.GetDownTime(),
                   item.IsPressed() ? "true" : "false",
                   item.GetGlobalX(),
                   item.GetGlobalY(),
                   item.GetPressure());
    }
}

std::shared_ptr<IInputEventConsumer> InputEventInterceptor::GetPtr()
{
    return std::make_shared<InputEventInterceptor>();
}

std::string InputManagerTest::DumpPointerItem2(const PointerEvent::PointerItem &item)
{
    std::ostringstream strm;
    strm << "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, downTime:" << item.GetDownTime()
         << ",isPressed:" << std::boolalpha << item.IsPressed() << ",globalX:" << item.GetGlobalX()
         << ",globalY:" << item.GetGlobalY() << ",pressure:" << item.GetPressure();
    return strm.str();
}

std::string InputManagerTest::DumpPointerEvent2(const std::shared_ptr<PointerEvent> &pointerEvent)
{
    const int precision = 2;
    std::ostringstream strm;
    strm << "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
         << "eventType:" << pointerEvent->GetEventType()
         << ",actionTime:" << pointerEvent->GetActionTime()
         << ",action:" << pointerEvent->GetAction()
         << ",actionStartTime:" << pointerEvent->GetActionStartTime()
         << ",flag:" << pointerEvent->GetFlag()
         << ",pointerAction:" << pointerEvent->DumpPointerAction()
         << ",sourceType:" << pointerEvent->DumpSourceType()
         << ",VerticalAxisValue:" << std::fixed << std::setprecision(precision)
         << pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)
         << ",HorizontalAxisValue:" << std::fixed << std::setprecision(precision)
         << pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL);
    return strm.str();
}

void InputManagerTest::TestInputEventInterceptor(std::shared_ptr<PointerEvent> pointerEvent)
{
    std::string sCmd {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "Pointer event intercepted:"
    };
    std::vector<std::string> sLogs { SearchLog(sCmd, true) };

    std::string sPointeE { DumpPointerEvent2(pointerEvent) };
    std::vector<std::string> sLogPointerEs { SearchLog(sPointeE, true) };
    MMI_HILOGD("sPointerE:%{public}s", sPointeE.c_str());

    PointerEvent::PointerItem item;
    EXPECT_TRUE(pointerEvent->GetPointerItem(DEFAULT_POINTER_ID, item));
    std::string sItem1 { DumpPointerItem2(item) };
    std::vector<std::string> sLogItem1s { SearchLog(sItem1, true) };
    MMI_HILOGD("sItem1:%{public}s", sItem1.c_str());

    MMI_HILOGD("Call InputManager::SimulateInputEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    int32_t nTries { N_TRIES_FOR_LOG };
    // 这里主要测试以下两方面：
    //   (1) 拦截器可以成功接收到事件；
    //   (2) 拦截器接收到的事件结构的各个字段与初始设置的值一致；
    // 为此，这里有三项测试：
    //   (1) 拦截器成功接收到PointerEvent事件；
    //   (2) PointerEvent记录的按下手指的数据的各字段与设置的值是一致的；
    //   (3) PointerEvent结构各字段的值与设置的值是一致的；
    // 这三项测试各自成功与否依次由states[0]、states[1]和states[2]标识；
    std::bitset<3> states { };

    while (true) {
        if (!states.test(0)) {
            // 搜索标识拦截器成功接收到事件的关键性日志；
            std::vector<std::string> tLogs { SearchLog(sCmd, sLogs, true) };
            if (!tLogs.empty()) {
                states.set(0);
            }
        }
        if (!states.test(1)) {
            // 搜索日志，匹配PointerEvent事件结构的数据；
            std::vector<std::string> tLogPointerEs { SearchLog(sPointeE, sLogPointerEs, true) };
            if (!tLogPointerEs.empty()) {
                states.set(1);
            }
        }
        if (!states.test(2)) {
            // 搜索日志，匹配按下手指的数据；
            std::vector<std::string> tLogItem1s { SearchLog(sItem1, sLogItem1s, true) };
            if (!tLogItem1s.empty()) {
                states.set(2);
            }
        }
        if (states.all() || (--nTries <= 0)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_LOG));
    }
    EXPECT_TRUE(states.all());
    EXPECT_TRUE(states.test(0));
    EXPECT_TRUE(states.test(1));
    EXPECT_TRUE(states.test(2));
}

/**
 * @tc.name:TestInputEventInterceptor_001
 * @tc.desc:Verify interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_001, TestSize.Level1)
{
    MMI_HILOGD("start TestInputEventInterceptor_001");
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(10010);
    item.SetPressed(true);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);

    std::shared_ptr<IInputEventConsumer> interceptor { InputEventInterceptor::GetPtr() };
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    TestInputEventInterceptor(pointerEvent);
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name:TestInputEventInterceptor_002
 * @tc.desc:Verify interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_002, TestSize.Level1)
{
    MMI_HILOGD("start TestInputEventInterceptor_002");
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10010);
    item.SetPressed(true);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    MMI_HILOGD("Call InterceptorManager");

    const std::vector<int32_t>::size_type N_TEST_CASES { 3 };
    std::vector<int32_t> ids(N_TEST_CASES);
    std::shared_ptr<IInputEventConsumer> interceptor { InputEventInterceptor::GetPtr() };

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        ids[i] = InputManager::GetInstance()->AddInterceptor(interceptor);
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    std::string command {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "Pointer event intercepted"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    int32_t nTries { N_TRIES_FOR_LOG };
    std::vector<std::string> rLogs;

    while (true) {
        std::vector<std::string> tLogs { SearchLog(command, sLogs, true) };
        rLogs.insert(rLogs.end(), tLogs.begin(), tLogs.end());
        if ((rLogs.size() >= N_TEST_CASES) || (--nTries <= 0)) {
            break;
        }
        sLogs.insert(sLogs.end(), tLogs.begin(), tLogs.end());
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_LOG));
    }
    EXPECT_TRUE(rLogs.size() >= N_TEST_CASES);

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        if (IsValidHandlerId(ids[i])) {
            InputManager::GetInstance()->RemoveInterceptor(ids[i]);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }
}

/**
 * @tc.name:TestInputEventInterceptor_003
 * @tc.desc:Verify interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_003, TestSize.Level1)
{
    MMI_HILOGD("start TestInputEventInterceptor_003");
    const std::vector<int32_t>::size_type N_TEST_CASES { 3 };
    std::vector<int32_t> ids(N_TEST_CASES);
    std::shared_ptr<IInputEventConsumer> interceptor { InputEventInterceptor::GetPtr() };

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        ids[i] = InputManager::GetInstance()->AddInterceptor(interceptor);
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    std::string command {
        "InputHandlerManagerGlobal: in RemoveInterceptor, #[[:digit:]]\\{1,\\}, "
        "Unregister interceptor successfully"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        if (IsValidHandlerId(ids[i])) {
            InputManager::GetInstance()->RemoveInterceptor(ids[i]);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }

    int32_t nTries { N_TRIES_FOR_LOG };
    std::vector<std::string> rLogs;

    while (true) {
        std::vector<std::string> tLogs { SearchLog(command, sLogs, true) };
        rLogs.insert(rLogs.end(), tLogs.begin(), tLogs.end());
        if ((rLogs.size() >= N_TEST_CASES) || (--nTries <= 0)) {
            break;
        }
        sLogs.insert(sLogs.end(), tLogs.begin(), tLogs.end());
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_LOG));
    }
    EXPECT_TRUE(rLogs.size() >= N_TEST_CASES);
}

/**
 * @tc.name:TestInputEventInterceptor_004
 * @tc.desc:Verify interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_004, TestSize.Level1)
{
    MMI_HILOGD("start TestInputEventInterceptor_004");
    std::string command {
        "InputManagerImpl: in AddInterceptor, #[[:digit:]]\\{1,\\}, "
        "CHKPR.interceptor. is null, return value is -1"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    std::shared_ptr<IInputEventConsumer> interceptor;
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
    EXPECT_TRUE(!IsValidHandlerId(interceptorId));

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

/**
 * @tc.name:TestInputEventInterceptor_005
 * @tc.desc:Verify interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_005, TestSize.Level1)
{
    MMI_HILOGD("start TestInputEventInterceptor_005");
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    PointerEvent::PointerItem item;
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    item.SetPressed(true);
    item.SetGlobalX(200);
    item.SetGlobalY(300);
    pointerEvent->AddPointerItem(item);

    std::shared_ptr<IInputEventConsumer> interceptor { InputEventInterceptor::GetPtr() };
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    TestInputEventInterceptor(pointerEvent);
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

void InputManagerTest::TestInputEventInterceptor2(std::shared_ptr<PointerEvent> pointerEvent)
{
    std::string sCmd {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "Pointer event intercepted:"
    };
    std::vector<std::string> sLogs { SearchLog(sCmd, true) };

    std::string sPointeE { DumpPointerEvent2(pointerEvent) };
    std::vector<std::string> sLogPointerEs { SearchLog(sPointeE, true) };

    PointerEvent::PointerItem item;
    pointerEvent->GetPointerItem(0, item);
    std::string sItem1 { DumpPointerItem2(item) };
    std::vector<std::string> sLogItem1s { SearchLog(sItem1, true) };

    pointerEvent->GetPointerItem(1, item);
    std::string sItem2 { DumpPointerItem2(item) };
    std::vector<std::string> sLogItem2s { SearchLog(sItem2, true) };

    MMI_HILOGD("Call InputManager::SimulateInputEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    int32_t nTries { N_TRIES_FOR_LOG };
    std::bitset<4> states { };

    while (true) {
        if (!states.test(0)) {
            std::vector<std::string> tLogs { SearchLog(sCmd, sLogs, true) };
            if (!tLogs.empty()) {
                states.set(0);
            }
        }
        if (!states.test(1)) {
            std::vector<std::string> tLogPointerEs { SearchLog(sPointeE, sLogPointerEs, true) };
            if (!tLogPointerEs.empty()) {
                states.set(1);
            }
        }
        if (!states.test(2)) {
            std::vector<std::string> tLogItem1s { SearchLog(sItem1, sLogItem1s, true) };
            if (!tLogItem1s.empty()) {
                states.set(2);
            }
        }
        if (!states.test(3)) {
            std::vector<std::string> tLogItem2s { SearchLog(sItem2, sLogItem2s, true) };
            if (!tLogItem2s.empty()) {
                states.set(3);
            }
        }
        if (states.all() || (--nTries <= 0)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_LOG));
    }
    EXPECT_TRUE(states.all());
}

/**
 * @tc.name:TestInputEventInterceptor_006
 * @tc.desc:Verify interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, TestInputEventInterceptor_006, TestSize.Level1)
{
    MMI_HILOGD("start TestInputEventInterceptor_006");
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetGlobalX(823);   // test code，set the GlobalX = 823
    item.SetGlobalY(723);   // test code，set the GlobalY = 723
    item.SetPressure(5);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);   // test code，set the PointerId = 1
    item.SetGlobalX(1010);   // test code，set the GlobalX = 1010
    item.SetGlobalY(910);   // test code，set the GlobalY = 910
    item.SetPressure(7);    // test code，set the Pressure = 7
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(1);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    std::shared_ptr<IInputEventConsumer> interceptor { InputEventInterceptor::GetPtr() };
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    TestInputEventInterceptor2(pointerEvent);
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

void InputManagerTest::TouchPadMonitorCallBack(std::shared_ptr<PointerEvent> pointerEvent)
{
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerId, pointerItem);
    MMI_HILOGD("TouchPadMonitorCallBack: pointerAction:%{public}d,pointerId:%{public}d,"
        "x:%{public}d,y:%{public}d", pointerEvent->GetPointerAction(),
        pointerEvent->GetPointerId(), pointerItem.GetGlobalX(), pointerItem.GetGlobalY());
}

/**
 * @tc.name:InputManagerTest_OnAddTouchPadMonitor_001
 * @tc.desc:Verify touchpad monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_001, TestSize.Level1)
{
    MMI_HILOGD("start InputManagerTest_OnAddTouchPadMonitor_001");
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10010);
    item.SetPressed(true);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    MMI_HILOGD("Call MontiorManager");

    std::string command { "PointerEvent received" };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    int32_t monitorId { };
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    monitorId = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(monitorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int32_t response = MMIEventHdl.InjectPointerEvent(pointerEvent);
    EXPECT_EQ(RET_OK, response);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManagerTest_OnAddTouchPadMonitor_002
 * @tc.desc:Verify touchpad monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_002, TestSize.Level1)
{
    MMI_HILOGD("start InputManagerTest_OnAddTouchPadMonitor_002");
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10010);
    item.SetPressed(true);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    MMI_HILOGD("Call MontiorManager");

    std::string command { "PointerEvent received" };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    int32_t monitorId { };
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    monitorId = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(monitorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int32_t response = MMIEventHdl.InjectPointerEvent(pointerEvent);
    EXPECT_EQ(RET_OK, response);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManagerTest_OnAddTouchPadMonitor_003
 * @tc.desc:Verify touchpad monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_003, TestSize.Level1)
{
    MMI_HILOGD("start InputManagerTest_OnAddTouchPadMonitor_003");
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10010);
    item.SetPressed(true);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    MMI_HILOGD("Call MontiorManager");

    std::string command { "PointerEvent received" };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    int32_t monitorId { };
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    monitorId = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(monitorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int32_t response = MMIEventHdl.InjectPointerEvent(pointerEvent);
    EXPECT_EQ(RET_OK, response);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManagerTest_OnAddTouchPadMonitor_004
 * @tc.desc:Verify touchpad monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_004, TestSize.Level1)
{
    MMI_HILOGD("start InputManagerTest_OnAddTouchPadMonitor_004");
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10010);
    item.SetPressed(true);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    MMI_HILOGD("Call MontiorManager");

    const std::vector<int32_t>::size_type N_TEST_CASES { 3 };
    std::vector<int32_t> ids(N_TEST_CASES);

    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        ids[i] = InputManager::GetInstance()->AddMonitor(callBackPtr);
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    std::string command {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "PointerEvent received"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    int32_t nTries { N_TRIES_FOR_LOG };
    std::vector<std::string> rLogs;

    while (true) {
        std::vector<std::string> tLogs { SearchLog(command, sLogs, true) };
        rLogs.insert(rLogs.end(), tLogs.begin(), tLogs.end());
        if ((rLogs.size() >= N_TEST_CASES) || (--nTries <= 0)) {
            break;
        }
        sLogs.insert(sLogs.end(), tLogs.begin(), tLogs.end());
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_LOG));
    }
    EXPECT_TRUE(rLogs.size() >= N_TEST_CASES);

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        InputManager::GetInstance()->RemoveMonitor(ids[i]);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name:InputManagerTest_OnAddTouchPadMonitor_005
 * @tc.desc:Verify touchpad monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_005, TestSize.Level1)
{
    MMI_HILOGD("start InputManagerTest_OnAddTouchPadMonitor_005");
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(10010);
    item.SetPressed(true);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(-1);
    MMI_HILOGD("Call MontiorManager");

    std::string command {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "PointerEvent received"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    int32_t monitorId { };
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    monitorId = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(monitorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int32_t response = MMIEventHdl.InjectPointerEvent(pointerEvent);
    EXPECT_EQ(RET_OK, response);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManager_TouchPadSimulateInputEvent_001
 * @tc.desc:Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_001, TestSize.Level1)
{
    MMI_HILOGD("start InputManager_TouchPadSimulateInputEvent_001");
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    int32_t monitorId { InputManager::GetInstance()->AddMonitor(callBackPtr) };
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t actionTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item { };
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetActionTime(actionTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);

    std::string command {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "PointerEvent received"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    MMI_HILOGD("Call InputManager::SimulateInputEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManager_TouchPadSimulateInputEvent_002
 * @tc.desc:Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_002, TestSize.Level1)
{
    MMI_HILOGD("start InputManager_TouchPadSimulateInputEvent_002");
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    int32_t monitorId { InputManager::GetInstance()->AddMonitor(callBackPtr) };
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t actionTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item { };
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetGlobalX(1000);
    item.SetGlobalY(610);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetActionTime(actionTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);

    std::string command {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "PointerEvent received"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    MMI_HILOGD("Call InputManager::SimulateInputEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManager_TouchPadSimulateInputEvent_003
 * @tc.desc:Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_003, TestSize.Level1)
{
    MMI_HILOGD("start InputManager_TouchPadSimulateInputEvent_003");
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    int32_t monitorId { InputManager::GetInstance()->AddMonitor(callBackPtr) };
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t actionTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item { };
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(actionTime);
    item.SetPressed(false);
    item.SetGlobalX(0);
    item.SetGlobalY(0);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetActionTime(actionTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);

    std::string command {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "PointerEvent received"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    MMI_HILOGD("Call InputManager::SimulateInputEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManager_TouchPadSimulateInputEvent_004
 * @tc.desc:Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_004, TestSize.Level1)
{
    MMI_HILOGD("start InputManager_TouchPadSimulateInputEvent_004");
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    int32_t monitorId { InputManager::GetInstance()->AddMonitor(callBackPtr) };
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t actionTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item { };
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetGlobalX(840);
    item.SetGlobalY(740);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(2);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetGlobalX(860);
    item.SetGlobalY(760);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetActionTime(actionTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);

    std::string command {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "PointerEvent received"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    MMI_HILOGD("Call InputManager::SimulateInputEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManagerTest_AddMouseMonitor_001
 * @tc.desc:Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_001, TestSize.Level1)
{
    MMI_HILOGD("start InputManagerTest_AddMouseMonitor_001");
    std::string command {
        "InputHandlerManagerGlobal: in AddMonitor, #[[:digit:]]\\{1,\\}, "
        "Service AddMonitor Success"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    int32_t id1 = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(id1));
    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    if (IsValidHandlerId(id1)) {
        InputManager::GetInstance()->RemoveMonitor(id1);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name:InputManagerTest_AddMouseMonitor_002
 * @tc.desc:Verify mouse monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_002, TestSize.Level1)
{
    MMI_HILOGD("start InputManagerTest_AddMouseMonitor_002");
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);

    int32_t id1 = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(id1));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    std::string command {
        "InputHandlerManagerGlobal: in RemoveMonitor, #[[:digit:]]\\{1,\\}, "
        "Service RemoveMonitor Success"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };
    if (IsValidHandlerId(id1)) {
        InputManager::GetInstance()->RemoveMonitor(id1);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

/**
 * @tc.name:InputManagerTest_AddMouseMonitor_003
 * @tc.desc:Verify mouse monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_003, TestSize.Level1)
{
    MMI_HILOGD("start InputManagerTest_AddMouseMonitor_003");
    std::string command {
        "InputHandlerManager: in AddHandler, #[[:digit:]]\\{1,\\}, "
        "The number of handlers exceeds the maximum"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    const std::vector<int32_t>::size_type N_TEST_CASES { MAX_N_INPUT_HANDLERS };
    std::vector<int32_t> ids(N_TEST_CASES);
    std::shared_ptr<InputEventCallback> cb = InputEventCallback::GetPtr();
    EXPECT_TRUE(cb != nullptr);

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        ids[i] = InputManager::GetInstance()->AddMonitor(cb);
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    int32_t monitorId = InputManager::GetInstance()->AddMonitor(cb);
    EXPECT_TRUE(!IsValidHandlerId(monitorId));
    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        if (IsValidHandlerId(ids[i])) {
            InputManager::GetInstance()->RemoveMonitor(ids[i]);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }
}

/**
 * @tc.name:InputManagerTest_AddMouseMonitor_004
 * @tc.desc:Verify mouse monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_004, TestSize.Level1)
{
    MMI_HILOGD("start InputManagerTest_AddMouseMonitor_004");
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    int32_t id1 = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(id1));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    std::string command {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "PointerEvent received"
    };
    std::vector<std::string> sLogs { SearchLog(command, true) };

    auto pointerEvent = SetupPointerEvent006();
    EXPECT_TRUE(pointerEvent != nullptr);
    MMI_HILOGD("Call InputManager::SimulateInputEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
    if (IsValidHandlerId(id1)) {
        InputManager::GetInstance()->RemoveMonitor(id1);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}
} // namespace MMI
} // namespace OHOS