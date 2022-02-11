/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "input_manager.h"
#include "error_multimodal.h"
#include <bitset>
#include <regex>
#include <sstream>
#include <gtest/gtest.h>
#include "define_multimodal.h"
#include "input_handler_type.h"
#include "input_event_monitor_manager.h"
#include "interceptor_manager.h"
#include "input_manager.h"
#include "key_event_pre.h"
#include "multimodal_event_handler.h"
#include "pointer_event.h"
#include "proto.h"
#include "run_shell_util.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace MMI;
namespace {
constexpr int32_t HOS_KEY_BACK = 2;
constexpr bool ACTION_DOWN = true;
constexpr bool ACTION_UP = false;
constexpr int32_t DEFAULT_DEVICE_ID = 1;
constexpr int32_t DEFAULT_POINTER_ID = 0;
constexpr int32_t NANOSECOND_TO_MILLISECOND = 1000000;
constexpr int32_t SEC_TO_NANOSEC = 1000000000;
constexpr int32_t TIME_WAIT_FOR_OP = 500;
constexpr int32_t TIME_WAIT_FOR_LOG = 50;
constexpr int32_t N_TRIES_FOR_LOG = 20;
constexpr bool ISINTERCEPTED_TRUE = true;
constexpr int32_t INDEX_FIRST = 1;
constexpr int32_t INDEX_SECOND = 2;
constexpr int32_t INDEX_THIRD = 3;
constexpr int32_t INDEX_INVALID = -1;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputManagerTest" };
}

class InputManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    static int64_t GetNanoTime();
    static bool FindCommand(const std::string &log, const std::string &command);
    static std::vector<std::string> SearchForLog(const std::string &command, bool noWait = false);
    static std::vector<std::string> SearchForLog(const std::string &command,
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
    static void KeyMonitorCallBack(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent);
    static void TouchPadMonitorCallBack(std::shared_ptr<OHOS::MMI::PointerEvent> pointerEvent);

private:
    static RunShellUtil runCommand_;
};

RunShellUtil InputManagerTest::runCommand_ { };

int64_t InputManagerTest::GetNanoTime()
{
    timespec time = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &time);
    return static_cast<uint64_t>(time.tv_sec) * SEC_TO_NANOSEC + time.tv_nsec;
}

class InputEventCallback : public OHOS::MMI::IInputEventConsumer {
public:
    virtual void OnInputEvent(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent) const override
    {
        MMI_LOGT("OnInputEvent keyCode = %{public}d", keyEvent->GetKeyCode());
    }
    virtual void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
    {
        MMI_LOGT("PointerEvent received.");
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

std::vector<std::string> InputManagerTest::SearchForLog(const std::string &command, bool noWait)
{
    std::vector<std::string> excludes;
    return SearchForLog(command, excludes, noWait);
}

std::vector<std::string> InputManagerTest::SearchForLog(const std::string &command,
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
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetGlobalX(823);   // test code，set the GlobalX = 823
    item.SetGlobalY(723);   // test code，set the GlobalY = 723
    item.SetPressure(5);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    MMI_LOGD("Call InputManager::SimulatePointerEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputManagerTest::TestMarkConsumedStep2()
{
    auto pointerEvent = PointerEvent::Create();
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetGlobalX(1023);  // test code，set the GlobalX = 823
    item.SetGlobalY(723);   // test code，set the GlobalY = 723
    item.SetPressure(5);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetId(2);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    MMI_LOGD("Call InputManager::SimulatePointerEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    return pointerEvent;
}

void InputManagerTest::TestMarkConsumedStep3(int32_t monitorId, int32_t eventId)
{
    std::string command {
        "ClientMsgHandler: in OnPointerEvent, #[[:digit:]]\\{1,\\}, "
        "Operation canceled." 
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    MMI_LOGD("Call InputManager::MarkConsumed ...");
    InputManager::GetInstance()->MarkConsumed(monitorId, eventId);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

void InputManagerTest::TestMarkConsumedStep4()
{
    auto pointerEvent = PointerEvent::Create();
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetGlobalX(1123);  // test code，set the GlobalX = 823
    item.SetGlobalY(723);   // test code，set the GlobalY = 723
    item.SetPressure(5);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetId(3);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    std::string command {
        "EventDispatch: in handlePointerEvent, #[[:digit:]]\\{1,\\}, "
        "PointerEvent consumed,will not send to client."
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    MMI_LOGD("Call InputManager::SimulatePointerEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

void InputManagerTest::TestMarkConsumedStep5()
{
    auto pointerEvent = PointerEvent::Create();
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetGlobalX(0);  // test code，set the GlobalX = 823
    item.SetGlobalY(0);   // test code，set the GlobalY = 723
    item.SetPressure(0);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetId(3);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(0);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    std::string command {
        "EventDispatch: in handlePointerEvent, #[[:digit:]]\\{1,\\}, "
        "PointerEvent consumed,will not send to client."
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    MMI_LOGD("Call InputManager::SimulatePointerEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

void InputManagerTest::TestMarkConsumedStep6()
{
    auto pointerEvent = PointerEvent::Create();
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code，set the PointerId = 0
    item.SetGlobalX(823);   // test code，set the GlobalX = 823
    item.SetGlobalY(723);   // test code，set the GlobalY = 723
    item.SetPressure(5);    // test code，set the Pressure = 5
    item.SetDeviceId(1);    // test code，set the DeviceId = 1
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetId(4);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);  // test code，set the PointerId = 1
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    std::string command {
        "ClientMsgHandler: in OnPointerEvent, #[[:digit:]]\\{1,\\}, "
        "pointer event dispatcher of client:"
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    MMI_LOGD("Call InputManager::SimulatePointerEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

HWTEST_F(InputManagerTest, InputManagerTest_SetWindowInputEventConsumer_001, TestSize.Level1)
{
    std::string command = "ServerStartTime =";
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    InputManager::GetInstance()->SetWindowInputEventConsumer(callBackPtr);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    OHOS::KeyEvent injectDownEvent;
    int64_t downTime = static_cast<int64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_TRUE(response);

    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<int64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    EXPECT_TRUE(response);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

std::string InputManagerTest::DumpPointerItem(const PointerEvent::PointerItem &item)
{
    std::ostringstream strm;
    strm << "ClientMsgHandler: in OnPointerEvent, #[[:digit:]]\\{1,\\}, downTime=" << item.GetDownTime()
         << ",isPressed=" << std::boolalpha << item.IsPressed() << ",globalX=" << item.GetGlobalX()
         << ",globalY=" << item.GetGlobalY()
         << ",localX=-\\{0,1\\}[[:digit:]]\\{1,\\},localY=-\\{0,1\\}[[:digit:]]\\{1,\\}"
         << ",width=" << item.GetWidth() << ",height=" << item.GetHeight()
         << ",pressure=" << item.GetPressure();
    return strm.str();
}

std::string InputManagerTest::DumpPointerEvent(const std::shared_ptr<PointerEvent> &pointerEvent)
{
    const int precision = 2;
    std::ostringstream strm;
    strm << "ClientMsgHandler: in OnPointerEvent, #[[:digit:]]\\{1,\\}, eventType="
         << pointerEvent->GetEventType()
         << ",actionTime=" << pointerEvent->GetActionTime()
         << ",action=" << pointerEvent->GetAction()
         << ",actionStartTime=" << pointerEvent->GetActionStartTime()
         << ",flag=" << pointerEvent->GetFlag()
         << ",pointerAction=" << pointerEvent->GetPointerAction()
         << ",sourceType=" << pointerEvent->GetSourceType()
         << ",VerticalAxisValue=" << std::fixed << std::setprecision(precision)
         << pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)
         << ",HorizontalAxisValue=" << std::fixed << std::setprecision(precision)
         << pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL);
    return strm.str();
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent001()
{
    auto pointerEvent = PointerEvent::Create();
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
    PointerEvent::PointerItem item;
    pointerEvent->GetPointerItem(0, item);
    std::string sItem1 { DumpPointerItem(item) };
    std::vector<std::string> sLogItem1s { SearchForLog(sItem1, true) };
    MMI_LOGD("sItem1 = %{public}s", sItem1.c_str());

    pointerEvent->GetPointerItem(1, item);
    std::string sItem2 { DumpPointerItem(item) };
    std::vector<std::string> sLogItem2s { SearchForLog(sItem2, true) };
    MMI_LOGD("sItem2 = %{public}s", sItem2.c_str());

    std::string sPointeE { DumpPointerEvent(pointerEvent) };
    std::vector<std::string> sLogPointerEs { SearchForLog(sPointeE, true) };
    MMI_LOGD("sPointerE = %{public}s", sPointeE.c_str());

    std::string sCmd {
        "InputManagerImpl: in OnPointerEvent, #[[:digit:]]\\{1,\\}, "
        "Pointer event received, processing ..."
    };
    std::vector<std::string> sLogs { SearchForLog(sCmd, true) };

    MMI_LOGD("Call InputManager::SimulateInputEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    int32_t nTries { N_TRIES_FOR_LOG };
    std::bitset<4> states { };

    while (true) {
        if (!states.test(0)) {
            std::vector<std::string> tLogItem1s { SearchForLog(sItem1, sLogItem1s, true) };
            if (!tLogItem1s.empty()) {
                states.set(0);
            }
        }
        if (!states.test(1)) {
            std::vector<std::string> tLogItem2s { SearchForLog(sItem2, sLogItem2s, true) };
            if (!tLogItem2s.empty()) {
                states.set(1);
            }
        }
        if (!states.test(2)) {
            std::vector<std::string> tLogPointerEs { SearchForLog(sPointeE, sLogPointerEs, true) };
            if (!tLogPointerEs.empty()) {
                states.set(2);
            }
        }
        if (!states.test(3)) {
            std::vector<std::string> tLogs { SearchForLog(sCmd, sLogs, true) };
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

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_001, TestSize.Level1)
{
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent001() };
    TestSimulateInputEvent(pointerEvent);
}

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_002, TestSize.Level1)
{
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent002() };
    TestSimulateInputEvent(pointerEvent);
}

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_003, TestSize.Level1)
{
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent002() };
    TestSimulateInputEvent(pointerEvent);
}

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_004, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(-1);

    std::string command {
        "InputWindowsManager: in UpdateTouchScreenTarget, #[[:digit:]]\\{1,\\}, "
        "Can.t find pointer item, pointer:"
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    MMI_LOGD("Call InputManager::SimulateInputEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_005, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetPressure(5);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(-1);
    pointerEvent->SetPointerId(0);

    std::string command {
        "EventDispatch: in HandlePointerEvent, #[[:digit:]]\\{1,\\}, "
        "Unknown source type!"
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    MMI_LOGD("Call InputManager::SimulateInputEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

HWTEST_F(InputManagerTest, InputManager_ANR_TEST_001, TestSize.Level1)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(20000));
    auto pointerEvent = PointerEvent::Create();

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
    MMI_LOGD("InputManager_ANR_TEST_001 wait 2s");
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
    MMI_LOGD("InputManager_ANR_TEST_001 wait 5s");
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

void InputManagerTest::TestSimulateInputEvent_2(std::shared_ptr<PointerEvent> pointerEvent)
{
    PointerEvent::PointerItem item;
    pointerEvent->GetPointerItem(1, item);
    std::string sItem1 { DumpPointerItem(item) };
    std::vector<std::string> sLogItem1s { SearchForLog(sItem1, true) };
    MMI_LOGD("sItem1 = %{public}s", sItem1.c_str());

    std::string sPointeE { DumpPointerEvent(pointerEvent) };
    std::vector<std::string> sLogPointerEs { SearchForLog(sPointeE, true) };
    MMI_LOGD("sPointerE = %{public}s", sPointeE.c_str());

    std::string sCmd {
        "InputManagerImpl: in OnPointerEvent, #[[:digit:]]\\{1,\\}, "
        "Pointer event received, processing ..."
    };
    std::vector<std::string> sLogs { SearchForLog(sCmd, true) };

    MMI_LOGD("Call InputManager::SimulateInputEvent ...");
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
            // 搜索日志，匹配按下手指的数据；
            std::vector<std::string> tLogItem1s { SearchForLog(sItem1, sLogItem1s, true) };
            if (!tLogItem1s.empty()) {
                states.set(0);
            }
        }
        if (!states.test(1)) {
            // 搜索日志，匹配PointerEvent事件结构的数据；
            std::vector<std::string> tLogPointerEs { SearchForLog(sPointeE, sLogPointerEs, true) };
            if (!tLogPointerEs.empty()) {
                states.set(1);
            }
        }
        if (!states.test(2)) {
            // 搜索标识客户端成功接收到事件的关键性日志；
            std::vector<std::string> tLogs { SearchForLog(sCmd, sLogs, true) };
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
    int64_t downTime = static_cast<int64_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(downTime);
    item.SetPressed(true);

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

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent007()
{
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(1);
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

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent008()
{
    auto pointerEvent = PointerEvent::Create();
    int64_t downTime = static_cast<int64_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(downTime);
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

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent009()
{
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, -1.0000);
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

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_006, TestSize.Level1)
{
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent006() };
    TestSimulateInputEvent_2(pointerEvent);
}

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_007, TestSize.Level1)
{
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent007() };
    TestSimulateInputEvent_2(pointerEvent);
}

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_008, TestSize.Level1)
{
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent008() };
    TestSimulateInputEvent_2(pointerEvent);
}

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_009, TestSize.Level1)
{
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent009() };
    TestSimulateInputEvent_2(pointerEvent);
}

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_010, TestSize.Level1)
{
    std::string command {
        "EventDispatch: in HandlePointerEvent, #[[:digit:]]\\{1,\\}, "
        "Unknown source type!"
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    auto pointerEvent = PointerEvent::Create();
    int64_t downTime = static_cast<int64_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    pointerEvent->SetSourceType(-1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    PointerEvent::PointerItem item;
    item.SetDownTime(downTime);
    item.SetPressed(true);

    item.SetGlobalX(200);
    item.SetGlobalY(200);
    item.SetLocalX(300);
    item.SetLocalY(300);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);

    MMI_LOGD("Call InputManager::SimulateInputEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_011, TestSize.Level1)
{
    std::string command {
        "EventDispatch: in handlePointerEvent, #[[:digit:]]\\{1,\\}, "
        "Unknown source type!" 
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    auto pointerEvent = PointerEvent::Create();
    int64_t downTime = static_cast<int64_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    PointerEvent::PointerItem item;
    item.SetDownTime(downTime);
    item.SetPressed(true);

    item.SetGlobalX(200);
    item.SetGlobalY(200);
    item.SetLocalX(300);
    item.SetLocalY(300);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);

    MMI_LOGD("Call InputManager::SimulateInputEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent012()
{
    auto pointerEvent = PointerEvent::Create();
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

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_012, TestSize.Level1)
{
    std::shared_ptr<PointerEvent> pointerEvent { SetupPointerEvent012() };
    TestSimulateInputEvent_2(pointerEvent);
}

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_013, TestSize.Level1)
{
    std::string command = "pointerAction=5";
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    auto pointerEvent = PointerEvent::Create();
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
    MMI_LOGI("Inject POINTER_ACTION_AXIS_BEGIN ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_014, TestSize.Level1)
{
    std::string command = "pointerAction=6";
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    auto pointerEvent = PointerEvent::Create();
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
    MMI_LOGI("Inject POINTER_ACTION_AXIS_UPDATE ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

HWTEST_F(InputManagerTest, InputManager_SimulateInputEvent_015, TestSize.Level1)
{
    std::string command = "pointerAction=7";
    std::vector<std::string>  sLogs { SearchForLog(command, true) };

    auto pointerEvent = PointerEvent::Create();
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

    MMI_LOGI("Inject POINTER_ACTION_AXIS_END ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

void InputManagerTest::KeyMonitorCallBack(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
{
    MMI_LOGD("KeyMonitorCallBack: keyCode = %{public}d, keyAction = %{public}d , action = %{public}d,"
             "deviceId=%{private}d, actionTime = %{public}d", keyEvent->GetKeyCode(), keyEvent->GetKeyAction(),
             keyEvent->GetAction(), keyEvent->GetDeviceId(), keyEvent->GetActionTime());
    EXPECT_EQ(keyEvent->GetKeyCode(), OHOS::MMI::KeyEvent::KEYCODE_BACK);
    EXPECT_EQ(keyEvent->GetKeyAction(), OHOS::MMI::KeyEvent::KEY_ACTION_UP);
    EXPECT_EQ(keyEvent->GetAction(), OHOS::MMI::KeyEvent::KEY_ACTION_UP);
    EXPECT_EQ(keyEvent->GetDeviceId(), 0);
}

HWTEST_F(InputManagerTest, InputManagerTest_AddMonitor_001, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string command = "consumer is null";
    std::vector<std::string> log;
    ASSERT_TRUE(runCommand.RunShellCommand(command, log) == RET_OK);

    int32_t response = MMI_STANDARD_EVENT_SUCCESS;
    response = InputManager::GetInstance()->AddMonitor(KeyMonitorCallBack);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, response);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    OHOS::KeyEvent injectUpEvent;
    uint64_t downTime = static_cast<uint64_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    EXPECT_TRUE(response);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->RemoveMonitor(INDEX_FIRST);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

HWTEST_F(InputManagerTest, InputManagerTest_AddMonitor_002, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string command = "consumer is null";
    std::vector<std::string> log;
    ASSERT_TRUE(runCommand.RunShellCommand(command, log) == RET_OK);

    int32_t response = MMI_STANDARD_EVENT_SUCCESS;
    response = InputManager::GetInstance()->AddMonitor(KeyMonitorCallBack);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, response);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    response = InputManager::GetInstance()->AddMonitor(KeyMonitorCallBack);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, response);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    response = InputManager::GetInstance()->AddMonitor(KeyMonitorCallBack);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, response);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    OHOS::KeyEvent injectUpEvent;
    uint64_t downTime = static_cast<uint64_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    EXPECT_TRUE(response);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->RemoveMonitor(INDEX_FIRST);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->RemoveMonitor(INDEX_SECOND);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->RemoveMonitor(INDEX_THIRD);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->RemoveMonitor(INDEX_INVALID);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

HWTEST_F(InputManagerTest, InputManagerTest_AddHandler_001, TestSize.Level1)
{
    std::string command {
        "InputHandlerManagerGlobal: in AddMonitor, #[[:digit:]]\\{1,\\}, "
        "Service AddMonitor Success."
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    int32_t id1 = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(id1));

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    if (IsValidHandlerId(id1)) {
        InputManager::GetInstance()->RemoveMonitor(id1);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

HWTEST_F(InputManagerTest, InputManagerTest_AddHandler_002, TestSize.Level1)
{
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);

    int32_t id1 = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(id1));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    std::string command {
        "InputHandlerManagerGlobal: in RemoveMonitor, #[[:digit:]]\\{1,\\}, "
        "Service RemoveMonitor Success."
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    if (IsValidHandlerId(id1)) {
        InputManager::GetInstance()->RemoveMonitor(id1);
    }
    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

HWTEST_F(InputManagerTest, InputManagerTest_AddHandler_003, TestSize.Level1)
{
    const std::vector<int32_t>::size_type N_TEST_CASES { 3 };
    std::vector<int32_t> ids(N_TEST_CASES);
    std::vector<std::shared_ptr<InputEventCallback>> cbs(N_TEST_CASES);

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        cbs[i] = InputEventCallback::GetPtr();
        EXPECT_TRUE(cbs[i] != nullptr);
        ids[i] = InputManager::GetInstance()->AddMonitor(cbs[i]);
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    std::string command {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "PointerEvent received."
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    auto pointerEvent = SetupPointerEvent001();
    MMI_LOGD("Call InputManager::SimulatePointerEvent.");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    int32_t nTries { N_TRIES_FOR_LOG };
    std::vector<std::string> rLogs;

    while (true) {
        std::vector<std::string> tLogs { SearchForLog(command, sLogs, true) };
        rLogs.insert(rLogs.end(), tLogs.begin(), tLogs.end());
        if ((rLogs.size() >= N_TEST_CASES) || (--nTries <= 0)) {
            break;
        }
        sLogs.insert(sLogs.end(), tLogs.begin(), tLogs.end());
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_LOG));
    }
    EXPECT_TRUE(rLogs.size() >= N_TEST_CASES);

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        if (IsValidHandlerId(ids[i])) {
            InputManager::GetInstance()->RemoveMonitor(ids[i]);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }
}

HWTEST_F(InputManagerTest, InputManagerTest_AddHandler_004, TestSize.Level1)
{
    std::string command {
        "InputHandlerManager: in AddHandler, #[[:digit:]]\\{1,\\}, "
        "The number of handlers exceeds the maximum."
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    const std::vector<int32_t>::size_type N_TEST_CASES { MAX_N_INPUT_HANDLERS };
    std::vector<int32_t> ids(N_TEST_CASES);
    std::shared_ptr<InputEventCallback> cb = InputEventCallback::GetPtr();
    EXPECT_TRUE(cb != nullptr);

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        ids[i] = InputManager::GetInstance()->AddMonitor(cb);
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    int32_t monitorId = InputManager::GetInstance()->AddMonitor(cb);
    EXPECT_TRUE(!IsValidHandlerId(monitorId));

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        if (IsValidHandlerId(ids[i])) {
            InputManager::GetInstance()->RemoveMonitor(ids[i]);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }
}

HWTEST_F(InputManagerTest, InputManagerTest_AddHandler_005, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::shared_ptr<InputEventCallback> cb = InputEventCallback::GetPtr();
    EXPECT_TRUE(cb != nullptr);
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(cb);
    EXPECT_TRUE(IsValidHandlerId(monitorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    TestMarkConsumedStep1();
    auto pointerEvent = TestMarkConsumedStep2();
    TestMarkConsumedStep3(monitorId, pointerEvent->GetId());
    TestMarkConsumedStep4();
    TestMarkConsumedStep5();

    if (IsValidHandlerId(monitorId)) {
        InputManager::GetInstance()->RemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

HWTEST_F(InputManagerTest, InputManagerTest_AddHandler_006, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::shared_ptr<InputEventCallback> cb = InputEventCallback::GetPtr();
    EXPECT_TRUE(cb != nullptr);
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(cb);
    EXPECT_TRUE(IsValidHandlerId(monitorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    auto pointerEvent = TestMarkConsumedStep1();
    TestMarkConsumedStep3(monitorId, pointerEvent->GetId());
    TestMarkConsumedStep4();
    TestMarkConsumedStep6();

    if (IsValidHandlerId(monitorId)) {
        InputManager::GetInstance()->RemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name:InputManagerTest_SubscribeKeyEvent_001
 * @tc.desc:Verify the subscribe key event.
 * @tc.type: FUNC
 * @tc.require: SR000GGQL4  AR000GJNGN
 * @tc.author: yangguang
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_001, TestSize.Level1)
{
    int32_t response = -1;
    std::vector<int32_t> preKeys;
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption = std::make_shared<OHOS::MMI::KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(OHOS::MMI::KeyEvent::KEYCODE_MENU);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(0);
    response = InputManager::GetInstance()->SubscribeKeyEvent(keyOption,
        [=](std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
    {
        MMI_LOGD("KeyEventId=%{public}d,KeyCode=%{public}d,ActionTime=%{public}d,"
                 "ActionStartTime=%{public}d,Action=%{public}d,KeyAction=%{public}d,"
                 "EventType=%{public}d,Flag=%{public}d",
                 keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                 keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                 keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_LOGD("subscribe key event trigger callback");
    });
    EXPECT_TRUE(response > 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    OHOS::KeyEvent injectDownEvent;
    uint64_t downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, OHOS::MMI::KeyEvent::KEYCODE_MENU,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectDownEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    // release pressed key
    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, OHOS::MMI::KeyEvent::KEYCODE_MENU,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectUpEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->UnsubscribeKeyEvent(response);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManagerTest_SubscribeKeyEvent_002
 * @tc.desc:Verify the repeat subscribe key event.
 * @tc.type: FUNC
 * @tc.require: SR000GGQL4  AR000GJNGN
 * @tc.author: yangguang
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_002, TestSize.Level1)
{
    int32_t response = -1;
    int32_t response2 = -1;
    std::vector<int32_t> preKeys;
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption = std::make_shared<OHOS::MMI::KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(OHOS::MMI::KeyEvent::KEYCODE_POWER);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(0);
    response = InputManager::GetInstance()->SubscribeKeyEvent(keyOption,
        [](std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
    {
        MMI_LOGD("KeyEventId=%{public}d,KeyCode=%{public}d,ActionTime=%{public}d,"
                 "ActionStartTime=%{public}d,Action=%{public}d,KeyAction=%{public}d,"
                 "EventType=%{public}d,Flag=%{public}d",
                 keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                 keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                 keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_LOGD("subscribe key event trigger callback");
    });
    EXPECT_TRUE(response > 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    response2 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption,
        [](std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
    {
        MMI_LOGD("KeyEventId=%{public}d,KeyCode=%{public}d,ActionTime=%{public}d,"
                 "ActionStartTime=%{public}d,Action=%{public}d,KeyAction=%{public}d,"
                 "EventType=%{public}d,Flag=%{public}d",
                 keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                 keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                 keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_LOGD("subscribe key event trigger callback");
    });
    EXPECT_TRUE(response2 < 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    OHOS::KeyEvent injectDownEvent;
    uint64_t downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, OHOS::MMI::KeyEvent::KEYCODE_POWER,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectDownEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    // release pressed key
    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, OHOS::MMI::KeyEvent::KEYCODE_POWER,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectUpEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->UnsubscribeKeyEvent(response);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManagerTest_SubscribeKeyEvent_003
 * @tc.desc:Verify the unsubscribe key event.
 * @tc.type: FUNC
 * @tc.require: SR000GGQL4  AR000GJNGN
 * @tc.author: yangguang
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_003, TestSize.Level1)
{
    int32_t response = -1;
    std::vector<int32_t> preKeys;
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption = std::make_shared<OHOS::MMI::KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(0);
    response = InputManager::GetInstance()->SubscribeKeyEvent(keyOption,
        [](std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
    {
        MMI_LOGD("KeyEventId=%{public}d,KeyCode=%{public}d,ActionTime=%{public}d,"
                 "ActionStartTime=%{public}d,Action=%{public}d,KeyAction=%{public}d,"
                 "EventType=%{public}d,Flag=%{public}d",
                 keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                 keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                 keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_LOGD("subscribe key event trigger callback");
    });
    EXPECT_TRUE(response > 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    OHOS::KeyEvent injectDownEvent;
    uint64_t downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, OHOS::MMI::KeyEvent::KEYCODE_HOME,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectDownEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    // release pressed key
    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, OHOS::MMI::KeyEvent::KEYCODE_HOME,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectUpEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->UnsubscribeKeyEvent(response);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManagerTest_SubscribeKeyEvent_004
 * @tc.desc:Verify down trigger subscribe key event.
 * @tc.type: FUNC
 * @tc.require: SR000GGQL4  AR000GJNGN
 * @tc.author: yangguang
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_004, TestSize.Level1)
{
    int32_t response = -1;
    std::vector<int32_t> preKeys;
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption = std::make_shared<OHOS::MMI::KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(OHOS::MMI::KeyEvent::KEYCODE_BACK);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(0);
    response = InputManager::GetInstance()->SubscribeKeyEvent(keyOption,
        [](std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
    {
        MMI_LOGD("KeyEventId=%{public}d,KeyCode=%{public}d,ActionTime=%{public}d,"
                 "ActionStartTime=%{public}d,Action=%{public}d,KeyAction=%{public}d,"
                 "EventType=%{public}d,Flag=%{public}d",
                 keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                 keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                 keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_LOGD("subscribe key event down trigger callback");
    });
    EXPECT_TRUE(response > 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    OHOS::KeyEvent injectDownEvent;
    uint64_t downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, OHOS::MMI::KeyEvent::KEYCODE_BACK,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectDownEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    // release pressed key
    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, OHOS::MMI::KeyEvent::KEYCODE_BACK,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectUpEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->UnsubscribeKeyEvent(response);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManagerTest_SubscribeKeyEvent_005
 * @tc.desc:Verify down trigger subscribe key event, need to hold down for a while.
 * @tc.type: FUNC
 * @tc.require: SR000GGQL4  AR000GJNGN
 * @tc.author: yangguang
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_005, TestSize.Level1)
{
    int32_t response = -1;
    std::vector<int32_t> preKeys;
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption = std::make_shared<OHOS::MMI::KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(OHOS::MMI::KeyEvent::KEYCODE_CALL);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(2000);
    response = InputManager::GetInstance()->SubscribeKeyEvent(keyOption,
        [](std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent) {
        MMI_LOGD("KeyEventId=%{public}d,KeyCode=%{public}d,ActionTime=%{public}d,"
                 "ActionStartTime=%{public}d,Action=%{public}d,KeyAction=%{public}d,"
                 "EventType=%{public}d,Flag=%{public}d",
                 keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                 keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                 keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_LOGD("hold down for a while. subscribe key event down trigger callback");
    });
    EXPECT_TRUE(response > 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    OHOS::KeyEvent injectDownEvent;
    uint64_t downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, OHOS::MMI::KeyEvent::KEYCODE_CALL,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectDownEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    // release pressed key
    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, OHOS::MMI::KeyEvent::KEYCODE_CALL,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectUpEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->UnsubscribeKeyEvent(response);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManagerTest_SubscribeKeyEvent_006
 * @tc.desc:Verify down trigger subscribe key event, other keys are pressed during the hold time.
 * @tc.type: FUNC
 * @tc.require: SR000GGQL4  AR000GJNGN
 * @tc.author: yangguang
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_006, TestSize.Level1)
{
    int32_t response = -1;
    std::vector<int32_t> preKeys;
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption = std::make_shared<OHOS::MMI::KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(OHOS::MMI::KeyEvent::KEYCODE_ENDCALL);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(2000);
    response = InputManager::GetInstance()->SubscribeKeyEvent(keyOption,
        [](std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent) {
        MMI_LOGD("KeyEventId=%{public}d,KeyCode=%{public}d,ActionTime=%{public}d,"
                 "ActionStartTime=%{public}d,Action=%{public}d,KeyAction=%{public}d,"
                 "EventType=%{public}d,Flag=%{public}d",
                 keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                 keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                 keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_LOGD("hold down for a while. subscribe key event down trigger callback");
    });
    EXPECT_TRUE(response > 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    OHOS::KeyEvent injectDownEvent;
    uint64_t downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, OHOS::MMI::KeyEvent::KEYCODE_ENDCALL,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectDownEvent);
    // other keys are pressed during the hold time
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    OHOS::KeyEvent injectDownEvent2;
    injectDownEvent2.Initialize(0, ACTION_DOWN, OHOS::MMI::KeyEvent::KEYCODE_VOLUME_UP,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectDownEvent2);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    // release pressed key1
    OHOS::KeyEvent injectUpEvent1;
    downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectUpEvent1.Initialize(0, ACTION_UP, OHOS::MMI::KeyEvent::KEYCODE_ENDCALL,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectUpEvent1);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    // release pressed key2
    OHOS::KeyEvent injectUpEvent2;
    downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectUpEvent2.Initialize(0, ACTION_UP, OHOS::MMI::KeyEvent::KEYCODE_VOLUME_UP,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectUpEvent2);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->UnsubscribeKeyEvent(response);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManagerTest_SubscribeKeyEvent_007
 * @tc.desc:Verify up trigger subscribe key event.
 * @tc.type: FUNC
 * @tc.require: SR000GGQL4  AR000GJNGN
 * @tc.author: yangguang
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_007, TestSize.Level1)
{
    int32_t response = -1;
    std::vector<int32_t> preKeys;
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption = std::make_shared<OHOS::MMI::KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(OHOS::MMI::KeyEvent::KEYCODE_VOLUME_DOWN);
    keyOption->SetFinalKeyDown(false);
    keyOption->SetFinalKeyDownDuration(0);
    response = InputManager::GetInstance()->SubscribeKeyEvent(keyOption,
        [](std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent) {
        MMI_LOGD("KeyEventId=%{public}d,KeyCode=%{public}d,ActionTime=%{public}d,"
                 "ActionStartTime=%{public}d,Action=%{public}d,KeyAction=%{public}d,"
                 "EventType=%{public}d,Flag=%{public}d",
                 keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                 keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                 keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_LOGD("subscribe key event up trigger callback");
    });
    EXPECT_TRUE(response > 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    uint64_t downTime = static_cast<uint64_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    OHOS::KeyEvent injectDownEvent;
    injectDownEvent.Initialize(0, ACTION_DOWN, OHOS::MMI::KeyEvent::KEYCODE_VOLUME_DOWN,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectDownEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    // release pressed key , up trigger
    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, OHOS::MMI::KeyEvent::KEYCODE_VOLUME_DOWN,
                             downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectUpEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->UnsubscribeKeyEvent(response);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManagerTest_SubscribeKeyEvent_008
 * @tc.desc:Verify invalid parameter.
 * @tc.type: FUNC
 * @tc.require: SR000GGQL4  AR000GJNGN
 * @tc.author: yangguang
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_008, TestSize.Level1)
{
    int32_t response = -1;
    std::vector<int32_t> preKeys;
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption = std::make_shared<OHOS::MMI::KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(OHOS::MMI::KeyEvent::KEYCODE_VOLUME_MUTE);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(0);
    response = InputManager::GetInstance()->SubscribeKeyEvent(keyOption, nullptr);
    EXPECT_TRUE(response < 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManagerTest_SubscribeKeyEvent_009
 * @tc.desc:Verify subscribe different key event.
 * @tc.type: FUNC
 * @tc.require: SR000GGQL4  AR000GJNGN
 * @tc.author: yangguang
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_009, TestSize.Level1)
{
    int32_t response = -1;
    std::vector<int32_t> preKeys;
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption = std::make_shared<OHOS::MMI::KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(OHOS::MMI::KeyEvent::KEYCODE_MUTE);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(0);
    // KEYCODE_MUTE, KEYCODE_HEADSETHOOK, MEDIA_PLAY, MEDIA_PAUSE, MEDIA_PLAY_PAUSE
    response = InputManager::GetInstance()->SubscribeKeyEvent(keyOption,
        [](std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent) {
        MMI_LOGD("KeyEventId=%{public}d,KeyCode=%{public}d,ActionTime=%{public}d,"
                 "ActionStartTime=%{public}d,Action=%{public}d,KeyAction=%{public}d,"
                 "EventType=%{public}d,Flag=%{public}d",
                 keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                 keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                 keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_LOGD("subscribe key event KEYCODE_MUTE trigger callback");
    });
    EXPECT_TRUE(response > 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    OHOS::KeyEvent injectDownEvent;
    uint64_t downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, OHOS::MMI::KeyEvent::KEYCODE_MUTE,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectDownEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    // release pressed key
    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, OHOS::MMI::KeyEvent::KEYCODE_MUTE,
                             downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectUpEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->UnsubscribeKeyEvent(response);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name:InputManagerTest_SubscribeKeyEvent_010
 * @tc.desc:Verify subscribe power key event.
 * @tc.type: FUNC
 * @tc.require: SR000GGQL4  AR000GJNGN
 * @tc.author: zhaoxueyuan
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_010, TestSize.Level1)
{
    if (!MultimodalEventHandler::GetInstance().GetMMIClient()) {
        MMI_LOGD("get mmi client failed");
        return;
    }
    // 电源键长按按下订阅
    std::vector<int32_t> preKeys;
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption = std::make_shared<OHOS::MMI::KeyOption>();
    int32_t subscribeId1 = -1;
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(OHOS::MMI::KeyEvent::KEYCODE_POWER);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(2000);
    subscribeId1 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption,
        [](std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent) {
        MMI_LOGD("KeyEventId=%{public}d,KeyCode=%{public}d,ActionTime=%{public}d,"
                 "ActionStartTime=%{public}d,Action=%{public}d,KeyAction=%{public}d,"
                 "EventType=%{public}d,Flag=%{public}d",
                 keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                 keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                 keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_LOGD("subscribe key event KEYCODE_POWER down trigger callback");
    });
    EXPECT_TRUE(subscribeId1 > 0);

    // 电源键抬起订阅
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption2 = std::make_shared<OHOS::MMI::KeyOption>();
    int32_t subscribeId2 = -1;
    keyOption2->SetPreKeys(preKeys);
    keyOption2->SetFinalKey(OHOS::MMI::KeyEvent::KEYCODE_POWER);
    keyOption2->SetFinalKeyDown(false);
    keyOption2->SetFinalKeyDownDuration(0);
    subscribeId2 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption2,
        [](std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent) {
        MMI_LOGD("KeyEventId=%{public}d,KeyCode=%{public}d,ActionTime=%{public}d,"
                 "ActionStartTime=%{public}d,Action=%{public}d,KeyAction=%{public}d,"
                 "EventType=%{public}d,Flag=%{public}d",
                 keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                 keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                 keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_LOGD("subscribe key event KEYCODE_POWER up trigger callback");
    });
    EXPECT_TRUE(subscribeId2 > 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(10000));
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId1);
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId2);
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));
}

/**
 * @tc.name:InputManagerTest_SubscribeKeyEvent_011
 * @tc.desc:Verify subscribe F1 key event.
 * @tc.type: FUNC
 * @tc.require: SR000GGQL4  AR000GJNGN
 * @tc.author: wanghao
 */
HWTEST_F(InputManagerTest, InputManagerTest_SubscribeKeyEvent_011, TestSize.Level1)
{
    if (!MultimodalEventHandler::GetInstance().GetMMIClient()) {
        MMI_LOGD("get mmi client failed");
        return;
    }
    
    int32_t response = -1;
    std::vector<int32_t> preKeys;
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption = std::make_shared<OHOS::MMI::KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(OHOS::MMI::KeyEvent::KEYCODE_F1);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(0);
    response = InputManager::GetInstance()->SubscribeKeyEvent(keyOption,
        [=](std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
    {
        MMI_LOGD("KeyEventId=%{public}d,KeyCode=%{public}d,ActionTime=%{public}d,"
                 "ActionStartTime=%{public}d,Action=%{public}d,KeyAction=%{public}d,"
                 "EventType=%{public}d,Flag=%{public}d",
                 keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                 keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                 keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_LOGD("subscribe key event KEYCODE_F1 down trigger callback");
    });
    EXPECT_TRUE(response > 0);

    std::shared_ptr<OHOS::MMI::KeyOption> keyOption2 = std::make_shared<OHOS::MMI::KeyOption>();
    int32_t subscribeId2 = -1;
    keyOption2->SetPreKeys(preKeys);
    keyOption2->SetFinalKey(OHOS::MMI::KeyEvent::KEYCODE_F1);
    keyOption2->SetFinalKeyDown(false);
    keyOption2->SetFinalKeyDownDuration(0);
    subscribeId2 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption2,
        [](std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent) {
        MMI_LOGD("KeyEventId=%{public}d,KeyCode=%{public}d,ActionTime=%{public}d,"
                 "ActionStartTime=%{public}d,Action=%{public}d,KeyAction=%{public}d,"
                 "EventType=%{public}d,Flag=%{public}d",
                 keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                 keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
                 keyEvent->GetEventType(), keyEvent->GetFlag());
        MMI_LOGD("subscribe key event KEYCODE_F1 up trigger callback");
    });
    EXPECT_TRUE(subscribeId2 > 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    
    // pressed key
    uint64_t downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    OHOS::KeyEvent injectDownEvent1;
    injectDownEvent1.Initialize(0, ACTION_DOWN, OHOS::MMI::KeyEvent::KEYCODE_F1,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectDownEvent1);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    // release pressed key
    downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    OHOS::KeyEvent injectUpEven1;
    injectUpEven1.Initialize(0, ACTION_UP, OHOS::MMI::KeyEvent::KEYCODE_F1,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectUpEven1);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    
    // pressed key
    downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    OHOS::KeyEvent injectDownEvent2;
    injectDownEvent2.Initialize(0, ACTION_DOWN, OHOS::MMI::KeyEvent::KEYCODE_F1,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectDownEvent2);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    // release pressed key
    downTime = static_cast<uint64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND);
    OHOS::KeyEvent injectUpEvent2;
    injectUpEvent2.Initialize(0, ACTION_UP, OHOS::MMI::KeyEvent::KEYCODE_F1,
                               downTime, 0, "", 0, 0, "", 0, false, 0, ISINTERCEPTED_TRUE);
    MMIEventHdl.InjectEvent(injectUpEvent2);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->UnsubscribeKeyEvent(response);
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId2);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

class InputEventInterceptor : public OHOS::MMI::IInputEventConsumer {
public:
    virtual void OnInputEvent(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent) const override { }
    virtual void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override;
    virtual void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override {}
    static std::shared_ptr<OHOS::MMI::IInputEventConsumer> GetPtr();
};

void InputEventInterceptor::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    std::vector<int32_t> pointerIds { pointerEvent->GetPointersIdList() };
    MMI_LOGD("Pointer event intercepted:");
    MMI_LOGD("eventType=%{public}d,actionTime=%{public}d,"
             "action=%{public}d,actionStartTime=%{public}d,"
             "flag=%{public}d,pointerAction=%{public}d,sourceType=%{public}d,"
             "VerticalAxisValue=%{public}.2f,HorizontalAxisValue=%{public}.2f,"
             "pointerCount=%{public}d",
             pointerEvent->GetEventType(), pointerEvent->GetActionTime(),
             pointerEvent->GetAction(), pointerEvent->GetActionStartTime(),
             pointerEvent->GetFlag(), pointerEvent->GetPointerAction(),
             pointerEvent->GetSourceType(),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL),
             static_cast<int32_t>(pointerIds.size()));
    for (int32_t pointerId : pointerIds) {
        OHOS::MMI::PointerEvent::PointerItem item;
        CHK(pointerEvent->GetPointerItem(pointerId, item), PARAM_INPUT_FAIL);

        MMI_LOGD("downTime=%{public}d,isPressed=%{public}s,"
                 "globalX=%{public}d,globalY=%{public}d,pressure=%{public}d",
                 item.GetDownTime(),
                 item.IsPressed() ? "true" : "false",
                 item.GetGlobalX(),
                 item.GetGlobalY(),
                 item.GetPressure());
    }
}

std::shared_ptr<OHOS::MMI::IInputEventConsumer> InputEventInterceptor::GetPtr()
{
    return std::make_shared<InputEventInterceptor>();
}

std::string InputManagerTest::DumpPointerItem2(const PointerEvent::PointerItem &item)
{
    std::ostringstream strm;
    strm << "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, downTime=" << item.GetDownTime()
         << ",isPressed=" << std::boolalpha << item.IsPressed() << ",globalX=" << item.GetGlobalX()
         << ",globalY=" << item.GetGlobalY() << ",pressure=" << item.GetPressure();
    return strm.str();
}

std::string InputManagerTest::DumpPointerEvent2(const std::shared_ptr<PointerEvent> &pointerEvent)
{
    const int precision = 2;
    std::ostringstream strm;
    strm << "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, eventType="
         << pointerEvent->GetEventType()
         << ",actionTime=" << pointerEvent->GetActionTime()
         << ",action=" << pointerEvent->GetAction()
         << ",actionStartTime=" << pointerEvent->GetActionStartTime()
         << ",flag=" << pointerEvent->GetFlag()
         << ",pointerAction=" << pointerEvent->GetPointerAction()
         << ",sourceType=" << pointerEvent->GetSourceType()
         << ",VerticalAxisValue=" << std::fixed << std::setprecision(precision)
         << pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)
         << ",HorizontalAxisValue=" << std::fixed << std::setprecision(precision)
         << pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL);
    return strm.str();
}

void InputManagerTest::TestInputEventInterceptor(std::shared_ptr<PointerEvent> pointerEvent)
{
    std::string sCmd {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "Pointer event intercepted:"
    };
    std::vector<std::string> sLogs { SearchForLog(sCmd, true) };

    PointerEvent::PointerItem item;
    EXPECT_TRUE(pointerEvent->GetPointerItem(DEFAULT_POINTER_ID, item));
    std::string sItem1 { DumpPointerItem2(item) };
    std::vector<std::string> sLogItem1s { SearchForLog(sItem1, true) };
    MMI_LOGD("sItem1 = %{public}s", sItem1.c_str());

    std::string sPointeE { DumpPointerEvent2(pointerEvent) };
    std::vector<std::string> sLogPointerEs { SearchForLog(sPointeE, true) };
    MMI_LOGD("sPointerE = %{public}s", sPointeE.c_str());

    MMI_LOGD("Call InputManager::SimulateInputEvent ...");
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
            std::vector<std::string> tLogs { SearchForLog(sCmd, sLogs, true) };
            if (!tLogs.empty()) {
                states.set(0);
            }
        }
        if (!states.test(1)) {
            // 搜索日志，匹配按下手指的数据；
            std::vector<std::string> tLogItem1s { SearchForLog(sItem1, sLogItem1s, true) };
            if (!tLogItem1s.empty()) {
                states.set(1);
            }
        }
        if (!states.test(2)) {
            // 搜索日志，匹配PointerEvent事件结构的数据；
            std::vector<std::string> tLogPointerEs { SearchForLog(sPointeE, sLogPointerEs, true) };
            if (!tLogPointerEs.empty()) {
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

HWTEST_F(InputManagerTest, TestInputEventInterceptor_001, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
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

    std::shared_ptr<OHOS::MMI::IInputEventConsumer> interceptor { InputEventInterceptor::GetPtr() };
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    TestInputEventInterceptor(pointerEvent);
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

HWTEST_F(InputManagerTest, TestInputEventInterceptor_002, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
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
    MMI_LOGD("Call InterceptorManager ...");

    const std::vector<int32_t>::size_type N_TEST_CASES { 3 };
    std::vector<int32_t> ids(N_TEST_CASES);
    std::shared_ptr<OHOS::MMI::IInputEventConsumer> interceptor { InputEventInterceptor::GetPtr() };

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        ids[i] = InputManager::GetInstance()->AddInterceptor(interceptor);
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    std::string command {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "Pointer event intercepted:"
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    int32_t nTries { N_TRIES_FOR_LOG };
    std::vector<std::string> rLogs;

    while (true) {
        std::vector<std::string> tLogs { SearchForLog(command, sLogs, true) };
        rLogs.insert(rLogs.end(), tLogs.begin(), tLogs.end());
        if ((rLogs.size() >= N_TEST_CASES) || (--nTries <= 0)) {
            break;
        }
        sLogs.insert(sLogs.end(), tLogs.begin(), tLogs.end());
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_LOG));
    }
    EXPECT_TRUE(rLogs.size() >= N_TEST_CASES);

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        if (IsValidHandlerId(ids[i])) {
            InputManager::GetInstance()->RemoveInterceptor(ids[i]);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }
}

HWTEST_F(InputManagerTest, TestInputEventInterceptor_003, TestSize.Level1)
{
    const std::vector<int32_t>::size_type N_TEST_CASES { 3 };
    std::vector<int32_t> ids(N_TEST_CASES);
    std::shared_ptr<OHOS::MMI::IInputEventConsumer> interceptor { InputEventInterceptor::GetPtr() };

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        ids[i] = InputManager::GetInstance()->AddInterceptor(interceptor);
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    std::string command {
        "InputHandlerManagerGlobal: in RemoveInterceptor, #[[:digit:]]\\{1,\\}, "
        "Unregister interceptor successfully."
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        if (IsValidHandlerId(ids[i])) {
            InputManager::GetInstance()->RemoveInterceptor(ids[i]);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }

    int32_t nTries { N_TRIES_FOR_LOG };
    std::vector<std::string> rLogs;

    while (true) {
        std::vector<std::string> tLogs { SearchForLog(command, sLogs, true) };
        rLogs.insert(rLogs.end(), tLogs.begin(), tLogs.end());
        if ((rLogs.size() >= N_TEST_CASES) || (--nTries <= 0)) {
            break;
        }
        sLogs.insert(sLogs.end(), tLogs.begin(), tLogs.end());
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_LOG));
    }
    EXPECT_TRUE(rLogs.size() >= N_TEST_CASES);
}

HWTEST_F(InputManagerTest, TestInputEventInterceptor_004, TestSize.Level1)
{
    std::string command {
        "InputInterceptorManager: in AddInterceptor, #[[:digit:]]\\{1,\\}, "
        "No interceptor was specified."
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    std::shared_ptr<OHOS::MMI::IInputEventConsumer> interceptor;
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
    EXPECT_TRUE(!IsValidHandlerId(interceptorId));

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

HWTEST_F(InputManagerTest, TestInputEventInterceptor_005, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    PointerEvent::PointerItem item;
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(static_cast<int64_t>(GetNanoTime() / NANOSECOND_TO_MILLISECOND));
    item.SetPressed(true);
    item.SetGlobalX(200);
    item.SetGlobalY(300);
    pointerEvent->AddPointerItem(item);

    std::shared_ptr<OHOS::MMI::IInputEventConsumer> interceptor { InputEventInterceptor::GetPtr() };
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
    std::vector<std::string> sLogs { SearchForLog(sCmd, true) };

    PointerEvent::PointerItem item;
    pointerEvent->GetPointerItem(0, item);
    std::string sItem1 { DumpPointerItem2(item) };
    std::vector<std::string> sLogItem1s { SearchForLog(sItem1, true) };

    pointerEvent->GetPointerItem(1, item);
    std::string sItem2 { DumpPointerItem2(item) };
    std::vector<std::string> sLogItem2s { SearchForLog(sItem2, true) };

    std::string sPointeE { DumpPointerEvent2(pointerEvent) };
    std::vector<std::string> sLogPointerEs { SearchForLog(sPointeE, true) };

    MMI_LOGD("Call InputManager::SimulateInputEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    int32_t nTries { N_TRIES_FOR_LOG };
    std::bitset<4> states { };

    while (true) {
        if (!states.test(0)) {
            std::vector<std::string> tLogs { SearchForLog(sCmd, sLogs, true) };
            if (!tLogs.empty()) {
                states.set(0);
            }
        }
        if (!states.test(1)) {
            std::vector<std::string> tLogItem1s { SearchForLog(sItem1, sLogItem1s, true) };
            if (!tLogItem1s.empty()) {
                states.set(1);
            }
        }
        if (!states.test(2)) {
            std::vector<std::string> tLogItem2s { SearchForLog(sItem2, sLogItem2s, true) };
            if (!tLogItem2s.empty()) {
                states.set(2);
            }
        }
        if (!states.test(3)) {
            std::vector<std::string> tLogPointerEs { SearchForLog(sPointeE, sLogPointerEs, true) };
            if (!tLogPointerEs.empty()) {
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

HWTEST_F(InputManagerTest, TestInputEventInterceptor_006, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
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

    std::shared_ptr<OHOS::MMI::IInputEventConsumer> interceptor { InputEventInterceptor::GetPtr() };
    int32_t interceptorId { InputManager::GetInstance()->AddInterceptor(interceptor) };
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    TestInputEventInterceptor2(pointerEvent);
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

void InputManagerTest::TouchPadMonitorCallBack(std::shared_ptr<OHOS::MMI::PointerEvent> pointerEvent)
{
    int32_t pointerId = pointerEvent->GetPointerId();
    OHOS::MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerId, pointerItem);
    MMI_LOGD("TouchPadMonitorCallBack: pointerAction = %{public}d, pointerId = %{public}d,"
        "x = %{public}d, y = %{public}d", pointerEvent->GetPointerAction(),
        pointerEvent->GetPointerId(), pointerItem.GetGlobalX(), pointerItem.GetGlobalY());
}

HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_001, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
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
    MMI_LOGD("Call MontiorManager ......");

    std::string command { "PointerEvent received." };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    int32_t monitorId { };
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    monitorId = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(monitorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int32_t response = MMIEventHdl.InjectPointerEvent(pointerEvent);
    EXPECT_EQ(RET_OK, response);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_002, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
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
    MMI_LOGD("Call MontiorManager ......");

    std::string command { "PointerEvent received." };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    int32_t monitorId { };
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    monitorId = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(monitorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int32_t response = MMIEventHdl.InjectPointerEvent(pointerEvent);
    EXPECT_EQ(RET_OK, response);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_003, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
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
    MMI_LOGD("Call MontiorManager ......");

    std::string command { "PointerEvent received." };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    int32_t monitorId { };
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    monitorId = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(monitorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int32_t response = MMIEventHdl.InjectPointerEvent(pointerEvent);
    EXPECT_EQ(RET_OK, response);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_004, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
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
    MMI_LOGD("Call MontiorManager ......");

    const std::vector<int32_t>::size_type N_TEST_CASES { 3 };
    std::vector<int32_t> ids(N_TEST_CASES);

    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        ids[i] = InputManager::GetInstance()->AddMonitor(callBackPtr);
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    std::string command {
        "InputManagerTest: in OnInputEvent, #[[:digit:]]\\{1,\\}, "
        "PointerEvent received."
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    int32_t nTries { N_TRIES_FOR_LOG };
    std::vector<std::string> rLogs;

    while (true) {
        std::vector<std::string> tLogs { SearchForLog(command, sLogs, true) };
        rLogs.insert(rLogs.end(), tLogs.begin(), tLogs.end());
        if ((rLogs.size() >= N_TEST_CASES) || (--nTries <= 0)) {
            break;
        }
        sLogs.insert(sLogs.end(), tLogs.begin(), tLogs.end());
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_LOG));
    }
    EXPECT_TRUE(rLogs.size() >= N_TEST_CASES);

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        InputManager::GetInstance()->RemoveMonitor(ids[i]);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

HWTEST_F(InputManagerTest, InputManagerTest_OnAddTouchPadMonitor_005, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
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
    MMI_LOGD("Call MontiorManager ......");

    std::string command {
        "EventDispatch: in handlePointerEvent, #[[:digit:]]\\{1,\\}, "
        "Unknown source type!"
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    int32_t monitorId { };
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    monitorId = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(IsValidHandlerId(monitorId));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int32_t response = MMIEventHdl.InjectPointerEvent(pointerEvent);
    EXPECT_EQ(RET_OK, response);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_001, TestSize.Level1)
{
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    int32_t monitorId { InputManager::GetInstance()->AddMonitor(callBackPtr) };
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int32_t actionTime { static_cast<int32_t>(GetSysClockTime()) };
    auto pointerEvent = PointerEvent::Create();
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
        "PointerEvent received."
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    MMI_LOGD("Call InputManager::SimulateInputEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_002, TestSize.Level1)
{
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    int32_t monitorId { InputManager::GetInstance()->AddMonitor(callBackPtr) };
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int32_t actionTime { static_cast<int32_t>(GetSysClockTime()) };
    auto pointerEvent = PointerEvent::Create();
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
        "PointerEvent received."
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    MMI_LOGD("Call InputManager::SimulateInputEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_003, TestSize.Level1)
{
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    int32_t monitorId { InputManager::GetInstance()->AddMonitor(callBackPtr) };
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int32_t actionTime { static_cast<int32_t>(GetSysClockTime()) };
    auto pointerEvent = PointerEvent::Create();
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
        "PointerEvent received."
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    MMI_LOGD("Call InputManager::SimulateInputEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_004, TestSize.Level1)
{
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    int32_t monitorId { InputManager::GetInstance()->AddMonitor(callBackPtr) };
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int32_t actionTime { static_cast<int32_t>(GetSysClockTime()) };
    auto pointerEvent = PointerEvent::Create();
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
        "PointerEvent received."
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    MMI_LOGD("Call InputManager::SimulateInputEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    InputManager::GetInstance()->RemoveMonitor(monitorId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

HWTEST_F(InputManagerTest, InputManager_TouchPadSimulateInputEvent_005, TestSize.Level1)
{
    std::string command {
        "EventDispatch: in handlePointerEvent, #[[:digit:]]\\{1,\\}, "
        "Unknown source type!"
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    auto pointerEvent = PointerEvent::Create();
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetGlobalX(823);
    item.SetGlobalY(723);
    item.SetPressure(5);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(-1);
    pointerEvent->SetPointerId(0);

    MMI_LOGD("Call InputManager::SimulateInputEvent 5 ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());
}

HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_001, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string addCmd {
        "InputHandlerManagerGlobal: in AddMonitor, #[[:digit:]]\\{1,\\}, "
        "Service AddMonitor Success."
    };
    std::vector<std::string> addLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(addCmd, addLogs) == RET_OK);

    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    int32_t id1 = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(id1 >= 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    std::vector<std::string> addItem;
    ASSERT_TRUE(runCommand.RunShellCommand(addCmd, addItem) == RET_OK);
    EXPECT_TRUE(addItem.size() > addLogs.size());
    if (!addItem.empty() && !addLogs.empty()) {
        EXPECT_TRUE(addItem.back() != addLogs.back());
    }
    InputManager::GetInstance()->RemoveMonitor(id1);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_002, TestSize.Level1)
{
    RunShellUtil runCommand;
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);

    int32_t id1 = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(id1 >= 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    std::string removeCmd {
        "InputHandlerManagerGlobal: in RemoveMonitor, #[[:digit:]]\\{1,\\}, "
        "Service RemoveMonitor Success."
    };
    std::vector<std::string> removeLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(removeCmd, removeLogs) == RET_OK);

    InputManager::GetInstance()->RemoveMonitor(id1);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    std::vector<std::string> removeItem;
    ASSERT_TRUE(runCommand.RunShellCommand(removeCmd, removeItem) == RET_OK);
    EXPECT_TRUE(removeItem.size() > removeLogs.size());
    if (!removeItem.empty() && !removeLogs.empty()) {
        EXPECT_TRUE(removeItem.back() != removeLogs.back());
    }
}

HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_003, TestSize.Level1)
{
    std::string command {
        "InputHandlerManager: in AddHandler, #[[:digit:]]\\{1,\\}, "
        "The number of handlers exceeds the maximum."
    };
    std::vector<std::string> sLogs { SearchForLog(command, true) };

    const std::vector<int32_t>::size_type N_TEST_CASES { MAX_N_INPUT_HANDLERS };
    std::vector<int32_t> ids(N_TEST_CASES);
    std::shared_ptr<InputEventCallback> cb = InputEventCallback::GetPtr();
    EXPECT_TRUE(cb != nullptr);

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        ids[i] = InputManager::GetInstance()->AddMonitor(cb);
        EXPECT_TRUE(ids[i] >= MIN_HANDLER_ID);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    int32_t monitorId = InputManager::GetInstance()->AddMonitor(cb);
    EXPECT_TRUE(monitorId < MIN_HANDLER_ID);

    std::vector<std::string> tLogs { SearchForLog(command, sLogs) };
    EXPECT_TRUE(!tLogs.empty());

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        if (ids[i] >= MIN_HANDLER_ID) {
            InputManager::GetInstance()->RemoveMonitor(ids[i]);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }
}

HWTEST_F(InputManagerTest, InputManagerTest_AddMouseMonitor_004, TestSize.Level1)
{
    auto callBackPtr = InputEventCallback::GetPtr();
    EXPECT_TRUE(callBackPtr != nullptr);
    int32_t id1 = InputManager::GetInstance()->AddMonitor(callBackPtr);
    EXPECT_TRUE(id1 >= 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    RunShellUtil runCommand;
    std::string command {
        "InputHandlerManagerGlobal: in AddMonitor, #[[:digit:]]\\{1,\\}, "
        "PointerEvent received."
    };
    std::vector<std::string> addLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(command, addLogs) == RET_OK);

    auto pointerEvent = SetupPointerEvent006();
    EXPECT_TRUE(pointerEvent != nullptr);
    MMI_LOGD("Call InputManager::SimulateInputEvent ...");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::vector<std::string> addItem;
    ASSERT_TRUE(runCommand.RunShellCommand(command, addItem) == RET_OK);
    EXPECT_TRUE(addItem.size() > addLogs.size());
    if (!addItem.empty() && !addLogs.empty()) {
        EXPECT_TRUE(addItem.back() != addLogs.back());
    }
    InputManager::GetInstance()->RemoveMonitor(id1);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}
}