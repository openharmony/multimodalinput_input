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

#include "event_util_test.h"

#include <iomanip>

#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventUtilTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t TIME_WAIT_FOR_EVENT { 1000 };
constexpr int32_t SEC_TO_NANOSEC { 1000000000 };
} // namespace

void InputEventConsumer::OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const
{
    CALL_DEBUG_ENTER;
    RECV_FLAG flag = TestUtil->GetRecvFlag();
    if (flag == RECV_FLAG::RECV_FOCUS || flag == RECV_FLAG::RECV_MARK_CONSUMED) {
        keyEvent->MarkProcessed();
        ASSERT_TRUE(keyEvent != nullptr);
        TestUtil->AddEventDump(TestUtil->DumpInputEvent(keyEvent));
    }
}

void InputEventConsumer::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CALL_DEBUG_ENTER;
    RECV_FLAG flag = TestUtil->GetRecvFlag();
    if (flag == RECV_FLAG::RECV_FOCUS || flag == RECV_FLAG::RECV_MARK_CONSUMED) {
        pointerEvent->MarkProcessed();
        ASSERT_TRUE(pointerEvent != nullptr);
        auto pointerAction = pointerEvent->GetPointerAction();
        if (pointerAction != PointerEvent::POINTER_ACTION_ENTER_WINDOW &&
            pointerAction != PointerEvent::POINTER_ACTION_LEAVE_WINDOW &&
            pointerAction != PointerEvent::POINTER_ACTION_PULL_IN_WINDOW &&
            pointerAction != PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW) {
            TestUtil->AddEventDump(TestUtil->DumpInputEvent(pointerEvent));
        }
    }
}

void InputEventCallback::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CALL_DEBUG_ENTER;
    if (TestUtil->GetRecvFlag() != RECV_FLAG::RECV_MARK_CONSUMED) {
        TestUtil->SetRecvFlag(RECV_FLAG::RECV_MONITOR);
        ASSERT_TRUE(pointerEvent != nullptr);
        TestUtil->AddEventDump(TestUtil->DumpInputEvent(pointerEvent));
        lastPointerEventId_ = pointerEvent->GetId();
    }
}

void InputEventCallback::OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const
{
    CALL_DEBUG_ENTER;
    if (TestUtil->GetRecvFlag() != RECV_FLAG::RECV_MARK_CONSUMED) {
        TestUtil->SetRecvFlag(RECV_FLAG::RECV_MONITOR);
        ASSERT_TRUE(keyEvent != nullptr);
        TestUtil->AddEventDump(TestUtil->DumpInputEvent(keyEvent));
    }
}

void PriorityMiddleCallback::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CALL_DEBUG_ENTER;
    if (TestUtil->GetRecvFlag() != RECV_FLAG::RECV_MARK_CONSUMED) {
        TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
        ASSERT_TRUE(pointerEvent != nullptr);
        TestUtil->AddEventDump("Call middle interceptor");
    }
}

void PriorityMiddleCallback::OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const
{
    CALL_DEBUG_ENTER;
    if (TestUtil->GetRecvFlag() != RECV_FLAG::RECV_MARK_CONSUMED) {
        TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
        ASSERT_TRUE(keyEvent != nullptr);
        TestUtil->AddEventDump("Call middle interceptor");
    }
}

void PriorityHighCallback::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CALL_DEBUG_ENTER;
    if (TestUtil->GetRecvFlag() != RECV_FLAG::RECV_MARK_CONSUMED) {
        TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
        ASSERT_TRUE(pointerEvent != nullptr);
        TestUtil->AddEventDump("Call high interceptor");
    }
}

void PriorityHighCallback::OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const
{
    CALL_DEBUG_ENTER;
    if (TestUtil->GetRecvFlag() != RECV_FLAG::RECV_MARK_CONSUMED) {
        TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
        ASSERT_TRUE(keyEvent != nullptr);
        TestUtil->AddEventDump("Call high interceptor");
    }
}

void WindowEventConsumer::OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const
{
    threadId_ = GetThisThreadId();
    MMI_HILOGD("Consumer callback keyEvent is threadId:%{public}" PRIu64, threadId_);
}

void WindowEventConsumer::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    threadId_ = GetThisThreadId();
    MMI_HILOGD("Consumer callback pointerEvent is threadId:%{public}" PRIu64, threadId_);
}

uint64_t WindowEventConsumer::GetConsumerThreadId()
{
    return threadId_;
}

EventUtilTest::EventUtilTest() {}
EventUtilTest::~EventUtilTest() {}

void EventUtilTest::AddEventDump(std::string eventDump)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lockGuard(mutex_);
    if (eventDump.empty()) {
        strEventDump_.clear();
        return;
    }
    strEventDump_.push_back(eventDump);
    MMI_HILOGD("Setting the Dump event, strEventDump_:%{public}s", eventDump.c_str());
    conditionVariable_.notify_one();
}

std::string EventUtilTest::GetEventDump()
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::mutex> uniqueLock(mutex_);
    std::string str = "";
    if (strEventDump_.empty()) {
        MMI_HILOGD("Waiting for an event to fire");
        if (conditionVariable_.wait_for(uniqueLock,
            std::chrono::milliseconds(TIME_WAIT_FOR_EVENT)) == std::cv_status::timeout) {
            MMI_HILOGD("Timeout");
            return str;
        }
    }
    str = strEventDump_.front();
    strEventDump_.pop_front();
    return str;
}

bool EventUtilTest::Init()
{
    CALL_DEBUG_ENTER;
    if (!WindowUtilsTest::GetInstance()->DrawTestWindow()) {
        return false;
    }
    sptr<Rosen::Window> window_ = WindowUtilsTest::GetInstance()->GetWindow();
    CHKPF(window_);
    auto listener_ = GetPtr<InputEventConsumer>();
    CHKPF(listener_);
    const std::string threadTest = "EventUtilTest";
    auto runner = AppExecFwk::EventRunner::Create(threadTest);
    CHKPF(runner);
    auto eventHandler = std::make_shared<AppExecFwk::EventHandler>(runner);
    MMI::InputManager::GetInstance()->SetWindowInputEventConsumer(listener_, eventHandler);
    return true;
}

std::string EventUtilTest::DumpInputEvent(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    const int precision = 2;
    std::ostringstream ostream;
    std::vector<int32_t> pointerIds { pointerEvent->GetPointerIds() };
    std::string str;
    std::vector<uint8_t> buffer = pointerEvent->GetBuffer();
    for (const auto& buff : buffer) {
        str += std::to_string(buff);
    }
    ostream << "ClientMsgHandler: in OnPointerEvent"
         << ",EventType:" << pointerEvent->GetEventType()
         << ",ActionTime:" << pointerEvent->GetActionTime()
         << ",Action:" << pointerEvent->GetAction()
         << ",ActionStartTime:" << pointerEvent->GetActionStartTime()
         << ",Flag:" << pointerEvent->GetFlag()
         << ",PointerAction:" << pointerEvent->DumpPointerAction()
         << ",SourceType:" << pointerEvent->DumpSourceType()
         << ",ButtonId:" << pointerEvent->GetButtonId()
         << ",DeviceId:" << pointerEvent->GetDeviceId()
         << ",VerticalAxisValue:" << std::fixed << std::setprecision(precision)
         << pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)
         << ",HorizontalAxisValue:" << std::fixed << std::setprecision(precision)
         << pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)
         <<",BufferCount:" << buffer.size()
         <<",Buffer:" << str.c_str();
    for (const auto &pointerId : pointerIds) {
        PointerEvent::PointerItem item;
        if (!pointerEvent->GetPointerItem(pointerId, item)) {
            MMI_HILOGE("Invalid pointer:%{public}d.", pointerId);
            return ostream.str();
        }
        ostream << ",pointerId:" << pointerId << ",DownTime:" << item.GetDownTime()
            << ",IsPressed:" << std::boolalpha << item.IsPressed()
            << ",DisplayX:" << item.GetDisplayX() << ",DisplayY:" << item.GetDisplayY()
            << ",Width:" << item.GetWidth() << ",Height:" << item.GetHeight()
            << ",TiltX:" << std::fixed << std::setprecision(precision) << item.GetTiltX()
            << ",TiltY:" << std::fixed << std::setprecision(precision) << item.GetTiltY()
            << ",ToolDisplayX:" << item.GetToolDisplayX() << ",ToolDisplayY:" << item.GetToolDisplayY()
            << ",ToolWindowX:" << item.GetToolWindowX() << ",ToolWindowY:" << item.GetToolWindowY()
            << ",ToolWidth:" << item.GetToolWidth() << ",ToolHeight:" << item.GetToolHeight()
            << ",Pressure:" << item.GetPressure() << ",ToolType:" << item.GetToolType()
            << ",LongAxis:" << item.GetLongAxis() << ",ShortAxis:" << item.GetShortAxis()
            << ",DeviceId:" << item.GetDeviceId() << ",RawDx:" << item.GetRawDx()
            << ",RawDy:" << item.GetRawDy();
    }

    return ostream.str();
}

std::string EventUtilTest::DumpInputEvent(const std::shared_ptr<KeyEvent>& keyEvent)
{
    std::ostringstream strm;
    strm << "InputManagerTest: in OnKeyEvent"
         << ", KeyCode:" << keyEvent->GetKeyCode()
         << ", ActionTime:" << keyEvent->GetActionTime()
         << ", Action:" << keyEvent->GetAction()
         << ", ActionStartTime:" << keyEvent->GetActionStartTime()
         << ", EventType:" << keyEvent->GetEventType()
         << ", KeyAction:" << keyEvent->GetKeyAction();
    std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
    for (const int32_t &key : pressedKeys) {
        std::optional<KeyEvent::KeyItem> keyItem = keyEvent->GetKeyItem(key);
        if (!keyItem) {
            MMI_HILOGE("keyItem is nullopt");
            return "";
        }
        strm << ", KeyCode:" << keyItem->GetKeyCode()
            << ", DeviceId:" << keyItem->GetDeviceId()
            << ", Unicode:" << keyItem->GetUnicode();
    }
    return strm.str();
}

bool EventUtilTest::CompareDump(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CALL_DEBUG_ENTER;
    std::string before = DumpInputEvent(pointerEvent);
    MMI_HILOGD("before:%{private}s", before.c_str());
    strEventDump_.clear();
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    std::string after = GetEventDump();
    MMI_HILOGD("after:%{public}s", after.c_str());
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
    std::string result = DumpInputEvent(pointerEvent);
    MMI_HILOGD("result:%{private}s", result.c_str());
    return result == after;
}

bool EventUtilTest::CompareDump(const std::shared_ptr<KeyEvent>& keyEvent)
{
    CALL_DEBUG_ENTER;
    std::string before = DumpInputEvent(keyEvent);
    MMI_HILOGD("before:%{public}s", before.c_str());
    strEventDump_.clear();
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    std::string after = GetEventDump();
    MMI_HILOGD("after:%{public}s", after.c_str());
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
    std::string result = DumpInputEvent(keyEvent);
    MMI_HILOGD("result:%{public}s", result.c_str());
    return result == after;
}

int64_t GetNanoTime()
{
    struct timespec time = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &time);
    return static_cast<int64_t>(time.tv_sec) * SEC_TO_NANOSEC + time.tv_nsec;
}

void DumpWindowData(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CALL_DEBUG_ENTER;
    pointerEvent->GetAxes();
    pointerEvent->GetPressedKeys();
    pointerEvent->GetPressedButtons();
    PointerEvent::PointerItem item;
    item.GetDisplayX();
    item.GetDisplayY();
    item.GetTargetWindowId();
}
} // namespace MMI
} // namespace OHOS