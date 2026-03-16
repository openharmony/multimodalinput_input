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

#include <cstdio>
#include <linux/input.h>
#include <gtest/gtest.h>
#include <input_manager.h>
#include <nocopyable.h>

#include "define_multimodal.h"
#include "general_touchscreen.h"
#include "input_device_manager.h"
#include "input_windows_manager_mock.h"
#include "libinput_mock.h"
#include "touch_transform_processor.h"
#include "input_event_handler.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t FIRST_POINTER_ID { 0 };
constexpr int32_t TIME_WAIT_FOR_OP { 50 };
constexpr int32_t TEST_DEVICE_ID { 5 };
constexpr int32_t TEST_DISPLAY_ID { 0 };
constexpr int32_t TEST_WINDOW_ID { 1 };
constexpr int32_t TEST_AGENT_WINDOW_ID { 2 };
constexpr int32_t TEST_POINTER_ID_1 { 0 };
constexpr int32_t TEST_POINTER_ID_2 { 1 };
constexpr int32_t TEST_POINTER_ID_3 { 2 };
constexpr int32_t TEST_DISPLAY_X_1 { 100 };
constexpr int32_t TEST_DISPLAY_Y_1 { 100 };
constexpr int32_t TEST_DISPLAY_X_2 { 200 };
constexpr int32_t TEST_DISPLAY_Y_2 { 200 };
constexpr int32_t TEST_DISPLAY_X_3 { 300 };
constexpr int32_t TEST_DISPLAY_Y_3 { 300 };
constexpr int32_t EXPECTED_TOUCH_EVENT_COUNT { 2 };
} // namespace

using namespace testing;
using namespace testing::ext;

class TouchTransformProcessorTestWithMock : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static void SetupTouchscreen();
    static void CloseTouchscreen();
    static void SimulateInputEvent001();

    static GeneralTouchscreen vTouchscreen_;
};

GeneralTouchscreen TouchTransformProcessorTestWithMock::vTouchscreen_;

void TouchTransformProcessorTestWithMock::SetUpTestCase()
{
    SetupTouchscreen();
}

void TouchTransformProcessorTestWithMock::TearDownTestCase()
{
    CloseTouchscreen();
}

void TouchTransformProcessorTestWithMock::SetUp()
{}

void TouchTransformProcessorTestWithMock::TearDown()
{
    InputEventHandlerManager::ReleaseInstance();
    InputWindowsManagerMock::ReleaseInstance();
}

void TouchTransformProcessorTestWithMock::SetupTouchscreen()
{
    std::cout << "Setup virtual touchscreen." << std::endl;
    if (!vTouchscreen_.SetUp()) {
        std::cout << "Failed to setup virtual touchscreen." << std::endl;
        return;
    }
    std::cout << "device node name: " << vTouchscreen_.GetDevPath() << std::endl;
}

void TouchTransformProcessorTestWithMock::CloseTouchscreen()
{
    std::cout << "Close virtual touchscreen." << std::endl;
    vTouchscreen_.Close();
}

/**
 * @tc.name: TouchTransformProcessorTest_OnEventTouchDown_001
 * @tc.desc: Test the function OnEventTouchDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, OnEventTouchDown_001, TestSize.Level1)
{
    libinput_event_touch event {};
    struct libinput_device dev {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_TOUCH_DOWN));
    EXPECT_CALL(libinputMock, GetSensorTime).WillOnce(Return(1));
    EXPECT_CALL(libinputMock, GetTouchEvent).WillOnce(Return(&event));
    EXPECT_CALL(libinputMock, GetDevice).WillOnce(Return(&dev));
    EXPECT_CALL(libinputMock, TouchEventGetTime).WillOnce(Return(2));
    EXPECT_CALL(libinputMock, TouchEventGetPressure).WillOnce(Return(1.0));
    EXPECT_CALL(libinputMock, TouchEventGetSeatSlot).WillOnce(Return(1));
    EXPECT_CALL(libinputMock, TouchEventGetContactLongAxis).WillOnce(Return(1));
    EXPECT_CALL(libinputMock, TouchEventGetContactShortAxis).WillOnce(Return(1));
    EXPECT_CALL(libinputMock, TouchEventGetToolType).WillOnce(Return(-1));
    EXPECT_CALL(libinputMock, TouchEventGetBtnToolTypeDown).WillRepeatedly(Return(PointerEvent::TOOL_TYPE_FINGER));

    EXPECT_CALL(*WIN_MGR_MOCK, TouchPointToDisplayPoint).WillOnce(Return(true));
    EXPECT_CALL(*WIN_MGR_MOCK, UpdateTargetPointer).WillOnce(Return(RET_OK));

    int32_t deviceId { -1 };
    TouchTransformProcessor processor(deviceId);
    auto pointerEvent = processor.OnEvent(&event.base);
    ASSERT_TRUE(pointerEvent != nullptr);
    EXPECT_EQ(pointerEvent->GetSourceType(), PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_DOWN);
}

struct MockInputEventConsumer final : public IInputEventConsumer {
public:
    MockInputEventConsumer() = default;
    ~MockInputEventConsumer() = default;
    DISALLOW_COPY_AND_MOVE(MockInputEventConsumer);

    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override;
    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override;
    void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override;

    std::shared_ptr<PointerEvent> GetPointerEvent() const;

private:
    mutable std::shared_ptr<PointerEvent> pointerEvent_;
};

void MockInputEventConsumer::OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const
{}

void MockInputEventConsumer::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPV(pointerEvent);
    pointerEvent_ = std::make_shared<PointerEvent>(*pointerEvent);
}

void MockInputEventConsumer::OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const
{}

std::shared_ptr<PointerEvent> MockInputEventConsumer::GetPointerEvent() const
{
    return pointerEvent_;
}

void TouchTransformProcessorTestWithMock::SimulateInputEvent001()
{
    int32_t xPos { 5190 };
    int32_t yPos { 8306 };
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_POSITION_X, xPos);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, yPos);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 0);
    vTouchscreen_.SendEvent(EV_SYN, SYN_MT_REPORT, 0);
    vTouchscreen_.SendEvent(EV_KEY, BTN_TOUCH, 1);
    vTouchscreen_.SendEvent(EV_SYN, SYN_MT_REPORT, 0);
    vTouchscreen_.SendEvent(EV_SYN, SYN_REPORT, 0);
}

/**
 * @tc.name: TouchTransformProcessorTest_GetDisplayXPos_001
 * @tc.desc: Supprt reporting touch-position in float precision.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, TouchTransformProcessorTest_GetDisplayXPos_001, TestSize.Level1)
{
    auto inputMonitor = std::make_shared<MockInputEventConsumer>();
    auto monitorId = InputManager::GetInstance()->AddMonitor(inputMonitor);
    ASSERT_GE(monitorId, 0);

    SimulateInputEvent001();
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    auto touchEvent = inputMonitor->GetPointerEvent();
    EXPECT_NE(touchEvent, nullptr);
    if (touchEvent != nullptr) {
        PointerEvent::PointerItem item {};
        auto haveItem = touchEvent->GetPointerItem(touchEvent->GetPointerId(), item);
        EXPECT_TRUE(haveItem);
        if (haveItem) {
            constexpr double precision { 0.05 };
            EXPECT_GT(std::abs(item.GetDisplayXPos() - std::round(item.GetDisplayXPos())), precision);
            EXPECT_GT(std::abs(item.GetDisplayYPos() - std::round(item.GetDisplayYPos())), precision);
            EXPECT_GT(std::abs(item.GetWindowXPos() - std::round(item.GetWindowXPos())), precision);
            EXPECT_GT(std::abs(item.GetWindowYPos() - std::round(item.GetWindowYPos())), precision);
        }
    }
}

#ifdef OHOS_BUILD_EXTERNAL_SCREEN
/**
 * @tc.name  : TouchTransformProcessorTestWithMock_AddInvalidAreaDownedEventTest_001
 * @tc.desc  : 测试当列表未满时,添加元素到列表中
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, AddInvalidAreaDownedEventTest_001, TestSize.Level1) {
    int32_t seatSlot = 5;
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    processor.InvalidAreaDownedEvents_.clear();

    processor.AddInvalidAreaDownedEvent(seatSlot);

    ASSERT_EQ(processor.InvalidAreaDownedEvents_.size(), 1);
    ASSERT_EQ(*(processor.InvalidAreaDownedEvents_.begin()), seatSlot);
}

/**
 * @tc.name  : TouchTransformProcessorTestWithMock_AddInvalidAreaDownedEventTest_002
 * @tc.desc  : 测试当seatSlot已经存在于列表中时,不会重复添加
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, AddInvalidAreaDownedEventTest_002, TestSize.Level1) {
    int32_t seatSlot = 5;
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    processor.InvalidAreaDownedEvents_.clear();

    processor.AddInvalidAreaDownedEvent(seatSlot);
    processor.AddInvalidAreaDownedEvent(seatSlot);

    ASSERT_EQ(processor.InvalidAreaDownedEvents_.size(), 1);
    ASSERT_EQ(*(processor.InvalidAreaDownedEvents_.begin()), seatSlot);
}

/**
 * @tc.name  : TouchTransformProcessorTestWithMock_AddInvalidAreaDownedEventTest_003
 * @tc.desc  : 测试当列表满时,添加元素会删除列表中的第一个元素
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, AddInvalidAreaDownedEventTest_003, TestSize.Level1) {
    int32_t seatSlot = 11;
    int32_t deviceId = 6;
    int32_t maxPointerItems = 10;
    TouchTransformProcessor processor(deviceId);
    processor.InvalidAreaDownedEvents_.clear();

    for (int i = 0; i < maxPointerItems; ++i) {
        processor.AddInvalidAreaDownedEvent(i);
    }

    processor.AddInvalidAreaDownedEvent(seatSlot);

    ASSERT_EQ(processor.InvalidAreaDownedEvents_.size(), maxPointerItems);
    ASSERT_FALSE(processor.InvalidAreaDownedEvents_.empty());
    ASSERT_EQ(processor.InvalidAreaDownedEvents_.back(), seatSlot);
}


/**
 * @tc.name  : TouchTransformProcessorTestWithMock_IsInvalidAreaDownedEvent_001
 * @tc.desc  : 测试当seatSlot已经存在于列表中, 判断存列表中的元素时返回true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, IsInvalidAreaDownedEvent_001, TestSize.Level1) {
    int32_t seatSlot = 5;
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    processor.InvalidAreaDownedEvents_.clear();
    processor.AddInvalidAreaDownedEvent(seatSlot);

    ASSERT_TRUE(processor.IsInvalidAreaDownedEvent(seatSlot));
}

/**
 * @tc.name  : TouchTransformProcessorTestWithMock_IsInvalidAreaDownedEvent_002
 * @tc.desc  : 测试当seatSlot已经存在于列表中, 判断不存列表中的元素时返回false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, IsInvalidAreaDownedEvent_002, TestSize.Level1) {
    int32_t seatSlot = 5;
    int32_t otherSeatSlot = 6;
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    processor.InvalidAreaDownedEvents_.clear();

    processor.AddInvalidAreaDownedEvent(seatSlot);

    ASSERT_FALSE(processor.IsInvalidAreaDownedEvent(otherSeatSlot));
}

/**
 * @tc.name  : TouchTransformProcessorTestWithMock_RemoveInvalidAreaDownedEventTest_001
 * @tc.desc  : 测试当seatSlot已经存在于列表中时,可以删除
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, RemoveInvalidAreaDownedEventTest_001, TestSize.Level1) {
    int32_t seatSlot = 5;
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    processor.InvalidAreaDownedEvents_.clear();

    processor.AddInvalidAreaDownedEvent(seatSlot);
    processor.RemoveInvalidAreaDownedEvent(seatSlot);

    ASSERT_EQ(processor.InvalidAreaDownedEvents_.size(), 0);
}

/**
 * @tc.name  : TouchTransformProcessorTestWithMock_RemoveInvalidAreaDownedEventTest_002
 * @tc.desc  : 测试当seatSlot不存在于列表中时,无法删除
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, RemoveInvalidAreaDownedEventTest_002, TestSize.Level1) {
    int32_t seatSlot = 5;
    int32_t otherSeatSlot = 6;
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    processor.InvalidAreaDownedEvents_.clear();

    processor.AddInvalidAreaDownedEvent(seatSlot);
    processor.RemoveInvalidAreaDownedEvent(otherSeatSlot);

    ASSERT_EQ(processor.InvalidAreaDownedEvents_.size(), 1);
    ASSERT_EQ(*(processor.InvalidAreaDownedEvents_.begin()), seatSlot);
}
#endif // OHOS_BUILD_EXTERNAL_SCREEN

/**
 * @tc.name: TouchTransformProcessorTest_OnDeviceEnabled_001
 * @tc.desc: Test OnDeviceEnabled function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, OnDeviceEnabled_001, TestSize.Level1)
{
    int32_t deviceId { TEST_DEVICE_ID };
    TouchTransformProcessor processor(deviceId);
    EXPECT_NO_FATAL_FAILURE(processor.OnDeviceEnabled());
}

/**
 * @tc.name: TouchTransformProcessorTest_OnDeviceDisabled_001
 * @tc.desc: Test OnDeviceDisabled function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, OnDeviceDisabled_001, TestSize.Level1)
{
    int32_t deviceId { TEST_DEVICE_ID };
    TouchTransformProcessor processor(deviceId);
    EXPECT_NO_FATAL_FAILURE(processor.OnDeviceDisabled());
    EXPECT_EQ(processor.GetPointerEvent(), nullptr);
}

/**
 * @tc.name: TouchTransformProcessorTest_RecordActiveOperations_001
 * @tc.desc: Test RecordActiveOperations when pointerEvent_ is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, RecordActiveOperations_001, TestSize.Level1)
{
    int32_t deviceId { TEST_DEVICE_ID };
    TouchTransformProcessor processor(deviceId);
    EXPECT_NO_FATAL_FAILURE(processor.RecordActiveOperations());
}

/**
 * @tc.name: TouchTransformProcessorTest_RecordActiveOperations_002
 * @tc.desc: Test RecordActiveOperations with active touches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, RecordActiveOperations_002, TestSize.Level1)
{
    int32_t deviceId { TEST_DEVICE_ID };
    int32_t displayId { TEST_DISPLAY_ID };
    TouchTransformProcessor processor(deviceId);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetTargetDisplayId(displayId);

    PointerEvent::PointerItem item1;
    item1.SetPointerId(TEST_POINTER_ID_1);
    item1.SetPressed(true);
    item1.SetDisplayX(TEST_DISPLAY_X_1);
    item1.SetDisplayY(TEST_DISPLAY_Y_1);
    pointerEvent->UpdatePointerItem(TEST_POINTER_ID_1, item1);

    PointerEvent::PointerItem item2;
    item2.SetPointerId(TEST_POINTER_ID_2);
    item2.SetPressed(false);
    item2.SetDisplayX(TEST_DISPLAY_X_2);
    item2.SetDisplayY(TEST_DISPLAY_Y_2);
    pointerEvent->UpdatePointerItem(TEST_POINTER_ID_2, item2);

    PointerEvent::PointerItem item3;
    item3.SetPointerId(TEST_POINTER_ID_3);
    item3.SetPressed(true);
    item3.SetDisplayX(TEST_DISPLAY_X_3);
    item3.SetDisplayY(TEST_DISPLAY_Y_3);
    pointerEvent->UpdatePointerItem(TEST_POINTER_ID_3, item3);

    processor.pointerEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(processor.RecordActiveOperations());
}

/**
 * @tc.name: TouchTransformProcessorTest_CancelAllTouches_001
 * @tc.desc: Test CancelAllTouches when pointerEvent_ is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, CancelAllTouches_001, TestSize.Level1)
{
    int32_t deviceId { TEST_DEVICE_ID };
    TouchTransformProcessor processor(deviceId);
    EXPECT_NO_FATAL_FAILURE(processor.CancelAllTouches());
}

/**
 * @tc.name: TouchTransformProcessorTest_CancelAllTouches_002
 * @tc.desc: Test CancelAllTouches when inputChannel is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, CancelAllTouches_002, TestSize.Level1)
{
    int32_t deviceId { TEST_DEVICE_ID };
    int32_t displayId { TEST_DISPLAY_ID };
    TouchTransformProcessor processor(deviceId);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetTargetDisplayId(displayId);

    PointerEvent::PointerItem item1;
    item1.SetPointerId(TEST_POINTER_ID_1);
    item1.SetPressed(true);
    item1.SetDisplayX(TEST_DISPLAY_X_1);
    item1.SetDisplayY(TEST_DISPLAY_Y_1);
    pointerEvent->UpdatePointerItem(TEST_POINTER_ID_1, item1);

    processor.pointerEvent_ = pointerEvent;

    EXPECT_NO_FATAL_FAILURE(processor.CancelAllTouches());
}

/**
 * @tc.name: TouchTransformProcessorTest_CancelAllTouches_003
 * @tc.desc: Test CancelAllTouches with active and inactive touches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, CancelAllTouches_003, TestSize.Level1)
{
    int32_t deviceId { TEST_DEVICE_ID };
    int32_t displayId { TEST_DISPLAY_ID };
    int32_t windowId { TEST_WINDOW_ID };
    int32_t agentWindowId { TEST_AGENT_WINDOW_ID };
    TouchTransformProcessor processor(deviceId);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetTargetDisplayId(displayId);
    pointerEvent->SetTargetWindowId(windowId);
    pointerEvent->SetAgentWindowId(agentWindowId);
    pointerEvent->SetDeviceId(deviceId);

    PointerEvent::PointerItem item1;
    item1.SetPointerId(TEST_POINTER_ID_1);
    item1.SetPressed(true);
    item1.SetDisplayX(TEST_DISPLAY_X_1);
    item1.SetDisplayY(TEST_DISPLAY_Y_1);
    item1.SetTargetWindowId(windowId);
    pointerEvent->UpdatePointerItem(TEST_POINTER_ID_1, item1);

    PointerEvent::PointerItem item2;
    item2.SetPointerId(TEST_POINTER_ID_2);
    item2.SetPressed(false);
    item2.SetDisplayX(TEST_DISPLAY_X_2);
    item2.SetDisplayY(TEST_DISPLAY_Y_2);
    item2.SetTargetWindowId(windowId);
    pointerEvent->UpdatePointerItem(TEST_POINTER_ID_2, item2);

    PointerEvent::PointerItem item3;
    item3.SetPointerId(TEST_POINTER_ID_3);
    item3.SetPressed(true);
    item3.SetDisplayX(TEST_DISPLAY_X_3);
    item3.SetDisplayY(TEST_DISPLAY_Y_3);
    item3.SetTargetWindowId(windowId);
    pointerEvent->UpdatePointerItem(TEST_POINTER_ID_3, item3);

    processor.pointerEvent_ = pointerEvent;

    auto eventNormalizeHandler = std::make_shared<EventNormalizeHandler>();
    EXPECT_CALL(*InputHandler, GetEventNormalizeHandler).WillOnce(Return(eventNormalizeHandler));
    EXPECT_CALL(*eventNormalizeHandler, HandleTouchEvent).Times(EXPECTED_TOUCH_EVENT_COUNT);
    EXPECT_CALL(*WIN_MGR_MOCK, UpdateTargetPointer).Times(EXPECTED_TOUCH_EVENT_COUNT);

    EXPECT_NO_FATAL_FAILURE(processor.CancelAllTouches());
}

/**
 * @tc.name: TouchTransformProcessorTest_OnDeviceDisabled_002
 * @tc.desc: Test OnDeviceDisabled with active touches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTestWithMock, OnDeviceDisabled_002, TestSize.Level1)
{
    int32_t deviceId { TEST_DEVICE_ID };
    int32_t displayId { TEST_DISPLAY_ID };
    int32_t windowId { TEST_WINDOW_ID };
    int32_t agentWindowId { TEST_AGENT_WINDOW_ID };
    TouchTransformProcessor processor(deviceId);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetTargetDisplayId(displayId);
    pointerEvent->SetTargetWindowId(windowId);
    pointerEvent->SetAgentWindowId(agentWindowId);
    pointerEvent->SetDeviceId(deviceId);

    PointerEvent::PointerItem item1;
    item1.SetPointerId(TEST_POINTER_ID_1);
    item1.SetPressed(true);
    item1.SetDisplayX(TEST_DISPLAY_X_1);
    item1.SetDisplayY(TEST_DISPLAY_Y_1);
    item1.SetTargetWindowId(windowId);
    pointerEvent->UpdatePointerItem(TEST_POINTER_ID_1, item1);

    PointerEvent::PointerItem item2;
    item2.SetPointerId(TEST_POINTER_ID_2);
    item2.SetPressed(true);
    item2.SetDisplayX(TEST_DISPLAY_X_2);
    item2.SetDisplayY(TEST_DISPLAY_Y_2);
    item2.SetTargetWindowId(windowId);
    pointerEvent->UpdatePointerItem(TEST_POINTER_ID_2, item2);

    processor.pointerEvent_ = pointerEvent;

    auto eventNormalizeHandler = std::make_shared<EventNormalizeHandler>();
    EXPECT_CALL(*InputHandler, GetEventNormalizeHandler).WillOnce(Return(eventNormalizeHandler));
    EXPECT_CALL(*eventNormalizeHandler, HandleTouchEvent).Times(EXPECTED_TOUCH_EVENT_COUNT);
    EXPECT_CALL(*WIN_MGR_MOCK, UpdateTargetPointer).Times(EXPECTED_TOUCH_EVENT_COUNT);
    EXPECT_NO_FATAL_FAILURE(processor.OnDeviceDisabled());
    EXPECT_EQ(processor.GetPointerEvent(), nullptr);
}
} // namespace MMI
} // namespace OHOS