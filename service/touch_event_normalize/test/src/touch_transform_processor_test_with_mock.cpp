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

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t FIRST_POINTER_ID { 0 };
constexpr int32_t TIME_WAIT_FOR_OP { 50 };
}
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
    InputWindowsManagerMock::ReleaseInstance();
}

void TouchTransformProcessorTestWithMock::SetUp()
{}

void TouchTransformProcessorTestWithMock::TearDown()
{}

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
 * @tc.desc: Test the funcation OnEventTouchDown
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
    ASSERT_EQ(*(processor.InvalidAreaDownedEvents_.end()), seatSlot);
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
} // namespace MMI
} // namespace OHOS