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

#include <gtest/gtest.h>

#include "i_input_event_consumer.h"
#include "input_handler_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputHandlerManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t TEN_FINGERS { 10 };
constexpr int32_t THREE_FINGERS { 3 };
constexpr int32_t FOUR_FINGERS { 4 };
} // namespace

class InputHandlerManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};


class MyInputHandlerManager : public InputHandlerManager {
public:
    MyInputHandlerManager() = default;
    ~MyInputHandlerManager() override = default;

protected:
    InputHandlerType GetHandlerType() const override
    {
        return InputHandlerType::INTERCEPTOR;
    }
};

class MYInputHandlerManager : public InputHandlerManager {
public:
    MYInputHandlerManager() = default;
    ~MYInputHandlerManager() override = default;

protected:
    InputHandlerType GetHandlerType() const override
    {
        return InputHandlerType::MONITOR;
    }
};

/**
 * @tc.name: InputHandlerManagerTest_FindHandler_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_FindHandler_001, TestSize.Level2)
{
    MyInputHandlerManager manager;
    int32_t handlerId = 1;
    ASSERT_NO_FATAL_FAILURE(manager.FindHandler(handlerId));
    handlerId = -1;
    ASSERT_NO_FATAL_FAILURE(manager.FindHandler(handlerId));
}

/**
 * @tc.name: InputHandlerManagerTest_AddMouseEventId_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_AddMouseEventId_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    ASSERT_NO_FATAL_FAILURE(manager.AddMouseEventId(pointerEvent));
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ASSERT_NO_FATAL_FAILURE(manager.AddMouseEventId(pointerEvent));
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    ASSERT_NO_FATAL_FAILURE(manager.AddMouseEventId(pointerEvent));
}

/**
 * @tc.name: InputHandlerManagerTest_HasHandler_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_HasHandler_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    int32_t handlerId = 1;
    ASSERT_NO_FATAL_FAILURE(manager.HasHandler(handlerId));
    handlerId = -1;
    ASSERT_NO_FATAL_FAILURE(manager.HasHandler(handlerId));
}

/**
 * @tc.name: InputHandlerManagerTest_OnDispatchEventProcessed_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_OnDispatchEventProcessed_001, TestSize.Level3)
{
    MyInputHandlerManager manager;
    int32_t eventId = 1;
    int64_t actionTime = 2;
    ASSERT_NO_FATAL_FAILURE(manager.OnDispatchEventProcessed(eventId, actionTime));
    eventId = -1;
    actionTime = -2;
    ASSERT_NO_FATAL_FAILURE(manager.OnDispatchEventProcessed(eventId, actionTime));
}

/**
 * @tc.name: InputHandlerManagerTest_OnDispatchEventProcessed_002
 * @tc.desc: Test the funcation OnDispatchEventProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_OnDispatchEventProcessed_002, TestSize.Level1)
{
    MyInputHandlerManager manager;
    int32_t eventId = 2;
    int64_t actionTime = 3;
    manager.mouseEventIds_.insert(10);
    ASSERT_NO_FATAL_FAILURE(manager.OnDispatchEventProcessed(eventId, actionTime));
    eventId = 10;
    ASSERT_NO_FATAL_FAILURE(manager.OnDispatchEventProcessed(eventId, actionTime));
}

/**
 * @tc.name: InputHandlerManagerTest_GetNextId_001
 * @tc.desc: Verify GetNextId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_GetNextId_001, TestSize.Level3)
{
    MyInputHandlerManager manager;
    manager.nextId_ = std::numeric_limits<int32_t>::max();
    int32_t result = manager.GetNextId();
    ASSERT_EQ(result, INVALID_HANDLER_ID);
}

/**
 * @tc.name: InputHandlerManagerTest_GetNextId_002
 * @tc.desc: Verify GetNextId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_GetNextId_002, TestSize.Level2)
{
    MyInputHandlerManager manager;
    manager.nextId_ = 5;
    int32_t result = manager.GetNextId();
    ASSERT_EQ(result, 5);
}

/**
 * @tc.name: InputHandlerManagerTest_FindHandler_002
 * @tc.desc: Verify FindHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_FindHandler_002, TestSize.Level1)
{
    MYInputHandlerManager manager;
    int32_t handlerId = 1;
    InputHandlerManager::Handler handler;
    std::shared_ptr<IInputEventConsumer> consumer = nullptr;
    handler.consumer_ = consumer;
    manager.monitorHandlers_[handlerId] = handler;
    std::shared_ptr<IInputEventConsumer> result = manager.FindHandler(handlerId);
    ASSERT_EQ(result, consumer);
}

/**
 * @tc.name: InputHandlerManagerTest_FindHandler_003
 * @tc.desc: Verify FindHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_FindHandler_003, TestSize.Level2)
{
    MYInputHandlerManager manager;
    int32_t handlerId = 1;
    std::shared_ptr<IInputEventConsumer> result = manager.FindHandler(handlerId);
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputHandlerManagerTest_FindHandler_004
 * @tc.desc: Verify FindHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_FindHandler_004, TestSize.Level1)
{
    MyInputHandlerManager manager;
    int32_t handlerId = 1;
    InputHandlerManager::Handler handler;
    handler.handlerId_ = 1;
    manager.interHandlers_.push_back(handler);
    std::shared_ptr<IInputEventConsumer> result = manager.FindHandler(handlerId);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: InputHandlerManagerTest_FindHandler_005
 * @tc.desc: Verify FindHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_FindHandler_005, TestSize.Level1)
{
    MyInputHandlerManager manager;
    int32_t handlerId = 5;
    InputHandlerManager::Handler handler;
    handler.handlerId_ = 1;
    manager.interHandlers_.push_back(handler);
    std::shared_ptr<IInputEventConsumer> result = manager.FindHandler(handlerId);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: InputHandlerManagerTest_OnDispatchEventProcessed_003
 * @tc.desc: Verify OnDispatchEventProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_OnDispatchEventProcessed_003, TestSize.Level2)
{
    MyInputHandlerManager manager;
    int32_t eventId = 4;
    int64_t actionTime = 2;
    manager.mouseEventIds_.insert(1);
    manager.mouseEventIds_.insert(2);
    manager.mouseEventIds_.insert(3);
    ASSERT_NO_FATAL_FAILURE(manager.OnDispatchEventProcessed(eventId, actionTime));
}

/**
 * @tc.name: InputHandlerManagerTest_OnDispatchEventProcessed_004
 * @tc.desc: Verify OnDispatchEventProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_OnDispatchEventProcessed_004, TestSize.Level2)
{
    MyInputHandlerManager manager;
    int32_t eventId = 10;
    int64_t actionTime = 2;
    manager.mouseEventIds_.insert(1);
    manager.mouseEventIds_.insert(2);
    manager.mouseEventIds_.insert(3);
    ASSERT_NO_FATAL_FAILURE(manager.OnDispatchEventProcessed(eventId, actionTime));
}

/**
 * @tc.name: InputHandlerManagerTest_OnDispatchEventProcessed_005
 * @tc.desc: Verify OnDispatchEventProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_OnDispatchEventProcessed_005, TestSize.Level1)
{
    MyInputHandlerManager manager;
    int32_t eventId = 1;
    int64_t actionTime = 2;
    manager.mouseEventIds_.insert(2);
    manager.mouseEventIds_.insert(3);
    ASSERT_NO_FATAL_FAILURE(manager.OnDispatchEventProcessed(eventId, actionTime));
}

/**
 * @tc.name: InputHandlerManagerTest_OnDispatchEventProcessed_006
 * @tc.desc: Verify OnDispatchEventProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_OnDispatchEventProcessed_006, TestSize.Level3)
{
    MyInputHandlerManager manager;
    int32_t eventId = 2;
    int64_t actionTime = 2;
    manager.mouseEventIds_.insert(1);
    manager.mouseEventIds_.insert(2);
    manager.mouseEventIds_.insert(3);
    ASSERT_NO_FATAL_FAILURE(manager.OnDispatchEventProcessed(eventId, actionTime));
}

/**
 * @tc.name: InputHandlerManagerTest_CheckInputDeviceSource_001
 * @tc.desc: Verify CheckInputDeviceSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_CheckInputDeviceSource_001, TestSize.Level2)
{
    MyInputHandlerManager manager;
    uint32_t deviceTags = 4;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    bool result = manager.CheckInputDeviceSource(pointerEvent, deviceTags);
    ASSERT_TRUE(result);
    deviceTags = 5;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    result = manager.CheckInputDeviceSource(pointerEvent, deviceTags);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: InputHandlerManagerTest_CheckInputDeviceSource_002
 * @tc.desc: Verify CheckInputDeviceSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_CheckInputDeviceSource_002, TestSize.Level1)
{
    MyInputHandlerManager manager;
    uint32_t deviceTags = 2;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    bool result = manager.CheckInputDeviceSource(pointerEvent, deviceTags);
    ASSERT_TRUE(result);
    deviceTags = 3;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    result = manager.CheckInputDeviceSource(pointerEvent, deviceTags);
    ASSERT_TRUE(result);
    deviceTags = 2;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    result = manager.CheckInputDeviceSource(pointerEvent, deviceTags);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: InputHandlerManagerTest_CheckInputDeviceSource_003
 * @tc.desc: Verify CheckInputDeviceSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_CheckInputDeviceSource_003, TestSize.Level1)
{
    MyInputHandlerManager manager;
    uint32_t deviceTags = 2;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    bool result = manager.CheckInputDeviceSource(pointerEvent, deviceTags);
    ASSERT_FALSE(result);
    deviceTags = 10;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    result = manager.CheckInputDeviceSource(pointerEvent, deviceTags);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: InputHandlerManagerTest_RecoverPointerEvent
 * @tc.desc: Test RecoverPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_RecoverPointerEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MYInputHandlerManager inputHdlMgr;
    inputHdlMgr.lastPointerEvent_ = PointerEvent::Create();
    ASSERT_NE(inputHdlMgr.lastPointerEvent_, nullptr);
    inputHdlMgr.lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    std::initializer_list<int32_t> pointerActionEvents { PointerEvent::POINTER_ACTION_DOWN,
        PointerEvent::POINTER_ACTION_UP };
    int32_t pointerActionEvent = PointerEvent::POINTER_ACTION_DOWN;
    inputHdlMgr.lastPointerEvent_->SetPointerId(0);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    inputHdlMgr.lastPointerEvent_->AddPointerItem(item);
    EXPECT_FALSE(inputHdlMgr.RecoverPointerEvent(pointerActionEvents, pointerActionEvent));

    inputHdlMgr.lastPointerEvent_->SetPointerId(1);
    EXPECT_TRUE(inputHdlMgr.RecoverPointerEvent(pointerActionEvents, pointerActionEvent));

    inputHdlMgr.lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    EXPECT_FALSE(inputHdlMgr.RecoverPointerEvent(pointerActionEvents, pointerActionEvent));
}

/**
 * @tc.name: InputHandlerManagerTest_OnDisconnected
 * @tc.desc: Test OnDisconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_OnDisconnected, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    MYInputHandlerManager inputHdlMgr;
    inputHdlMgr.lastPointerEvent_ = PointerEvent::Create();
    ASSERT_NE(inputHdlMgr.lastPointerEvent_, nullptr);
    inputHdlMgr.lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    inputHdlMgr.lastPointerEvent_->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    inputHdlMgr.lastPointerEvent_->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(inputHdlMgr.OnDisconnected());

    inputHdlMgr.lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    EXPECT_NO_FATAL_FAILURE(inputHdlMgr.OnDisconnected());
}

/**
 * @tc.name: InputHandlerManagerTest_IsMatchGesture_001
 * @tc.desc: Overrides the IsMatchGesture function branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_IsMatchGesture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MYInputHandlerManager inputHdlMgr;
    InputHandlerManager::Handler handler;
    handler.eventType_ = 0;
    int32_t action = PointerEvent::TOUCH_ACTION_SWIPE_DOWN;
    int32_t count = 1;
    EXPECT_TRUE(inputHdlMgr.IsMatchGesture(handler, action, count));
    handler.eventType_ = HANDLE_EVENT_TYPE_TOUCH_GESTURE;
    handler.handlerId_ = 100;
    handler.gestureHandler_.gestureType = TOUCH_GESTURE_TYPE_SWIPE;
    handler.gestureHandler_.fingers = 1;
    inputHdlMgr.monitorHandlers_.insert(std::make_pair(50, handler));
    EXPECT_FALSE(inputHdlMgr.IsMatchGesture(handler, action, count));
    inputHdlMgr.monitorHandlers_.insert(std::make_pair(100, handler));
    EXPECT_TRUE(inputHdlMgr.IsMatchGesture(handler, action, count));
    action = PointerEvent::TOUCH_ACTION_SWIPE_UP;
    handler.gestureHandler_.fingers = ALL_FINGER_COUNT;
    inputHdlMgr.monitorHandlers_[1] = handler;
    EXPECT_TRUE(inputHdlMgr.IsMatchGesture(handler, action, count));
    action = PointerEvent::TOUCH_ACTION_SWIPE_RIGHT;
    EXPECT_TRUE(inputHdlMgr.IsMatchGesture(handler, action, count));
    action = PointerEvent::TOUCH_ACTION_SWIPE_LEFT;
    EXPECT_TRUE(inputHdlMgr.IsMatchGesture(handler, action, count));
    action = PointerEvent::TOUCH_ACTION_PINCH_OPENED;
    handler.gestureHandler_.gestureType = TOUCH_GESTURE_TYPE_PINCH;
    handler.gestureHandler_.gestureState = false;
    inputHdlMgr.monitorHandlers_[1] = handler;
    EXPECT_FALSE(inputHdlMgr.IsMatchGesture(handler, action, count));
    action = PointerEvent::TOUCH_ACTION_PINCH_CLOSEED;
    EXPECT_FALSE(inputHdlMgr.IsMatchGesture(handler, action, count));
    action = PointerEvent::TOUCH_ACTION_GESTURE_END;
    EXPECT_TRUE(inputHdlMgr.IsMatchGesture(handler, action, count));
    action = PointerEvent::TOUCH_ACTION_GESTURE_END;
    handler.gestureHandler_.gestureState = true;
    inputHdlMgr.monitorHandlers_[1] = handler;
    EXPECT_FALSE(inputHdlMgr.IsMatchGesture(handler, action, count));
    action = 0;
    EXPECT_FALSE(inputHdlMgr.IsMatchGesture(handler, action, count));
}

/**
 * @tc.name: InputHandlerManagerTest_HasHandler_002
 * @tc.desc: Test the funcation HasHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_HasHandler_002, TestSize.Level1)
{
    MyInputHandlerManager manager;
    int32_t handlerId = 2;
    InputHandlerManager::Handler handler;
    handler.handlerId_ = 2;
    manager.interHandlers_.push_back(handler);
    bool ret = manager.HasHandler(handlerId);
    ASSERT_TRUE(ret);
    handlerId = 3;
    ret = manager.HasHandler(handlerId);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InputHandlerManagerTest_CheckInputDeviceSource_004
 * @tc.desc: Test the funcation CheckInputDeviceSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_CheckInputDeviceSource_004, TestSize.Level2)
{
    MyInputHandlerManager manager;
    uint32_t deviceTags = 1;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    bool result = manager.CheckInputDeviceSource(pointerEvent, deviceTags);
    ASSERT_FALSE(result);
    deviceTags = 2;
    result = manager.CheckInputDeviceSource(pointerEvent, deviceTags);
    ASSERT_FALSE(result);
    deviceTags = 4;
    result = manager.CheckInputDeviceSource(pointerEvent, deviceTags);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: InputHandlerManagerTest_IsPinchType_001
 * @tc.desc: Test the funcation IsPinchType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_IsPinchType_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    bool ret = manager.IsPinchType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ret = manager.IsPinchType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    ret = manager.IsPinchType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    ret = manager.IsPinchType(pointerEvent);
    ASSERT_FALSE(ret);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    ret = manager.IsPinchType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ret = manager.IsPinchType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    ret = manager.IsPinchType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    ret = manager.IsPinchType(pointerEvent);
    ASSERT_FALSE(ret);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    ret = manager.IsPinchType(pointerEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InputHandlerManagerTest_IsRotateType_001
 * @tc.desc: Test the funcation IsRotateType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_IsRotateType_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_BEGIN);
    bool ret = manager.IsRotateType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_UPDATE);
    ret = manager.IsRotateType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_END);
    ret = manager.IsRotateType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    ret = manager.IsRotateType(pointerEvent);
    ASSERT_FALSE(ret);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ret = manager.IsRotateType(pointerEvent);
    ASSERT_FALSE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_UPDATE);
    ret = manager.IsRotateType(pointerEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InputHandlerManagerTest_IsThreeFingersSwipeType_001
 * @tc.desc: Test the funcation IsThreeFingersSwipeType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_IsThreeFingersSwipeType_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetFingerCount(THREE_FINGERS);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    bool ret = manager.IsThreeFingersSwipeType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ret = manager.IsThreeFingersSwipeType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_END);
    ret = manager.IsThreeFingersSwipeType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_BEGIN);
    ret = manager.IsThreeFingersSwipeType(pointerEvent);
    ASSERT_FALSE(ret);
    pointerEvent->SetFingerCount(TEN_FINGERS);
    ret = manager.IsThreeFingersSwipeType(pointerEvent);
    ASSERT_FALSE(ret);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    ret = manager.IsThreeFingersSwipeType(pointerEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InputHandlerManagerTest_IsFourFingersSwipeType_001
 * @tc.desc: Test the funcation IsFourFingersSwipeType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_IsFourFingersSwipeType_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetFingerCount(FOUR_FINGERS);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    bool ret = manager.IsFourFingersSwipeType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ret = manager.IsFourFingersSwipeType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_END);
    ret = manager.IsFourFingersSwipeType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_BEGIN);
    ret = manager.IsFourFingersSwipeType(pointerEvent);
    ASSERT_FALSE(ret);
    pointerEvent->SetFingerCount(TEN_FINGERS);
    ret = manager.IsThreeFingersSwipeType(pointerEvent);
    ASSERT_FALSE(ret);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    ret = manager.IsFourFingersSwipeType(pointerEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InputHandlerManagerTest_IsThreeFingersTapType_001
 * @tc.desc: Test the funcation IsThreeFingersTapType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_IsThreeFingersTapType_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetFingerCount(THREE_FINGERS);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    bool ret = manager.IsThreeFingersTapType(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ret = manager.IsThreeFingersTapType(pointerEvent);
    ASSERT_FALSE(ret);
    pointerEvent->SetFingerCount(TEN_FINGERS);
    ret = manager.IsThreeFingersTapType(pointerEvent);
    ASSERT_FALSE(ret);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    ret = manager.IsThreeFingersTapType(pointerEvent);
    ASSERT_FALSE(ret);
}

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
/**
 * @tc.name: InputHandlerManagerTest_IsFingerprintType_001
 * @tc.desc: Test the funcation IsFingerprintType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_IsFingerprintType_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_EXIT);
    bool ret = manager.IsFingerprintType(pointerEvent);
    ASSERT_FALSE(ret);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_FINGERPRINT);
    ret = manager.IsFingerprintType(pointerEvent);
    ASSERT_FALSE(ret);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE);
    ret = manager.IsFingerprintType(pointerEvent);
    ASSERT_TRUE(ret);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_CLICK);
    ret = manager.IsFingerprintType(pointerEvent);
    ASSERT_TRUE(ret);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_CANCEL);
    ret = manager.IsFingerprintType(pointerEvent);
    ASSERT_TRUE(ret);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_HOLD);
    ret = manager.IsFingerprintType(pointerEvent);
    ASSERT_TRUE(ret);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_TOUCH);
    ret = manager.IsFingerprintType(pointerEvent);
    ASSERT_TRUE(ret);
}
#endif // OHOS_BUILD_ENABLE_FINGERPRINT

#ifdef OHOS_BUILD_ENABLE_X_KEY
/**
 * @tc.name: InputHandlerManagerTest_IsXKeyType_001
 * @tc.desc: Test the funcation IsXKeyType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_IsXKeyType_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    bool ret = manager.IsXKeyType(pointerEvent);
    ASSERT_FALSE(ret);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_X_KEY);
    ret = manager.IsXKeyType(pointerEvent);
    ASSERT_TRUE(ret);
}
#endif // OHOS_BUILD_ENABLE_X_KEY

/**
 * @tc.name: InputHandlerManagerTest_CheckIfNeedAddToConsumerInfos_001
 * @tc.desc: Test the funcation CheckIfNeedAddToConsumerInfos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_CheckIfNeedAddToConsumerInfos_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    InputHandlerManager::Handler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    handler.eventType_ = HANDLE_EVENT_TYPE_POINTER;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetFingerCount(THREE_FINGERS);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    bool ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_TRUE(ret);

    handler.eventType_ = HANDLE_EVENT_TYPE_TOUCH_GESTURE;
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_TRUE(ret);

    handler.eventType_ = HANDLE_EVENT_TYPE_SWIPEINWARD;
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_TRUE(ret);

    handler.eventType_ = HANDLE_EVENT_TYPE_TOUCH;
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_FALSE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_TRUE(ret);

    handler.eventType_ = HANDLE_EVENT_TYPE_MOUSE;
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_FALSE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InputHandlerManagerTest_CheckIfNeedAddToConsumerInfos_002
 * @tc.desc: Test the funcation CheckIfNeedAddToConsumerInfos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_CheckIfNeedAddToConsumerInfos_002, TestSize.Level1)
{
    MyInputHandlerManager manager;
    InputHandlerManager::Handler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetFingerCount(THREE_FINGERS);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);

    handler.eventType_ = HANDLE_EVENT_TYPE_PINCH;
    auto ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_FALSE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_TRUE(ret);

    handler.eventType_ = HANDLE_EVENT_TYPE_THREEFINGERSSWIP;
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_FALSE(ret);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_TRUE(ret);

    handler.eventType_ = HANDLE_EVENT_TYPE_FOURFINGERSSWIP;
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_FALSE(ret);

    pointerEvent->SetFingerCount(FOUR_FINGERS);
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InputHandlerManagerTest_CheckIfNeedAddToConsumerInfos_003
 * @tc.desc: Test the funcation CheckIfNeedAddToConsumerInfos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_CheckIfNeedAddToConsumerInfos_003, TestSize.Level1)
{
    MyInputHandlerManager manager;
    InputHandlerManager::Handler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    handler.eventType_ = HANDLE_EVENT_TYPE_ROTATE;
    auto ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_FALSE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_BEGIN);
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_TRUE(ret);

    handler.eventType_ = HANDLE_EVENT_TYPE_THREEFINGERSTAP;
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_FALSE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    pointerEvent->SetFingerCount(THREE_FINGERS);
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_TRUE(ret);

    #ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    handler.eventType_ = HANDLE_EVENT_TYPE_FINGERPRINT;
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_TRUE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_FINGERPRINT);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_HOLD);
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_TRUE(ret);
    #endif

    #ifdef OHOS_BUILD_ENABLE_X_KEY
    handler.eventType_ = HANDLE_EVENT_TYPE_X_KEY;
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_TRUE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_X_KEY);
    ret = manager.CheckIfNeedAddToConsumerInfos(handler, pointerEvent);
    ASSERT_TRUE(ret);
    #endif
}
} // namespace MMI
} // namespace OHOS