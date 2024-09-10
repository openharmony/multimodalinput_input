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
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_FindHandler_001, TestSize.Level1)
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
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_OnDispatchEventProcessed_001, TestSize.Level1)
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
 * @tc.name: InputHandlerManagerTest_AddProcessedEventId_001
 * @tc.desc:Test the funcation AddProcessedEventId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_AddProcessedEventId_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    int32_t consumerCount = 1;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ASSERT_NO_FATAL_FAILURE(manager.AddProcessedEventId(pointerEvent, consumerCount));
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    ASSERT_NO_FATAL_FAILURE(manager.AddProcessedEventId(pointerEvent, consumerCount));
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    ASSERT_NO_FATAL_FAILURE(manager.AddProcessedEventId(pointerEvent, consumerCount));
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
    manager.processedEvents_.insert(std::make_pair(10, 10));
    ASSERT_NO_FATAL_FAILURE(manager.OnDispatchEventProcessed(eventId, actionTime));
    manager.processedEvents_.insert(std::make_pair(5, 8));
    ASSERT_NO_FATAL_FAILURE(manager.OnDispatchEventProcessed(eventId, actionTime));
}

/**
 * @tc.name: InputHandlerManagerTest_GetNextId_001
 * @tc.desc: Verify GetNextId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_GetNextId_001, TestSize.Level1)
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
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_GetNextId_002, TestSize.Level1)
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
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_FindHandler_003, TestSize.Level1)
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
 * @tc.name: InputHandlerManagerTest_AddProcessedEventId_002
 * @tc.desc: Verify AddProcessedEventId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_AddProcessedEventId_002, TestSize.Level1)
{
    MyInputHandlerManager manager;
    int32_t consumerCount = 1;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ASSERT_NO_FATAL_FAILURE(manager.AddProcessedEventId(pointerEvent, consumerCount));
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    ASSERT_NO_FATAL_FAILURE(manager.AddProcessedEventId(pointerEvent, consumerCount));
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_CROWN);
    ASSERT_NO_FATAL_FAILURE(manager.AddProcessedEventId(pointerEvent, consumerCount));
}

/**
 * @tc.name: InputHandlerManagerTest_OnDispatchEventProcessed_003
 * @tc.desc: Verify OnDispatchEventProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_OnDispatchEventProcessed_003, TestSize.Level1)
{
    MyInputHandlerManager manager;
    int32_t eventId = 4;
    int64_t actionTime = 2;
    manager.mouseEventIds_.insert(1);
    manager.mouseEventIds_.insert(2);
    manager.mouseEventIds_.insert(3);
    manager.processedEvents_[1] = 100;
    manager.processedEvents_[2] = 200;
    manager.processedEvents_[3] = 300;
    manager.processedEvents_[4] = 400;
    ASSERT_NO_FATAL_FAILURE(manager.OnDispatchEventProcessed(eventId, actionTime));
}

/**
 * @tc.name: InputHandlerManagerTest_OnDispatchEventProcessed_004
 * @tc.desc: Verify OnDispatchEventProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_OnDispatchEventProcessed_004, TestSize.Level1)
{
    MyInputHandlerManager manager;
    int32_t eventId = 10;
    int64_t actionTime = 2;
    manager.mouseEventIds_.insert(1);
    manager.mouseEventIds_.insert(2);
    manager.mouseEventIds_.insert(3);
    manager.processedEvents_[1] = 100;
    manager.processedEvents_[2] = 200;
    manager.processedEvents_[3] = 300;
    manager.processedEvents_[4] = 400;
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
    manager.processedEvents_[2] = 200;
    manager.processedEvents_[3] = 300;
    manager.processedEvents_[4] = 400;
    ASSERT_NO_FATAL_FAILURE(manager.OnDispatchEventProcessed(eventId, actionTime));
}

/**
 * @tc.name: InputHandlerManagerTest_OnDispatchEventProcessed_006
 * @tc.desc: Verify OnDispatchEventProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_OnDispatchEventProcessed_006, TestSize.Level1)
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
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_CheckInputDeviceSource_001, TestSize.Level1)
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
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_CROWN);
    bool result = manager.CheckInputDeviceSource(pointerEvent, deviceTags);
    ASSERT_FALSE(result);
    deviceTags = 10;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_CROWN);
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
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_OnDisconnected, TestSize.Level1)
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
} // namespace MMI
} // namespace OHOS