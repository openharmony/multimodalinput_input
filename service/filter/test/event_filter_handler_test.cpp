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

#include <memory>
#include <gtest/gtest.h>

#include "event_filter_handler.h"
#include "event_normalize_handler.h"
#include "event_filter_service.h"
#include "i_input_event_handler.h"
#include "mmi_log.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventFilterHandlerTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class EventFilterHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp() {}
    void TearDown() {}
};

class MyEventFilter : public IRemoteStub<IEventFilter> {
public:
    bool HandleKeyEvent(const std::shared_ptr<KeyEvent> event) override
    {
        return true;
    }
    bool HandlePointerEvent(const std::shared_ptr<PointerEvent> event) override
    {
        return true;
    }
};

/**
 * @tc.name: EventFilterHandlerTest_HandleKeyEvent_001
 * @tc.desc: Verify the HandleKeyEvent and HandleKeyEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_KeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    EventFilterHandler event;
    bool flag = event.HandleKeyEventFilter(keyEvent);
    EXPECT_FALSE(flag);
    EventNormalizeHandler eventNormal;
    auto nextHandler = std::make_shared<EventNormalizeHandler>();
    eventNormal.SetNext(nextHandler);
    eventNormal.HandleKeyEvent(keyEvent);
}

/**
 * @tc.name: EventFilterHandlerTest_Dump_001
 * @tc.desc: Verify the Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_Dump_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFilterHandler event;
    int32_t fd = 0;
    std::vector<std::string> args = {};
    std::vector<std::string> idNames = {};
    event.Dump(fd, args);
    ASSERT_EQ(args, idNames);
}

/**
 * @tc.name: EventFilterHandlerTest_AddInputEventFilter_001
 * @tc.desc: Verify the AddInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_AddInputEventFilter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto event = std::make_shared<EventFilterHandler>();
    EXPECT_NE(event, nullptr);
    sptr<IEventFilter> filter = new (std::nothrow) MyEventFilter();
    EXPECT_NE(filter, nullptr);
    int32_t filterId = 200;
    int32_t priority = 201;
    uint32_t deviceTags = 3;
    int32_t clientPid = 3;
    int32_t ret = event->AddInputEventFilter(filter, filterId, priority, deviceTags, clientPid);
    EXPECT_EQ(ret, RET_OK);

    filterId = 2;
    priority = 5;
    ret = event->AddInputEventFilter(filter, filterId, priority, deviceTags, clientPid);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventFilterHandlerTest_RemoveInputEventFilter_001
 * @tc.desc: Verify the RemoveInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_RemoveInputEventFilter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto event = std::make_shared<EventFilterHandler>();
    EXPECT_NE(event, nullptr);
    sptr<IEventFilter> filter = new (std::nothrow) MyEventFilter();
    EXPECT_NE(filter, nullptr);
    int32_t filterId = -1;
    int32_t clientPid = 12345;
    int32_t result = event->RemoveInputEventFilter(filterId, clientPid);
    EXPECT_EQ(result, RET_OK);

    uint32_t deviceTags = 0;
    int32_t ret = event->AddInputEventFilter(filter, 10, 6, deviceTags, clientPid);
    EXPECT_EQ(ret, RET_OK);
    ret = event->AddInputEventFilter(filter, 1, 5, deviceTags, clientPid);
    EXPECT_EQ(ret, RET_OK);
    result = event->RemoveInputEventFilter(-1, clientPid);
    EXPECT_EQ(result, RET_OK);
    result = event->RemoveInputEventFilter(1, clientPid);
    EXPECT_EQ(result, RET_OK);
    result = event->RemoveInputEventFilter(2, clientPid);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: EventFilterHandlerTest_HandleKeyEventFilter_001
 * @tc.desc: Verify the HandleKeyEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_HandleKeyEventFilter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto event = std::make_shared<EventFilterHandler>();
    EXPECT_NE(event, nullptr);
    sptr<IEventFilter> filter = new (std::nothrow) MyEventFilter();
    EXPECT_NE(filter, nullptr);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    bool flag = event->HandleKeyEventFilter(keyEvent);
    EXPECT_FALSE(flag);

    int32_t filterId = 1;
    int32_t priority = 10;
    uint32_t deviceTags = 0;
    int32_t clientPid = 0;
    int32_t ret = event->AddInputEventFilter(filter, filterId, priority, deviceTags, clientPid);
    EXPECT_EQ(ret, RET_OK);
    flag = event->HandleKeyEventFilter(keyEvent);
    EXPECT_FALSE(flag);

    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    keyEvent->AddKeyItem(item);
    
    flag = event->HandleKeyEventFilter(keyEvent);
    EXPECT_FALSE(flag);
}

/**
 * @tc.name: EventFilterHandlerTest_HandlePointerEventFilter_001
 * @tc.desc: Verify the HandlePointerEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_HandlePointerEventFilter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto event = std::make_shared<EventFilterHandler>();
    EXPECT_NE(event, nullptr);
    sptr<IEventFilter> filter = new (std::nothrow) MyEventFilter();
    EXPECT_NE(filter, nullptr);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    bool flag = event->HandlePointerEventFilter(pointerEvent);
    EXPECT_FALSE(flag);

    int32_t filterId = 1;
    int32_t priority = 10;
    uint32_t deviceTags = 0;
    int32_t clientPid = 0;
    int32_t ret = event->AddInputEventFilter(filter, filterId, priority, deviceTags, clientPid);
    EXPECT_EQ(ret, RET_OK);

    flag = event->HandlePointerEventFilter(pointerEvent);
    EXPECT_FALSE(flag);

    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDisplayX(1);
    item.SetDisplayY(1);
    pointerEvent->AddPointerItem(item);
    
    flag = event->HandlePointerEventFilter(pointerEvent);
    EXPECT_FALSE(flag);
}

/**
 * @tc.name: EventFilterHandlerTest_HandleKeyEvent_002
 * @tc.desc: Verify the HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_HandleKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    EventFilterHandler event;
    KeyEvent::KeyItem item;
    item.SetDeviceId(1);
    keyEvent->AddKeyItem(item);
    bool result = event.HandleKeyEventFilter(keyEvent);
    ASSERT_FALSE(result);
    ASSERT_NO_FATAL_FAILURE(event.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: EventFilterHandlerTest_HandlePointerEvent_001
 * @tc.desc: Verify the HandlePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_HandlePointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    EventFilterHandler event;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetDeviceId(1);
    keyEvent->AddKeyItem(item);
    bool result = event.HandlePointerEventFilter(pointerEvent);
    ASSERT_FALSE(result);
    ASSERT_NO_FATAL_FAILURE(event.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: EventFilterHandlerTest_HandleTouchEvent_001
 * @tc.desc: Verify the HandleTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_HandleTouchEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    EventFilterHandler event;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetDeviceId(1);
    keyEvent->AddKeyItem(item);
    bool result = event.HandlePointerEventFilter(pointerEvent);
    ASSERT_FALSE(result);
    ASSERT_NO_FATAL_FAILURE(event.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventFilterHandlerTest_HandlePointerEventFilter_002
 * @tc.desc: Verify the HandlePointerEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_HandlePointerEventFilter_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    EXPECT_NE(event, nullptr);
    EventFilterHandler handler;
    bool result = handler.HandlePointerEventFilter(event);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: EventFilterHandlerTest_HandlePointerEventFilter_003
 * @tc.desc: Verify the HandlePointerEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_HandlePointerEventFilter_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    EXPECT_NE(event, nullptr);
    EventFilterHandler handler;
    EventFilterHandler::FilterInfo filter1 = {nullptr, nullptr, 1, 10, 0x1, 100};
    EventFilterHandler::FilterInfo filter2 = {nullptr, nullptr, 2, 20, 0x2, 200};
    EventFilterHandler::FilterInfo filter3 = {nullptr, nullptr, 3, 30, 0x3, 300};
    handler.filters_.push_back(filter1);
    handler.filters_.push_back(filter2);
    handler.filters_.push_back(filter3);
    ASSERT_EQ(handler.filters_.size(), 3);
    ASSERT_TRUE(handler.filters_.front().IsSameClient(1, 100));
    ASSERT_TRUE(handler.filters_.back().IsSameClient(3, 300));
    bool result = handler.HandlePointerEventFilter(event);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: EventFilterHandlerTest_HandlePointerEventFilter_004
 * @tc.desc: Verify the HandlePointerEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_HandlePointerEventFilter_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    EXPECT_NE(event, nullptr);
    EventFilterHandler handler;
    EventFilterHandler::FilterInfo filter1 = {nullptr, nullptr, 1, 10, 0x1, 100};
    EventFilterHandler::FilterInfo filter2 = {nullptr, nullptr, 2, 20, 0x2, 200};
    EventFilterHandler::FilterInfo filter3 = {nullptr, nullptr, 3, 30, 0x3, 300};
    handler.filters_.push_back(filter1);
    handler.filters_.push_back(filter2);
    handler.filters_.push_back(filter3);
    ASSERT_EQ(handler.filters_.size(), 3);
    ASSERT_TRUE(handler.filters_.front().IsSameClient(1, 100));
    ASSERT_TRUE(handler.filters_.back().IsSameClient(3, 300));
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    event->AddPointerItem(item);
    event->SetPointerId(1);
    bool result = handler.HandlePointerEventFilter(event);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: EventFilterHandlerTest_HandleKeyEventFilter_002
 * @tc.desc: Verify the HandleKeyEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_HandleKeyEventFilter_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    EXPECT_NE(event, nullptr);
    EventFilterHandler handler;
    bool result = handler.HandleKeyEventFilter(event);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: EventFilterHandlerTest_HandleKeyEventFilter_003
 * @tc.desc: Verify the HandleKeyEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_HandleKeyEventFilter_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    EXPECT_NE(event, nullptr);
    EventFilterHandler handler;
    EventFilterHandler::FilterInfo filter1 = {nullptr, nullptr, 1, 10, 0x1, 100};
    EventFilterHandler::FilterInfo filter2 = {nullptr, nullptr, 2, 20, 0x2, 200};
    EventFilterHandler::FilterInfo filter3 = {nullptr, nullptr, 3, 30, 0x3, 300};
    handler.filters_.push_back(filter1);
    handler.filters_.push_back(filter2);
    handler.filters_.push_back(filter3);
    ASSERT_EQ(handler.filters_.size(), 3);
    ASSERT_TRUE(handler.filters_.front().IsSameClient(1, 100));
    ASSERT_TRUE(handler.filters_.back().IsSameClient(3, 300));
    bool result = handler.HandleKeyEventFilter(event);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: EventFilterHandlerTest_HandleKeyEventFilter_004
 * @tc.desc: Verify the HandleKeyEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerTest, EventFilterHandlerTest_HandleKeyEventFilter_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    EXPECT_NE(event, nullptr);
    std::shared_ptr<PointerEvent> pointevent = PointerEvent::Create();
    EXPECT_NE(pointevent, nullptr);
    EventFilterHandler handler;
    EventFilterHandler::FilterInfo filter1 = {nullptr, nullptr, 1, 10, 0x1, 100};
    EventFilterHandler::FilterInfo filter2 = {nullptr, nullptr, 2, 20, 0x2, 200};
    EventFilterHandler::FilterInfo filter3 = {nullptr, nullptr, 3, 30, 0x3, 300};
    handler.filters_.push_back(filter1);
    handler.filters_.push_back(filter2);
    handler.filters_.push_back(filter3);
    ASSERT_EQ(handler.filters_.size(), 3);
    ASSERT_TRUE(handler.filters_.front().IsSameClient(1, 100));
    ASSERT_TRUE(handler.filters_.back().IsSameClient(3, 300));
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointevent->AddPointerItem(item);
    pointevent->SetPointerId(1);
    bool result = handler.HandleKeyEventFilter(event);
    ASSERT_FALSE(result);
}
} // namespace MMI
} // namespace OHOS