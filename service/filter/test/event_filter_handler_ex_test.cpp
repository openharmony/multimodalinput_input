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
#include "mock.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventFilterHandlerTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
} // namespace

class EventFilterHandlerExTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() {}
    void TearDown() {}
    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void EventFilterHandlerExTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}
void EventFilterHandlerExTest::TearDownTestCase()
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}

class MyEventFilter : public IRemoteStub<IEventFilter> {
public:
    ErrCode HandleKeyEvent(const std::shared_ptr<KeyEvent>& event, bool &resultValue) override
    {
        resultValue = true;
        return ERR_OK;
    }
    ErrCode HandlePointerEvent(const std::shared_ptr<PointerEvent>& event, bool &resultValue) override
    {
        resultValue = true;
        return ERR_OK;
    }
};

/**
 * @tc.name: EventFilterHandlerExTest_HandleKeyEventFilter
 * @tc.desc: Verify the HandleKeyEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerExTest, EventFilterHandlerExTest_HandleKeyEventFilter, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillRepeatedly(Return(inputDevice));
    EXPECT_CALL(*messageParcelMock_, HasCapability(_)).WillRepeatedly(Return(false));
    EventFilterHandler filterHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    sptr<IEventFilter> filter = new (std::nothrow) MyEventFilter();
    ASSERT_NE(filter, nullptr);
    KeyEvent::KeyItem keyItem;
    keyItem.SetKeyCode(2042);
    keyEvent->AddKeyItem(keyItem);
    EventFilterHandler::FilterInfo filterInfo = { filter, nullptr, 500, 200, 100, 300 };
    filterHandler.filters_.emplace_front(filterInfo);
    EXPECT_FALSE(filterHandler.HandleKeyEventFilter(keyEvent));
}

/**
 * @tc.name: EventFilterHandlerExTest_HandleKeyEventFilter_001
 * @tc.desc: Verify the HandleKeyEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerExTest, EventFilterHandlerExTest_HandleKeyEventFilter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillRepeatedly(Return(inputDevice));
    EXPECT_CALL(*messageParcelMock_, HasCapability(_)).WillRepeatedly(Return(true));
    EventFilterHandler filterHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    sptr<IEventFilter> filter = new (std::nothrow) MyEventFilter();
    ASSERT_NE(filter, nullptr);
    KeyEvent::KeyItem keyItem;
    keyItem.SetKeyCode(2042);
    keyEvent->AddKeyItem(keyItem);
    EventFilterHandler::FilterInfo filterInfo = { filter, nullptr, 500, 200, 100, 300 };
    filterHandler.filters_.emplace_front(filterInfo);
    EXPECT_TRUE(filterHandler.HandleKeyEventFilter(keyEvent));
}

/**
 * @tc.name: EventFilterHandlerExTest_HandlePointerEventFilter
 * @tc.desc: Verify the HandlePointerEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerExTest, EventFilterHandlerExTest_HandlePointerEventFilter, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillRepeatedly(Return(inputDevice));
    EXPECT_CALL(*messageParcelMock_, HasCapability(_)).WillRepeatedly(Return(false));
    EventFilterHandler filterHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    sptr<IEventFilter> filter = new (std::nothrow) MyEventFilter();
    ASSERT_NE(filter, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(100);
    pointerEvent->SetPointerId(100);
    pointerEvent->AddPointerItem(item);
    EventFilterHandler::FilterInfo filterInfo = { filter, nullptr, 500, 200, 100, 300 };
    filterHandler.filters_.emplace_front(filterInfo);
    EXPECT_FALSE(filterHandler.HandlePointerEventFilter(pointerEvent));
}

/**
 * @tc.name: EventFilterHandlerExTest_HandlePointerEventFilter_001
 * @tc.desc: Verify the HandlePointerEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterHandlerExTest, EventFilterHandlerExTest_HandlePointerEventFilter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillRepeatedly(Return(inputDevice));
    EXPECT_CALL(*messageParcelMock_, HasCapability(_)).WillRepeatedly(Return(true));
    EventFilterHandler filterHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    sptr<IEventFilter> filter = new (std::nothrow) MyEventFilter();
    ASSERT_NE(filter, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(100);
    pointerEvent->SetPointerId(100);
    pointerEvent->AddPointerItem(item);
    EventFilterHandler::FilterInfo filterInfo = { filter, nullptr, 500, 200, 100, 300 };
    filterHandler.filters_.emplace_front(filterInfo);
    EXPECT_TRUE(filterHandler.HandlePointerEventFilter(pointerEvent));
}
} // namespace MMI
} // namespace OHOS