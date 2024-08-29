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
#include <gmock/gmock.h>

#include "event_filter_proxy.h"
#include "event_normalize_handler.h"
#include "event_filter_service.h"
#include "iremote_object.h"
#include "message_parcel_mock.h"
#include "mmi_log.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventFilterProxyTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;

class RemoteObjectTest : public IRemoteObject {
public:
    explicit RemoteObjectTest(std::u16string descriptor) : IRemoteObject(descriptor) {}
    ~RemoteObjectTest() {}

    int32_t GetObjectRefCount() { return 0; }
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) { return 0; }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; }
    int Dump(int fd, const std::vector<std::u16string> &args) { return 0; }
};
} // namespace

class EventFilterProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() {}
    void TearDown() {}

    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void EventFilterProxyTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}
void EventFilterProxyTest::TearDownTestCase()
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}

/**
 * @tc.name: EventFilterProxyTest_HandleKeyEvent_001
 * @tc.desc: Test the funcation HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterProxyTest, EventFilterProxyTest_HandleKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(false));
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    EventFilterProxy event(remote);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    EXPECT_FALSE(event.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: EventFilterProxyTest_HandleKeyEvent_002
 * @tc.desc: Test the funcation HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterProxyTest, EventFilterProxyTest_HandleKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(true));
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    EventFilterProxy event(remote);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    EXPECT_FALSE(event.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: EventFilterProxyTest_HandlePointerEvent_001
 * @tc.desc: Test the funcation HandlePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterProxyTest, EventFilterProxyTest_HandlePointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(false));
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    EventFilterProxy event(remote);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    EXPECT_FALSE(event.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: EventFilterProxyTest_HandlePointerEvent_002
 * @tc.desc: Test the funcation HandlePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterProxyTest, EventFilterProxyTest_HandlePointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(true));
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    EventFilterProxy event(remote);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    EXPECT_FALSE(event.HandlePointerEvent(pointerEvent));
}
} // namespace MMI
} // namespace OHOS