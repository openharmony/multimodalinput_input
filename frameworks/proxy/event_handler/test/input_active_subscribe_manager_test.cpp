/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "error_multimodal.h"
#include "input_active_subscribe_manager.h"
#include "input_handler_type.h"
#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputActiveSubscribeManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int64_t DEFAULT_INTERVAL { 500 }; // ms
constexpr int32_t VALID_SUBSCRIBE_ID { 0 };
constexpr int32_t INVALID_SUBSCRIBE_ID { -1 };
} // namespace

class InputActiveSubscribeManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class TestInputEventConsumer : public IInputEventConsumer {
public:
    TestInputEventConsumer() = default;
    ~TestInputEventConsumer() = default;
    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override
    {
        MMI_HILOGI("OnInputEvent KeyEvent enter");
    }
    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
    {
        MMI_HILOGI("OnInputEvent PointerEvent enter");
    }
    void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override
    {}
};

/**
 * @tc.name: SubscribeInputActive_Test_001
 * @tc.desc: Subscribe with a valid callback returns the current subscribe id, then
 *           a duplicate subscribe in the same process is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, SubscribeInputActive_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    EXPECT_NE(inputEventConsumer, nullptr);
    int32_t subscriberId = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), DEFAULT_INTERVAL);
    EXPECT_EQ(subscriberId, VALID_SUBSCRIBE_ID);
    int32_t subscriberId1 = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), DEFAULT_INTERVAL);
    EXPECT_EQ(subscriberId1, ERROR_ONE_PROCESS_ONLY_SUPPORT_ONE);
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberId);
    EXPECT_EQ(result, RET_OK);
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberId);
    EXPECT_NE(result, RET_OK);
}

/**
 * @tc.name: SubscribeInputActive_Test_002
 * @tc.desc: Subscribe with a nullptr callback is rejected with the invalid id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, SubscribeInputActive_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t subscriberInput = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(nullptr, DEFAULT_INTERVAL);
    EXPECT_EQ(subscriberInput, INVALID_HANDLER_ID);
}

/**
 * @tc.name: SubscribeInputActive_Test_003
 * @tc.desc: Unsubscribe with an id that differs from the supported single id is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, SubscribeInputActive_Test_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(INVALID_SUBSCRIBE_ID);
    EXPECT_EQ(result, ERROR_INVALID_SUBSCRIBE_ID);
}

/**
 * @tc.name: OnSubscribeInputActiveCallback_Test_001
 * @tc.desc: Key callback after a successful subscribe returns RET_OK and clears afterward
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, OnSubscribeInputActiveCallback_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    EXPECT_NE(inputEventConsumer, nullptr);
    int32_t subscriberInput = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), DEFAULT_INTERVAL);
    EXPECT_EQ(subscriberInput, VALID_SUBSCRIBE_ID);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(keyEvent, subscriberInput);
    EXPECT_EQ(result, RET_OK);
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput);
    EXPECT_EQ(result, RET_OK);
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(keyEvent, subscriberInput);
    EXPECT_NE(result, RET_OK);
}

/**
 * @tc.name: OnSubscribeInputActiveCallback_Test_002
 * @tc.desc: Pointer callback after a successful subscribe returns RET_OK and clears afterward
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, OnSubscribeInputActiveCallback_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    EXPECT_NE(inputEventConsumer, nullptr);
    int32_t subscriberInput = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), DEFAULT_INTERVAL);
    EXPECT_EQ(subscriberInput, VALID_SUBSCRIBE_ID);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(pointerEvent, subscriberInput);
    EXPECT_EQ(result, RET_OK);
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput);
    EXPECT_EQ(result, RET_OK);
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(pointerEvent, subscriberInput);
    EXPECT_NE(result, RET_OK);
}

/**
 * @tc.name: OnSubscribeInputActiveCallback_Test_003
 * @tc.desc: Key callback with a nullptr event or an invalid subscribe id is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, OnSubscribeInputActiveCallback_Test_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    EXPECT_NE(inputEventConsumer, nullptr);
    int32_t subscriberInput = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), DEFAULT_INTERVAL);
    EXPECT_EQ(subscriberInput, VALID_SUBSCRIBE_ID);

    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(keyEvent, subscriberInput);
    EXPECT_NE(result, RET_OK);
    keyEvent = KeyEvent::Create();
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(keyEvent, INVALID_SUBSCRIBE_ID);
    EXPECT_EQ(result, ERROR_INVALID_SUBSCRIBE_ID);
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: OnSubscribeInputActiveCallback_Test_004
 * @tc.desc: Pointer callback with a nullptr event or an invalid subscribe id is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, OnSubscribeInputActiveCallback_Test_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    EXPECT_NE(inputEventConsumer, nullptr);
    int32_t subscriberInput = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), DEFAULT_INTERVAL);
    EXPECT_EQ(subscriberInput, VALID_SUBSCRIBE_ID);

    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(pointerEvent, subscriberInput);
    EXPECT_NE(result, RET_OK);
    pointerEvent = PointerEvent::Create();
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(pointerEvent, INVALID_SUBSCRIBE_ID);
    EXPECT_EQ(result, ERROR_INVALID_SUBSCRIBE_ID);
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: OnSubscribeInputActiveCallback_Test_005
 * @tc.desc: Key callback with a valid id but no active subscription is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, OnSubscribeInputActiveCallback_Test_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(keyEvent, VALID_SUBSCRIBE_ID);
    EXPECT_EQ(result, ERROR_HAD_UNSUBSCRIBE_INPUT_ACTIVE);
}

/**
 * @tc.name: OnSubscribeInputActiveCallback_Test_006
 * @tc.desc: Pointer callback with a valid id but no active subscription is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, OnSubscribeInputActiveCallback_Test_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(pointerEvent, VALID_SUBSCRIBE_ID);
    EXPECT_EQ(result, ERROR_HAD_UNSUBSCRIBE_INPUT_ACTIVE);
}

/**
 * @tc.name: UnsubscribeInputActive_Test_001
 * @tc.desc: Unsubscribe with the valid id but no active subscription is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, UnsubscribeInputActive_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(VALID_SUBSCRIBE_ID);
    EXPECT_EQ(result, ERROR_NO_SUBSCRIBE_INPUT_ACTIVE);
}

/**
 * @tc.name: UnsubscribeInputActive_Test_002
 * @tc.desc: Unsubscribe with an invalid id is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, UnsubscribeInputActive_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(INVALID_SUBSCRIBE_ID);
    EXPECT_EQ(result, ERROR_INVALID_SUBSCRIBE_ID);
}

/**
 * @tc.name: SubscribeInputActiveInfo_Test_001
 * @tc.desc: SubscribeInputActiveInfo stores the interval and callback and exposes them
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, SubscribeInputActiveInfo_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    EXPECT_NE(inputEventConsumer, nullptr);
    int64_t interval = 3600000; // 1 hour in ms
    InputActiveSubscribeManager::SubscribeInputActiveInfo info(inputEventConsumer, interval);
    EXPECT_EQ(info.GetInputActiveInterval(), interval);
    EXPECT_EQ(info.GetCallback(), inputEventConsumer);
}

/**
 * @tc.name: SubscribeInputActiveInfo_Test_002
 * @tc.desc: SubscribeInputActiveInfo with a nullptr callback still exposes the stored data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, SubscribeInputActiveInfo_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t interval = 0;
    InputActiveSubscribeManager::SubscribeInputActiveInfo info(nullptr, interval);
    EXPECT_EQ(info.GetInputActiveInterval(), interval);
    EXPECT_EQ(info.GetCallback(), nullptr);
}

/**
 * @tc.name: OnConnected_Test_001
 * @tc.desc: OnConnected is a no-op when there is no active subscription
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, OnConnected_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(INPUT_ACTIVE_SUBSCRIBE_MGR.OnConnected());
}

/**
 * @tc.name: OnConnected_Test_002
 * @tc.desc: OnConnected with an active subscription triggers a server subscribe and returns
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, OnConnected_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    EXPECT_NE(inputEventConsumer, nullptr);
    int32_t subscriberInput = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), DEFAULT_INTERVAL);
    EXPECT_EQ(subscriberInput, VALID_SUBSCRIBE_ID);
    EXPECT_NO_FATAL_FAILURE(INPUT_ACTIVE_SUBSCRIBE_MGR.OnConnected());
    EXPECT_EQ(INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput), RET_OK);
}

/**
 * @tc.name: SubscribeAndUnsubscribe_Test_001
 * @tc.desc: A full subscribe and unsubscribe cycle leaves the manager reusable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, SubscribeAndUnsubscribe_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    EXPECT_NE(inputEventConsumer, nullptr);
    int32_t subscriberInput = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), DEFAULT_INTERVAL);
    EXPECT_EQ(subscriberInput, VALID_SUBSCRIBE_ID);
    EXPECT_EQ(INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput), RET_OK);
    int32_t subscriberInput2 = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), DEFAULT_INTERVAL * 2);
    EXPECT_EQ(subscriberInput2, VALID_SUBSCRIBE_ID);
    EXPECT_EQ(INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput2), RET_OK);
}
} // namespace MMI
} // namespace OHOS
