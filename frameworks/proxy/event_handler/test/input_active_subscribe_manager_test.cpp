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
 * @tc.desc: Test SubscribeInputActive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, SubscribeInputActive_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    int64_t interval = 500; // ms
    int32_t subscriberInput = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), interval);
    EXPECT_GE(subscriberInput, 0);
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: SubscribeInputActive_Test_002
 * @tc.desc: Test SubscribeInputActive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, SubscribeInputActive_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    int64_t interval = 500; // ms
    int32_t subscriberInput = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(inputEventConsumer, interval);
    EXPECT_GE(subscriberInput, 0);
    int32_t subscriberInput1 = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(inputEventConsumer, interval);
    EXPECT_GE(subscriberInput1, 0);
    int32_t subscriberInput2 = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(inputEventConsumer, interval);
    EXPECT_GE(subscriberInput2, 0);
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput);
    EXPECT_EQ(result, RET_OK);
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput1);
    EXPECT_EQ(result, RET_OK);
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput2);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: SubscribeInputActive_Test_003
 * @tc.desc: Test SubscribeInputActive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, SubscribeInputActive_Test_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t interval = 500; // ms
    int32_t subscriberInput = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(nullptr, interval);
    EXPECT_LT(subscriberInput, 0);
}

/**
 * @tc.name: OnSubscribeInputActiveCallback_Test_001
 * @tc.desc: Test OnSubscribeInputActiveCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, OnSubscribeInputActiveCallback_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    int64_t interval = 500; // ms
    int32_t subscriberInput = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), interval);
    EXPECT_GE(subscriberInput, 0);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(keyEvent, subscriberInput);
    EXPECT_EQ(result, RET_OK);
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: OnSubscribeInputActiveCallback_Test_002
 * @tc.desc: Test OnSubscribeInputActiveCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, OnSubscribeInputActiveCallback_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    int64_t interval = 500; // ms
    int32_t subscriberInput = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), interval);
    EXPECT_GE(subscriberInput, 0);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(pointerEvent, subscriberInput);
    EXPECT_EQ(result, RET_OK);
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: OnSubscribeInputActiveCallback_Test_003
 * @tc.desc: Test OnSubscribeInputActiveCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, OnSubscribeInputActiveCallback_Test_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    int64_t interval = 500; // ms
    int32_t subscriberInput = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), interval);
    EXPECT_GE(subscriberInput, 0);

    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(keyEvent, subscriberInput);
    EXPECT_NE(result, RET_OK);
    keyEvent = KeyEvent::Create();
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(keyEvent, -1);
    EXPECT_NE(result, RET_OK);
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: OnSubscribeInputActiveCallback_Test_004
 * @tc.desc: Test OnSubscribeInputActiveCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscribeManagerTest, OnSubscribeInputActiveCallback_Test_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    int64_t interval = 500; // ms
    int32_t subscriberInput = INPUT_ACTIVE_SUBSCRIBE_MGR.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), interval);
    EXPECT_GE(subscriberInput, 0);

    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    int32_t result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(pointerEvent, subscriberInput);
    EXPECT_NE(result, RET_OK);
    pointerEvent = PointerEvent::Create();
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.OnSubscribeInputActiveCallback(pointerEvent, -1);
    EXPECT_NE(result, RET_OK);
    result = INPUT_ACTIVE_SUBSCRIBE_MGR.UnsubscribeInputActive(subscriberInput);
    EXPECT_EQ(result, RET_OK);
}
} // namespace MMI
} // namespace OHOS