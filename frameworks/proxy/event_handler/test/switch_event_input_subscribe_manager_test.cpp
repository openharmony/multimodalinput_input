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

#include "error_multimodal.h"
#include "event_log_helper.h"
#include "switch_event_input_subscribe_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SwitchEventInputSubscribeManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t INVAID_VALUE = -1;
constexpr int32_t SUBSCRIBER_ID = 0;
constexpr int32_t MIN_SUBSCRIBER_ID = 0;
} // namespace

class SwitchEventInputSubscribeManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: SwitchEventInputSubscribeManagerTest_SubscribeSwitchEvent_001
 * @tc.desc: Verify SubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchEventInputSubscribeManagerTest,
    SwitchEventInputSubscribeManagerTest_SubscribeSwitchEvent_001, TestSize.Level1)
{
    auto func = [](std::shared_ptr<SwitchEvent> event) {
        MMI_HILOGD("Subscribe switch event success, type:%{public}d, value:%{public}d",
            event->GetSwitchType(), event->GetSwitchValue());
    };

    ASSERT_EQ(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.SubscribeSwitchEvent(INVAID_VALUE, nullptr), RET_ERR);
    ASSERT_EQ(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.SubscribeSwitchEvent(INVAID_VALUE, func), RET_ERR);
    int32_t subscribeId =
        SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.SubscribeSwitchEvent(SwitchEvent::SwitchType::SWITCH_DEFAULT, func);
    ASSERT_GE(subscribeId, MIN_SUBSCRIBER_ID);
    ASSERT_EQ(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.UnsubscribeSwitchEvent(subscribeId), RET_OK);
}

/**
 * @tc.name: SwitchEventInputSubscribeManagerTest_UnsubscribeSwitchEvent_001
 * @tc.desc: Verify UnsubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchEventInputSubscribeManagerTest,
    SwitchEventInputSubscribeManagerTest_UnsubscribeSwitchEvent_001, TestSize.Level1)
{
    auto func = [](std::shared_ptr<SwitchEvent> event) {
        MMI_HILOGD("Subscribe switch event success, type:%{public}d, value:%{public}d",
            event->GetSwitchType(), event->GetSwitchValue());
    };

    ASSERT_EQ(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.UnsubscribeSwitchEvent(INVAID_VALUE), RET_ERR);
    ASSERT_EQ(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.UnsubscribeSwitchEvent(SUBSCRIBER_ID), RET_ERR);
    int32_t subscribeId =
        SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.SubscribeSwitchEvent(SwitchEvent::SwitchType::SWITCH_DEFAULT, func);
    ASSERT_GE(subscribeId, MIN_SUBSCRIBER_ID);
    ASSERT_EQ(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.UnsubscribeSwitchEvent(subscribeId), RET_OK);
}

/**
 * @tc.name: SwitchEventInputSubscribeManagerTest_OnSubscribeSwitchEventCallback_001
 * @tc.desc: Verify OnSubscribeSwitchEventCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchEventInputSubscribeManagerTest,
    SwitchEventInputSubscribeManagerTest_OnSubscribeSwitchEventCallback_001, TestSize.Level1)
{
    auto func = [](std::shared_ptr<SwitchEvent> event) {
        MMI_HILOGD("Subscribe switch event success, type:%{public}d, value:%{public}d",
            event->GetSwitchType(), event->GetSwitchValue());
    };
    auto switchEvent = std::make_shared<SwitchEvent>(INVAID_VALUE);
    ASSERT_NE(switchEvent, nullptr);

    ASSERT_EQ(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.OnSubscribeSwitchEventCallback(
        nullptr, SUBSCRIBER_ID), ERROR_NULL_POINTER);
    ASSERT_EQ(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.OnSubscribeSwitchEventCallback(
        switchEvent, INVAID_VALUE), RET_ERR);
    ASSERT_EQ(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.OnSubscribeSwitchEventCallback(
        switchEvent, SUBSCRIBER_ID), ERROR_NULL_POINTER);
    int32_t subscribeId =
        SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.SubscribeSwitchEvent(SwitchEvent::SwitchType::SWITCH_DEFAULT, func);
    ASSERT_GE(subscribeId, MIN_SUBSCRIBER_ID);
    ASSERT_EQ(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.OnSubscribeSwitchEventCallback(
        switchEvent, subscribeId), RET_OK);
    ASSERT_EQ(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.UnsubscribeSwitchEvent(subscribeId), RET_OK);
}

/**
 * @tc.name: SwitchEventInputSubscribeManagerTest_OnConnected_001
 * @tc.desc: Verify OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchEventInputSubscribeManagerTest,
    SwitchEventInputSubscribeManagerTest_OnConnected_001, TestSize.Level1)
{
    auto func = [](std::shared_ptr<SwitchEvent> event) {
        MMI_HILOGD("Subscribe switch event success, type:%{public}d, value:%{public}d",
            event->GetSwitchType(), event->GetSwitchValue());
    };

    SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.OnConnected();
    int32_t subscribeId =
        SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.SubscribeSwitchEvent(SwitchEvent::SwitchType::SWITCH_DEFAULT, func);
    ASSERT_GE(subscribeId, MIN_SUBSCRIBER_ID);
    SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.OnConnected();
    ASSERT_EQ(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.UnsubscribeSwitchEvent(subscribeId), RET_OK);
}

} // namespace MMI
} // namespace OHOS
