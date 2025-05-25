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
#include "input_manager_impl.h"
#include "switch_event_input_subscribe_manager.h"
#include "multimodal_input_connect_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SwitchEventInputSubscribeManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t INVAID_VALUE { -1 };
constexpr int32_t SUBSCRIBER_ID { 0 };
constexpr int32_t MIN_SUBSCRIBER_ID { 0 };
} // namespace

class SwitchEventInputSubscribeManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

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
    SwitchEventInputSubscribeManagerTest_UnsubscribeSwitchEvent_001, TestSize.Level2)
{
    auto func = [](std::shared_ptr<SwitchEvent> event) {
        MMI_HILOGD("Subscribe switch event success, type:%{public}d, value:%{public}d",
            event->GetSwitchType(), event->GetSwitchValue());
    };

    ASSERT_NE(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.UnsubscribeSwitchEvent(INVAID_VALUE), RET_OK);
    ASSERT_EQ(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.UnsubscribeSwitchEvent(SUBSCRIBER_ID), RET_ERR);
    int32_t subscribeId =
        SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.SubscribeSwitchEvent(SwitchEvent::SwitchType::SWITCH_DEFAULT, func);
    ASSERT_GE(subscribeId, MIN_SUBSCRIBER_ID);
    ASSERT_EQ(SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.UnsubscribeSwitchEvent(subscribeId), RET_OK);
}

/**
 * @tc.name: SwitchEventInputSubscribeManagerTest_QuerySwitchStatus_001
 * @tc.desc: Verify QuerySwitchStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchEventInputSubscribeManagerTest,
    SwitchEventInputSubscribeManagerTest_QuerySwitchStatus_001, TestSize.Level2)
{
    int32_t state = 0;
    int32_t retCode =
        MULTIMODAL_INPUT_CONNECT_MGR->QuerySwitchStatus(SwitchEvent::SwitchType::SWITCH_DEFAULT, state);
    ASSERT_EQ(retCode, RET_OK);
    retCode =
        MULTIMODAL_INPUT_CONNECT_MGR->QuerySwitchStatus(SwitchEvent::SwitchType::SWITCH_LID, state);
    ASSERT_EQ(retCode, RET_OK);
    retCode =
        MULTIMODAL_INPUT_CONNECT_MGR->QuerySwitchStatus(SwitchEvent::SwitchType::SWITCH_TABLET, state);
    ASSERT_EQ(retCode, RET_OK);
    retCode =
        MULTIMODAL_INPUT_CONNECT_MGR->QuerySwitchStatus(SwitchEvent::SwitchType::SWITCH_PRIVACY, state);
    ASSERT_EQ(retCode, RET_OK);
}

/**
 * @tc.name: SwitchEventInputSubscribeManagerTest_OnSubscribeSwitchEventCallback_001
 * @tc.desc: Verify OnSubscribeSwitchEventCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchEventInputSubscribeManagerTest,
    SwitchEventInputSubscribeManagerTest_OnSubscribeSwitchEventCallback_001, TestSize.Level2)
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

/**
 * @tc.name: SwitchEventInputSubscribeManagerTest_OnDisconnected_001
 * @tc.desc: Verify OnDisconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchEventInputSubscribeManagerTest,
    SwitchEventInputSubscribeManagerTest_OnDisconnected_001, TestSize.Level1)
{
    InputManagerImpl inputManager;
    EXPECT_NO_FATAL_FAILURE(inputManager.OnDisconnected());
}

/**
 * @tc.name: SwitchEventInputSubscribeManagerTest_ReAddInputEventFilter_001
 * @tc.desc: Verify ReAddInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchEventInputSubscribeManagerTest,
    SwitchEventInputSubscribeManagerTest_ReAddInputEventFilter_001, TestSize.Level1)
{
    InputManagerImpl inputManager;
    EXPECT_NO_FATAL_FAILURE(inputManager.ReAddInputEventFilter());
}

/**
 * @tc.name: SwitchEventInputSubscribeManagerTest_SetTouchpadScrollSwitch_001
 * @tc.desc: Verify SetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchEventInputSubscribeManagerTest,
    SwitchEventInputSubscribeManagerTest_SetTouchpadScrollSwitch_001, TestSize.Level1)
{
    InputManagerImpl inputManager;
    bool switchFlag = true;
    int32_t ret = inputManager.SetTouchpadScrollSwitch(switchFlag);
    ASSERT_EQ(ret, RET_OK);
    switchFlag = false;
    ret = inputManager.SetTouchpadScrollSwitch(switchFlag);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SwitchEventInputSubscribeManagerTest_GetTouchpadScrollSwitch_001
 * @tc.desc: Verify GetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchEventInputSubscribeManagerTest,
    SwitchEventInputSubscribeManagerTest_GetTouchpadScrollSwitch_001, TestSize.Level3)
{
    InputManagerImpl inputManager;
    bool switchFlag = true;
    int32_t ret = inputManager.GetTouchpadScrollSwitch(switchFlag);
    ASSERT_EQ(ret, RET_OK);
    switchFlag = false;
    ret = inputManager.GetTouchpadScrollSwitch(switchFlag);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SwitchEventInputSubscribeManagerTest_SetPixelMapData_001
 * @tc.desc: Test the funcation SetPixelMapData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchEventInputSubscribeManagerTest,
    SwitchEventInputSubscribeManagerTest_SetPixelMapData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputManagerImpl inputManagerImpl;
    int32_t infoId = -1;
    void* pixelMap = nullptr;
    EXPECT_NO_FATAL_FAILURE(inputManagerImpl.SetPixelMapData(infoId, pixelMap));
    infoId = 1;
    EXPECT_NO_FATAL_FAILURE(inputManagerImpl.SetPixelMapData(infoId, pixelMap));
}

/**
 * @tc.name: SwitchEventInputSubscribeManagerTest_ReAddInputEventFilter_002
 * @tc.desc: Test the funcation ReAddInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchEventInputSubscribeManagerTest,
    SwitchEventInputSubscribeManagerTest_ReAddInputEventFilter_002, TestSize.Level1)
{
    InputManagerImpl inputManager;
    sptr<IEventFilter> filter1 = new (std::nothrow) MyEventFilter();
    std::tuple<sptr<IEventFilter>, int32_t, uint32_t> value1(filter1, 10, 20);
    inputManager.eventFilterServices_.insert(std::make_pair(1, value1));
    EXPECT_NO_FATAL_FAILURE(inputManager.ReAddInputEventFilter());
    sptr<IEventFilter> filter2 = new (std::nothrow) MyEventFilter();
    std::tuple<sptr<IEventFilter>, int32_t, uint32_t> value2(filter2, 20, 30);
    inputManager.eventFilterServices_.insert(std::make_pair(2, value1));
    sptr<IEventFilter> filter3 = new (std::nothrow) MyEventFilter();
    std::tuple<sptr<IEventFilter>, int32_t, uint32_t> value3(filter3, 30, 40);
    inputManager.eventFilterServices_.insert(std::make_pair(3, value3));
    sptr<IEventFilter> filter4 = new (std::nothrow) MyEventFilter();
    std::tuple<sptr<IEventFilter>, int32_t, uint32_t> value4(filter4, 40, 50);
    inputManager.eventFilterServices_.insert(std::make_pair(4, value4));
    sptr<IEventFilter> filter5 = new (std::nothrow) MyEventFilter();
    std::tuple<sptr<IEventFilter>, int32_t, uint32_t> value5(filter5, 50, 60);
    inputManager.eventFilterServices_.insert(std::make_pair(5, value5));
    EXPECT_NO_FATAL_FAILURE(inputManager.ReAddInputEventFilter());
}
} // namespace MMI
} // namespace OHOS
