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

#include "tablet_event_input_subscribe_manager.h"
#include <cinttypes>
#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "multimodal_event_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TabletEventInputSubscribeManagerTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INVALID_SUBSCRIBE_ID { -1 };
using namespace testing::ext;
} // namespace

class TabletEventInputSubscribeManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: TabletEventInputSubscribeManagerTest_SubscribeNormal
 * @tc.desc: Verify SubscribeTabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletEventInputSubscribeManagerTest, TabletEventInputSubscribeManagerTest_SubscribeTabletProximity001,
    TestSize.Level1)
{
    TabletEventInputSubscribeManager manager;
    auto callback = [](std::shared_ptr<PointerEvent> event) {};
    int32_t ret = manager.SubscribeTabletProximity(callback);
    EXPECT_GE(ret, 0);

    manager.subscribeManagerId_ = INT_MAX;
    ret = manager.SubscribeTabletProximity(callback);
    EXPECT_GE(ret, INVALID_SUBSCRIBE_ID);

    manager.subscribeManagerId_ = -1;
    ret = manager.SubscribeTabletProximity(callback);
    EXPECT_GE(ret, INVALID_SUBSCRIBE_ID);
}

/**
 * @tc.name: TabletEventInputSubscribeManagerTest_SubscribeWithNullCallback
 * @tc.desc: Verify SubscribeTabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletEventInputSubscribeManagerTest, TabletEventInputSubscribeManagerTest_SubscribeTabletProximity002,
    TestSize.Level1)
{
    TabletEventInputSubscribeManager manager;
    int32_t ret = manager.SubscribeTabletProximity(nullptr);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/**
 * @tc.name: TabletEventInputSubscribeManagerTest_UnsubscribeValid
 * @tc.desc: Verify UnsubscribetabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletEventInputSubscribeManagerTest, TabletEventInputSubscribeManagerTest_UnSubscribeTabletProximity001,
    TestSize.Level1)
{
    TabletEventInputSubscribeManager manager;
    auto callback = [](std::shared_ptr<PointerEvent> event) {};
    int32_t subscribeId = manager.SubscribeTabletProximity(callback);
    EXPECT_EQ(manager.UnsubscribetabletProximity(subscribeId), RET_OK);
}

/**
 * @tc.name: TabletEventInputSubscribeManagerTest_UnsubscribeInvalid
 * @tc.desc: Verify UnsubscribetabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletEventInputSubscribeManagerTest, TabletEventInputSubscribeManagerTest_UnSubscribeTabletProximity002,
    TestSize.Level1)
{
    TabletEventInputSubscribeManager manager;
    EXPECT_EQ(manager.UnsubscribetabletProximity(-1), RET_ERR);
}

/**
 * @tc.name: TabletEventInputSubscribeManagerTest_CallbackExecution
 * @tc.desc: Verify callback OnSubscribeTabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletEventInputSubscribeManagerTest, TabletEventInputSubscribeManagerTest_OnSubscribeTabletProximity001,
    TestSize.Level1)
{
    TabletEventInputSubscribeManager manager;
    bool callbackExecuted = false;
    auto callback = [&callbackExecuted](std::shared_ptr<PointerEvent> event) {
        callbackExecuted = true;
    };
    
    int32_t subscribeId = manager.SubscribeTabletProximity(callback);
    auto event = std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    auto ret = manager.OnSubscribeTabletProximityCallback(event, subscribeId);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_TRUE(callbackExecuted);

    EXPECT_EQ(manager.UnsubscribetabletProximity(subscribeId), RET_OK);
    ret = manager.OnSubscribeTabletProximityCallback(event, subscribeId);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);

    ret = manager.OnSubscribeTabletProximityCallback(nullptr, subscribeId);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);

    subscribeId = -1;
    ret = manager.OnSubscribeTabletProximityCallback(event, subscribeId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TabletEventInputSubscribeManagerTest_DoubleUnsubscribe
 * @tc.desc: Verify UnsubscribetabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletEventInputSubscribeManagerTest, TabletEventInputSubscribeManagerTest_DoubleUnsubscribe,
    TestSize.Level1)
{
    TabletEventInputSubscribeManager manager;
    auto callback = [](std::shared_ptr<PointerEvent> event) {};
    int32_t subscribeId1 = manager.SubscribeTabletProximity(callback);
    int32_t subscribeId2 = manager.SubscribeTabletProximity(callback);
    EXPECT_EQ(manager.UnsubscribetabletProximity(subscribeId1), RET_OK);
    EXPECT_EQ(manager.UnsubscribetabletProximity(subscribeId1), RET_ERR);

    EXPECT_EQ(manager.UnsubscribetabletProximity(subscribeId2), RET_OK);
    EXPECT_EQ(manager.UnsubscribetabletProximity(subscribeId2), RET_ERR);
}
} // namespace MMI
} // namespace OHOS