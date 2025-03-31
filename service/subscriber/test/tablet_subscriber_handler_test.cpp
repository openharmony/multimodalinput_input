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

#include "tablet_subscriber_handler.h"
#include <parameters.h>
#include "dfx_hisysevent.h"
#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "net_packet.h"
#include "proto.h"
#include "util_ex.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TabletSubscriberHandler_test"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class TabletSubscriberHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: TabletSubscriberHandlerTest_SubscribeTabletProximity
 * @tc.desc: Verify SubscribeTabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletSubscriberHandlerTest, TabletSubscriberHandlerTest_SubscribeTabletProximity_001, TestSize.Level1)
{
    TabletSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, 123, 1000, 2000);
    int32_t subscribeId = 1001;
    
    auto ret = handler.SubscribeTabletProximity(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: TabletSubscriberHandlerTest_SubscribeTabletProximity_002
 * @tc.desc: Verify sSubscribeTabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletSubscriberHandlerTest, TabletSubscriberHandlerTest_SubscribeTabletProximity_002, TestSize.Level1)
{
    TabletSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, 123, 1000, 2000);
    
    // Test null session
    EXPECT_EQ(handler.SubscribeTabletProximity(nullptr, 1001), ERROR_NULL_POINTER);
    
    // Test negative subscribeId
    EXPECT_EQ(handler.SubscribeTabletProximity(session, -1), RET_ERR);
}

/**
 * @tc.name: TabletSubscriberHandlerTest_UnSubscribeTabletProximity_001
 * @tc.desc: Verify UnsubscribetabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletSubscriberHandlerTest, TabletSubscriberHandlerTest_UnSubscribeTabletProximity_001, TestSize.Level1)
{
    TabletSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, 123, 1000, 2000);
    int32_t subscribeId = 1001;
    handler.SubscribeTabletProximity(session, subscribeId);
    EXPECT_EQ(handler.UnsubscribetabletProximity(session, subscribeId), RET_OK);
}

/**
 * @tc.name: TabletSubscriberHandlerTest_OnSubscribeTabletProximity_001
 * @tc.desc: Verify OnSubscribeTabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletSubscriberHandlerTest, TabletSubscriberHandlerTest_OnSubscribeTabletProximity_001, TestSize.Level1)
{
    TabletSubscriberHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent =
        std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    EXPECT_FALSE(handler.OnSubscribeTabletProximity(pointerEvent));
}

/**
 * @tc.name: TabletSubscriberHandlerTest_OnSubscribeTabletProximity_002
 * @tc.desc: Verify OnSubscribeTabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletSubscriberHandlerTest, TabletSubscriberHandlerTest_OnSubscribeTabletProximity_002, TestSize.Level1)
{
    TabletSubscriberHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent =
        std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_PROXIMITY_OUT);
    EXPECT_FALSE(handler.OnSubscribeTabletProximity(pointerEvent));
}

/**
 * @tc.name: TabletSubscriberHandlerTest_OnSubscribeTabletProximity_003
 * @tc.desc: Verify OnSubscribeTabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletSubscriberHandlerTest, TabletSubscriberHandlerTest_OnSubscribeTabletProximity_003, TestSize.Level1)
{
    TabletSubscriberHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent =
        std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_MOVE);
    EXPECT_FALSE(handler.OnSubscribeTabletProximity(pointerEvent));
}
} // namespace MMI
} // namespace OHOS