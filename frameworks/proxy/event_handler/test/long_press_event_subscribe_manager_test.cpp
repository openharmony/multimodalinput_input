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

#include "long_press_event_subscribe_manager.h"
#include <cinttypes>
#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "multimodal_event_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "LongPressEventSubscribeManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class LongPressEventSubscribeManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};
/**
 * @tc.name: LongPressEventSubscribeManagerTest_OnSubscribeLongPressEventCallback001
 * @tc.desc: Verify OnSubscribeLongPressEventCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LongPressEventSubscribeManagerTest, LongPressEventSubscribeManagerTest_OnSubscribeLongPressEventCallback001,
    TestSize.Level1)
{
    LongPressEvent longPressEvent;
    int32_t subscribeId = -1;

    LongPressEventSubscribeManager manager;
    auto ret = manager.OnSubscribeLongPressEventCallback(longPressEvent, subscribeId);
    EXPECT_EQ(ret, RET_ERR);

    subscribeId = 1;
    ret = manager.OnSubscribeLongPressEventCallback(longPressEvent, subscribeId);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);

    auto myCallback = [](LongPressEvent event) {
        MMI_HILOGD("Add event success");
    };

    LongPressRequest longPressRequest;
    LongPressEventSubscribeManager::SubscribeLongPressEventInfo info(longPressRequest, myCallback);
    manager.subscribeInfos_.emplace(std::make_pair(subscribeId, info));
    ret = manager.OnSubscribeLongPressEventCallback(longPressEvent, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: LongPressEventSubscribeManagerTest_OnConnected001
 * @tc.desc: Verify OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LongPressEventSubscribeManagerTest, LongPressEventSubscribeManagerTest_OnConnected001,
    TestSize.Level1)
{
    LongPressEventSubscribeManager manager;
    EXPECT_NO_FATAL_FAILURE(manager.OnConnected());
    
    auto myCallback = [](LongPressEvent event) {
        MMI_HILOGD("Add event success");
    };

    int32_t subscribeId = 1;
    LongPressRequest longPressRequest;
    LongPressEventSubscribeManager::SubscribeLongPressEventInfo info(longPressRequest, myCallback);
    manager.subscribeInfos_.emplace(std::make_pair(subscribeId, info));
    EXPECT_NO_FATAL_FAILURE(manager.OnConnected());
}
} // namespace MMI
} // namespace OHOS