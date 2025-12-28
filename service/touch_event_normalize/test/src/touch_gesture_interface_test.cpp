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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ffrt.h"
#include "input_service_context.h"
#include "touch_gesture_interface.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchGestureInterfaceTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
} // namespace

class TouchGestureInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}

private:
    InputServiceContext env_ {};
};

/**
 * @tc.name: DoesSupportGesture_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureInterfaceTest, DoesSupportGesture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto touchGestureMgr = std::make_shared<TouchGestureInterface>();
    TouchGestureType gestureType { TOUCH_GESTURE_TYPE_PINCH };
    int32_t nFingers { 4 };
    EXPECT_FALSE(touchGestureMgr->DoesSupportGesture(gestureType, nFingers));
}

/**
 * @tc.name: DoesSupportGesture_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureInterfaceTest, DoesSupportGesture_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto touchGestureMgr = TouchGestureInterface::Load(&env_);
    ffrt::wait();
    TouchGestureType gestureType { TOUCH_GESTURE_TYPE_PINCH };
    int32_t nFingers { 4 };
    EXPECT_TRUE(touchGestureMgr->DoesSupportGesture(gestureType, nFingers));
}

/**
 * @tc.name: AddHandler_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureInterfaceTest, AddHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto touchGestureMgr = std::make_shared<TouchGestureInterface>();
    int32_t session { 1 };
    TouchGestureType gestureType { TOUCH_GESTURE_TYPE_PINCH };
    int32_t nFingers { 4 };
    EXPECT_TRUE(touchGestureMgr->AddHandler(session, gestureType, nFingers));
}

/**
 * @tc.name: HasHandler_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureInterfaceTest, HasHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto touchGestureMgr = std::make_shared<TouchGestureInterface>();
    EXPECT_FALSE(touchGestureMgr->HasHandler());
}
} // namespace MMI
} // namespace OHOS
