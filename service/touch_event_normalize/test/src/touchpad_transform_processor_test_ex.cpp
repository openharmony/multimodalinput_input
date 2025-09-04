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

#include <cstdio>
#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "general_touchpad.h"
#include "touchpad_transform_processor.h"

#include <vector>
#include <deque>
#include <mutex>

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchPadTransformProcessorTestEx"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class TouchPadTransformProcessorTestEx : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TouchPadTransformProcessorTestEx::SetUpTestCase()
{
}

void TouchPadTransformProcessorTestEx::TearDownTestCase()
{
}

void TouchPadTransformProcessorTestEx::SetUp()
{
}

void TouchPadTransformProcessorTestEx::TearDown()
{
}



/**
 * @tc.name: TouchPadTransformProcessorTestEx_SmoothMultifingerSwipeData_001
 * @tc.desc: Test SmoothMultifingerSwipeData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTestEx, TouchPadTransformProcessorTestEx_GetTouchpadScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    TouchPadTransformProcessor processor(deviceId);
    vector<Coords> fingerCoords = {{1, 1}, {0, 0}};
    int32_t fingerCount = 2;
    // pre add swipeHistory_
    processor.swipeHistory_.push_back({{1, 1}, {2, 2}});
    processor.swipeHistory_.push_back({});
    processor.SmoothMultifingerSwipeData(fingerCoords, fingerCount);
    EXPECT_EQ(fingerCoords[1].x, 0);
    EXPECT_EQ(fingerCoords[1].y, 0);
}

/**
 * @tc.name: TouchPadTransformProcessorTestEx_SmoothMultifingerSwipeData_002
 * @tc.desc: Test SmoothMultifingerSwipeData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTestEx, TouchPadTransformProcessorTestEx_GetTouchpadScrollRows_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    TouchPadTransformProcessor processor(deviceId);
    vector<Coords> fingerCoords = {{1, 1}, {2, 2}, {3, 3}};
    vector<Coords> fingerCoordsZero = {{1, 1}, {0, 0}, {3, 3}};
    int32_t fingerCount = 3;
    for(int i = 0; i < 3; ++i) {
        processor.SmoothMultifingerSwipeData(fingerCoords, fingerCount);
    }
    EXPECT_EQ(processor.swipeHistory_[0].size, 3);
    EXPECT_EQ(processor.swipeHistory_[1].size, 3);
    EXPECT_EQ(processor.swipeHistory_[2].size, 3);

    processor.SmoothMultifingerSwipeData(fingerCoordsZero, fingerCount);
    EXPECT_EQ(fingerCoordsZero[0].x, 1);
    EXPECT_EQ(fingerCoordsZero[0].x, 1);
    EXPECT_EQ(fingerCoordsZero[1].x, 2);
    EXPECT_EQ(fingerCoordsZero[1].x, 2);
    EXPECT_EQ(fingerCoordsZero[2].x, 3);
    EXPECT_EQ(fingerCoordsZero[2].x, 3);
}
} // namespace MMI
} // namespace OHOS