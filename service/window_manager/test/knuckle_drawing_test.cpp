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
#include "define_multimodal.h"
#include "i_knuckle_drawing.h"
#include "knuckle_drawing.h"

using namespace testing::ext;
using namespace OHOS::MMI;

extern "C" IKnuckleDrawing *GetKnuckleDrawing();
extern "C" void DestroyKnuckleDrawing(IKnuckleDrawing *inst);

namespace OHOS {
namespace MMI {

class KnuckleDrawingTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {}
};

/**
 * @tc.name: KnuckleDrawingTest_GetKnuckleDrawing
 * @tc.desc: Test Overrides GetKnuckleDrawing and DestroyKnuckleDrawing function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDrawingTest, KnuckleDrawingTest_GetKnuckleDrawing, TestSize.Level1)
{
    IKnuckleDrawing *knuckleDrawing = GetKnuckleDrawing();
    ASSERT_NE(knuckleDrawing, nullptr);

    DestroyKnuckleDrawing(knuckleDrawing);
    knuckleDrawing = nullptr;

    DestroyKnuckleDrawing(knuckleDrawing);
}

/**
 * @tc.name: KnuckleDrawingTest_Draw
 * @tc.desc: Test Overrides Draw function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDrawingTest, KnuckleDrawingTest_Draw, TestSize.Level1)
{
    std::shared_ptr<KnuckleDrawing> knuckleDrawing = std::make_shared<KnuckleDrawing>();
    ASSERT_NE(knuckleDrawing, nullptr);
    ASSERT_NE(knuckleDrawing->knuckleDrawingMgr_, nullptr);

    OLD::DisplayInfo info;
    auto pointerEvent = PointerEvent::Create();
    knuckleDrawing->Draw(info, pointerEvent);
    ASSERT_EQ(knuckleDrawing->knuckleDrawingMgr_->screenReadObserver_, nullptr);

    knuckleDrawing->knuckleDrawingMgr_ = nullptr;
    knuckleDrawing->Draw(info, pointerEvent);
}

/**
 * @tc.name: KnuckleDrawingTest_SetMultiWindowScreenId
 * @tc.desc: Test Overrides SetMultiWindowScreenId function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDrawingTest, KnuckleDrawingTest_SetMultiWindowScreenId, TestSize.Level1)
{
    std::shared_ptr<KnuckleDrawing> knuckleDrawing = std::make_shared<KnuckleDrawing>();
    ASSERT_NE(knuckleDrawing, nullptr);
    ASSERT_NE(knuckleDrawing->knuckleDrawingMgr_, nullptr);

    uint64_t screenId = 0;
    uint64_t displayNodeScreenId = 0;
    knuckleDrawing->SetMultiWindowScreenId(screenId, displayNodeScreenId);
    ASSERT_EQ(knuckleDrawing->knuckleDrawingMgr_->screenReadObserver_, nullptr);

    knuckleDrawing->knuckleDrawingMgr_ = nullptr;
    knuckleDrawing->SetMultiWindowScreenId(screenId, displayNodeScreenId);
}

/**
 * @tc.name: KnuckleDrawingTest_RegisterAddTimer_001
 * @tc.desc: Test Overrides RegisterAddTimer function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDrawingTest, KnuckleDrawingTest_RegisterAddTimer_001, TestSize.Level1)
{
    std::shared_ptr<KnuckleDrawing> knuckleDrawing = std::make_shared<KnuckleDrawing>();
    ASSERT_NE(knuckleDrawing, nullptr);
    ASSERT_NE(knuckleDrawing->knuckleDrawingMgr_, nullptr);

    auto addTimerFunc = []
        (int32_t intervalMs, int32_t repeatCount, std::function<void()> callback, const std::string &name) -> int32_t {
        (void)intervalMs;
        (void)repeatCount;
        (void)callback;
        (void)name;
        return RET_OK;
    };
    knuckleDrawing->RegisterAddTimer(addTimerFunc);
    ASSERT_NE(knuckleDrawing->knuckleDrawingMgr_->addTimerFunc_, nullptr);
}

/**
 * @tc.name: KnuckleDrawingTest_RegisterAddTimer_002
 * @tc.desc: Test Overrides RegisterAddTimer function abnormal branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDrawingTest, KnuckleDrawingTest_RegisterAddTimer_002, TestSize.Level1)
{
    std::shared_ptr<KnuckleDrawing> knuckleDrawing = std::make_shared<KnuckleDrawing>();
    ASSERT_NE(knuckleDrawing, nullptr);
    ASSERT_NE(knuckleDrawing->knuckleDrawingMgr_, nullptr);
    std::shared_ptr<KnuckleDrawingManager> knuckleDrawingMgrTmp = knuckleDrawing->knuckleDrawingMgr_;
    knuckleDrawing->knuckleDrawingMgr_ = nullptr;

    auto addTimerFunc = []
        (int32_t intervalMs, int32_t repeatCount, std::function<void()> callback, const std::string &name) -> int32_t {
        (void)intervalMs;
        (void)repeatCount;
        (void)callback;
        (void)name;
        return RET_OK;
    };
    knuckleDrawing->RegisterAddTimer(addTimerFunc);
    ASSERT_FALSE(knuckleDrawingMgrTmp->addTimerFunc_);
}
} // namespace MMI
} // namespace OHOS