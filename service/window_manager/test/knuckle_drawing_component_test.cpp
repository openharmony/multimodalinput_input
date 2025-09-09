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
#include <gmock/gmock.h>

#include "i_knuckle_drawing.h"
#include "knuckle_drawing_component.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleDrawingComponentTest"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace MMI {

class KnuckleDrawingComponentTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {}
    void SetCase() {}
};

class MockIKnuckleDrawing : public IKnuckleDrawing {
public:
    MockIKnuckleDrawing() = default;
    ~MockIKnuckleDrawing() override = default;

    MOCK_METHOD2(Draw, void(const OLD::DisplayInfo&, const std::shared_ptr<PointerEvent>&));
    MOCK_METHOD2(SetMultiWindowScreenId, void(uint64_t, uint64_t));
    MOCK_METHOD1(RegisterAddTimer, void(AddTimerFunc));
};

/**
 * @tc.name: LoadKnuckleDrawing
 * @tc.desc: Test Overrides Draw function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDrawingComponentTest, LoadKnuckleDrawing, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDrawingComponent &knuckleDrawingComp = KnuckleDrawingComponent::GetInstance();
    ASSERT_EQ(knuckleDrawingComp.handle_, nullptr);
    ASSERT_EQ(knuckleDrawingComp.create_, nullptr);
    ASSERT_EQ(knuckleDrawingComp.destroy_, nullptr);
    ASSERT_EQ(knuckleDrawingComp.impl_, nullptr);
    ASSERT_EQ(knuckleDrawingComp.timerId_, -1);
}

/**
 * @tc.name: KnuckleDrawingComponentTest_Draw
 * @tc.desc: Test Overrides Draw function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDrawingComponentTest, KnuckleDrawingComponentTest_Draw, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDrawingComponent::GetInstance().Unload();

    MockIKnuckleDrawing *knuckleDrawing = new (std::nothrow) MockIKnuckleDrawing();
    ASSERT_NE(knuckleDrawing, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleDrawing, Draw(_, _)).WillOnce([&isCalled] {
        isCalled = true;
    });
    KnuckleDrawingComponent::GetInstance().impl_ = knuckleDrawing;

    OLD::DisplayInfo displayInfo;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    if (pointerEvent == nullptr) {
        KnuckleDrawingComponent::GetInstance().impl_ = nullptr;
        delete knuckleDrawing;
        knuckleDrawing = nullptr;
        FAIL() << "Create PointerEvent fail";
    }

    KnuckleDrawingComponent::GetInstance().Draw(displayInfo, pointerEvent);
    KnuckleDrawingComponent::GetInstance().impl_ = nullptr;
    delete knuckleDrawing;
    knuckleDrawing = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleDrawingComponentTest_SetMultiWindowScreenId
 * @tc.desc: Test Overrides SetMultiWindowScreenId function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDrawingComponentTest, KnuckleDrawingComponentTest_SetMultiWindowScreenId, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDrawingComponent::GetInstance().Unload();

    MockIKnuckleDrawing *knuckleDrawing = new (std::nothrow) MockIKnuckleDrawing();
    ASSERT_NE(knuckleDrawing, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleDrawing, SetMultiWindowScreenId(_, _)).WillOnce([&isCalled] {
        isCalled = true;
    });
    KnuckleDrawingComponent::GetInstance().impl_ = knuckleDrawing;

    uint64_t screenId = 0;
    uint64_t displayNodeScreenId = 0;
    KnuckleDrawingComponent::GetInstance().SetMultiWindowScreenId(screenId, displayNodeScreenId);
    ASSERT_EQ(KnuckleDrawingComponent::GetInstance().windowScreenId_, 0);
    ASSERT_EQ(KnuckleDrawingComponent::GetInstance().displayNodeScreenId_, 0);
    KnuckleDrawingComponent::GetInstance().impl_ = nullptr;
    delete knuckleDrawing;
    knuckleDrawing = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleDrawingComponentTest_Load
 * @tc.desc: Test Overrides Load function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDrawingComponentTest, KnuckleDrawingComponentTest_Load, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDrawingComponent::GetInstance().Unload();

    MockIKnuckleDrawing *knuckleDrawing = new (std::nothrow) MockIKnuckleDrawing();
    ASSERT_NE(knuckleDrawing, nullptr);

    KnuckleDrawingComponent::GetInstance().impl_ = knuckleDrawing;
    KnuckleDrawingComponent::GetInstance().Load();
    KnuckleDrawingComponent::GetInstance().impl_ = nullptr;
    delete knuckleDrawing;
    knuckleDrawing = nullptr;

    KnuckleDrawingComponent::GetInstance().Load();
    ASSERT_NE(KnuckleDrawingComponent::GetInstance().impl_, nullptr);
    ASSERT_NE(KnuckleDrawingComponent::GetInstance().handle_, nullptr);
    ASSERT_NE(KnuckleDrawingComponent::GetInstance().create_, nullptr);
    ASSERT_NE(KnuckleDrawingComponent::GetInstance().destroy_, nullptr);
    ASSERT_GE(KnuckleDrawingComponent::GetInstance().timerId_, 0);

    KnuckleDrawingComponent::GetInstance().Unload();
}

/**
 * @tc.name: KnuckleDrawingComponentTest_Unload
 * @tc.desc: Test Overrides Unload function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDrawingComponentTest, KnuckleDrawingComponentTest_Unload, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDrawingComponent::GetInstance().Unload();
    ASSERT_EQ(KnuckleDrawingComponent::GetInstance().impl_, nullptr);
    ASSERT_EQ(KnuckleDrawingComponent::GetInstance().handle_, nullptr);
    ASSERT_EQ(KnuckleDrawingComponent::GetInstance().create_, nullptr);
    ASSERT_EQ(KnuckleDrawingComponent::GetInstance().destroy_, nullptr);
    ASSERT_EQ(KnuckleDrawingComponent::GetInstance().timerId_, -1);
}

/**
 * @tc.name: KnuckleDrawingComponentTest_LoadKnuckleSharedLibrary
 * @tc.desc: Test Overrides LoadKnuckleSharedLibrary function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDrawingComponentTest, KnuckleDrawingComponentTest_LoadKnuckleSharedLibrary, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDrawingComponent::GetInstance().Unload();
    bool ret = KnuckleDrawingComponent::GetInstance().LoadKnuckleSharedLibrary();
    ASSERT_TRUE(ret);
    ASSERT_NE(KnuckleDrawingComponent::GetInstance().handle_, nullptr);
    ASSERT_NE(KnuckleDrawingComponent::GetInstance().create_, nullptr);
    ASSERT_NE(KnuckleDrawingComponent::GetInstance().destroy_, nullptr);
    KnuckleDrawingComponent::GetInstance().Unload();
}
} // namespace OHOS
} // namespace MMI