 /*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dlfcn.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "key_command_types.h"
#include "knuckle_handler_component.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleHandlerComponentTest"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace MMI {
class KnuckleHandlerComponentTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {}
    void SetCase() {}
};

class MockIKnuckleHandler : public IKnuckleHandler {
public:
    MockIKnuckleHandler() = default;
    ~MockIKnuckleHandler() override = default;

    MOCK_METHOD2(Draw, void(const OLD::DisplayInfo&, const std::shared_ptr<PointerEvent>&));
    MOCK_METHOD2(SetCurrentToolType, void(const struct TouchType&, int32_t&));
    MOCK_METHOD1(NotifyTouchUp, void(struct TouchType*));
    MOCK_METHOD0(EnableFingersense, void(void));
    MOCK_METHOD0(DisableFingersense, void(void));
    MOCK_METHOD1(UpdateDisplayMode, void(int32_t));
    MOCK_METHOD3(SaveTouchInfo, void(float, float, int32_t));
    MOCK_METHOD3(CheckKnuckleEvent, int32_t(float, float, bool&));
    MOCK_METHOD2(SetMultiWindowScreenId, void(uint64_t, uint64_t));
    MOCK_METHOD1(HandleKnuckleEvent, void(std::shared_ptr<PointerEvent>));
    MOCK_METHOD0(RegisterSwitchObserver, void(void));
    MOCK_METHOD1(RegisterKnuckleSwitchByUserId, int32_t(int32_t));
    MOCK_METHOD2(SetKnucklePermissions, int32_t(uint32_t, bool));
    MOCK_METHOD0(SkipKnuckleDetect, bool());
    MOCK_METHOD1(SetKnuckleSwitch, int32_t(bool));
    MOCK_METHOD1(Dump, void(int32_t));
};

/**
 * @tc.name: KnuckleHandlerComponentTest_GetInstance
 * @tc.desc: Test Overrides GetInstance function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_GetInstance, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent &knuckleHandlerComp = KnuckleHandlerComponent::GetInstance();
    ASSERT_EQ(knuckleHandlerComp.handle_, nullptr);
    ASSERT_EQ(knuckleHandlerComp.create_, nullptr);
    ASSERT_EQ(knuckleHandlerComp.destroy_, nullptr);
    ASSERT_EQ(knuckleHandlerComp.impl_, nullptr);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_SetCurrentToolType
 * @tc.desc: Test Overrides SetCurrentToolType function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_SetCurrentToolType, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, SetCurrentToolType(_, _)).WillOnce([&isCalled] {
        isCalled = true;
    });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    struct TouchType touchType;
    int32_t toolType = PointerEvent::TOOL_TYPE_FINGER;

    KnuckleHandlerComponent::GetInstance().SetCurrentToolType(touchType, toolType);
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_NotifyTouchUp
 * @tc.desc: Test Overrides NotifyTouchUp function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_NotifyTouchUp, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, NotifyTouchUp(_)).WillOnce([&isCalled] {
        isCalled = true;
    });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    KnuckleHandlerComponent::GetInstance().NotifyTouchUp(nullptr);
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_EnableFingersense
 * @tc.desc: Test Overrides EnableFingersense function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_EnableFingersense, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, EnableFingersense()).WillOnce([&isCalled] {
        isCalled = true;
    });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    KnuckleHandlerComponent::GetInstance().EnableFingersense();
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_DisableFingersense
 * @tc.desc: Test Overrides DisableFingersense function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_DisableFingersense, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, DisableFingersense()).WillOnce([&isCalled] {
        isCalled = true;
    });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    KnuckleHandlerComponent::GetInstance().DisableFingersense();
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_UpdateDisplayMode
 * @tc.desc: Test Overrides UpdateDisplayMode function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_UpdateDisplayMode, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, UpdateDisplayMode(_)).WillOnce([&isCalled] {
        isCalled = true;
    });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    KnuckleHandlerComponent::GetInstance().UpdateDisplayMode(0);
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_SaveTouchInfo
 * @tc.desc: Test Overrides SaveTouchInfo function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_SaveTouchInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, SaveTouchInfo(_, _, _)).WillOnce([&isCalled] {
        isCalled = true;
    });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    KnuckleHandlerComponent::GetInstance().SaveTouchInfo(0, 0, PointerEvent::TOOL_TYPE_FINGER);
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_CheckKnuckleEvent
 * @tc.desc: Test Overrides CheckKnuckleEvent function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_CheckKnuckleEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, CheckKnuckleEvent(_, _, _)).WillOnce(
        [&isCalled] (float pointX, float pointY, bool &isKnuckleType) -> bool {
            (void)pointX;
            (void)pointY;
            (void)isKnuckleType;
            isCalled = true;
            return true;
        });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    bool isKnuckleTypeParam = false;
    KnuckleHandlerComponent::GetInstance().CheckKnuckleEvent(0, 0, isKnuckleTypeParam);
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_SetMultiWindowScreenId
 * @tc.desc: Test Overrides SetMultiWindowScreenId function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_SetMultiWindowScreenId, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, SetMultiWindowScreenId(_, _)).WillOnce([&isCalled] {
        isCalled = true;
    });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    KnuckleHandlerComponent::GetInstance().SetMultiWindowScreenId(0, 0);
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_HandleKnuckleEvent
 * @tc.desc: Test Overrides HandleKnuckleEvent function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_HandleKnuckleEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, HandleKnuckleEvent(_)).WillOnce([&isCalled] {
        isCalled = true;
    });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    KnuckleHandlerComponent::GetInstance().HandleKnuckleEvent(nullptr);
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_RegisterSwitchObserver
 * @tc.desc: Test Overrides RegisterSwitchObserver function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_RegisterSwitchObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, RegisterSwitchObserver()).WillOnce([&isCalled] {
        isCalled = true;
    });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    KnuckleHandlerComponent::GetInstance().RegisterSwitchObserver();
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_RegisterKnuckleSwitchByUserId
 * @tc.desc: Test Overrides RegisterKnuckleSwitchByUserId function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_RegisterKnuckleSwitchByUserId, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, RegisterKnuckleSwitchByUserId(_)).WillOnce(
        [&isCalled] (int32_t userId) -> int32_t {
            (void)userId;
            isCalled = true;
            return RET_OK;
        });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    KnuckleHandlerComponent::GetInstance().RegisterKnuckleSwitchByUserId(0);
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_SetKnucklePermissions
 * @tc.desc: Test Overrides SetKnucklePermissions function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_SetKnucklePermissions, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, SetKnucklePermissions(_, _)).WillOnce(
        [&isCalled] (uint32_t permissions, bool enable) -> int32_t {
            (void)permissions;
            (void)enable;
            isCalled = true;
            return RET_OK;
        });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    KnuckleHandlerComponent::GetInstance().SetKnucklePermissions(0, false);
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_SkipKnuckleDetect
 * @tc.desc: Test Overrides SkipKnuckleDetect function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_SkipKnuckleDetect, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, SkipKnuckleDetect()).WillOnce([&isCalled] () -> bool {
        isCalled = true;
        return true;
    });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    KnuckleHandlerComponent::GetInstance().SkipKnuckleDetect();
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_SetKnuckleSwitch
 * @tc.desc: Test Overrides SetKnuckleSwitch function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_SetKnuckleSwitch, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, SetKnuckleSwitch(_)).WillOnce(
        [&isCalled] (bool knuckleSwitch) -> int32_t {
            (void)knuckleSwitch;
            isCalled = true;
            return RET_OK;
        });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    KnuckleHandlerComponent::GetInstance().SetKnuckleSwitch(true);
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleHandlerComponentTest_Dump
 * @tc.desc: Test Overrides Dump function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleHandlerComponentTest_Dump, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleHandlerComponent::GetInstance().Unload();

    MockIKnuckleHandler *knuckleHandler = new (std::nothrow) MockIKnuckleHandler();
    ASSERT_NE(knuckleHandler, nullptr);

    bool isCalled = false;
    EXPECT_CALL(*knuckleHandler, Dump(_)).WillOnce([&isCalled] {
        isCalled = true;
    });
    KnuckleHandlerComponent::GetInstance().impl_ = knuckleHandler;

    KnuckleHandlerComponent::GetInstance().Dump(1);
    KnuckleHandlerComponent::GetInstance().impl_ = nullptr;
    delete knuckleHandler;
    knuckleHandler = nullptr;

    EXPECT_TRUE(isCalled);
}

/**
 * @tc.name: KnuckleContextImpl_GetPhysicalDisplay
 * @tc.desc: Test Overrides GetPhysicalDisplay function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_GetPhysicalDisplay, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    auto displayInfo = ctx->GetPhysicalDisplay(0);
    EXPECT_EQ(displayInfo, nullptr);
}

/**
 * @tc.name: KnuckleContextImpl_GetWindowAndDisplayInfo
 * @tc.desc: Test Overrides GetWindowAndDisplayInfo function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_GetWindowAndDisplayInfo, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    auto windowInfo = ctx->GetWindowAndDisplayInfo(0, 0);
    EXPECT_FALSE(windowInfo);
}

/**
 * @tc.name: KnuckleContextImpl_ReportKnuckleClickEvent
 * @tc.desc: Test Overrides ReportKnuckleClickEvent function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportKnuckleClickEvent, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->ReportKnuckleClickEvent());
}

/**
 * @tc.name: KnuckleContextImpl_ReportFailIfOneSuccTwoFail
 * @tc.desc: Test Overrides ReportFailIfOneSuccTwoFail function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportFailIfOneSuccTwoFail, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->ReportFailIfOneSuccTwoFail(nullptr));
}

/**
 * @tc.name: KnuckleContextImpl_ReportFailIfKnockTooFast
 * @tc.desc: Test Overrides ReportFailIfKnockTooFast function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportFailIfKnockTooFast, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->ReportFailIfKnockTooFast());
}

/**
 * @tc.name: KnuckleContextImpl_ReportSingleKnuckleDoubleClickEvent
 * @tc.desc: Test Overrides ReportSingleKnuckleDoubleClickEvent function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportSingleKnuckleDoubleClickEvent, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->ReportSingleKnuckleDoubleClickEvent(0, 0));
}

/**
 * @tc.name: KnuckleContextImpl_ReportScreenRecorderGesture
 * @tc.desc: Test Overrides ReportScreenRecorderGesture function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportScreenRecorderGesture, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->ReportScreenRecorderGesture(0));
}

/**
 * @tc.name: KnuckleContextImpl_ReportFailIfInvalidTime
 * @tc.desc: Test Overrides ReportFailIfInvalidTime function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportFailIfInvalidTime, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->ReportFailIfInvalidTime(nullptr, 0));
}

/**
 * @tc.name: KnuckleContextImpl_ReportFailIfInvalidDistance
 * @tc.desc: Test Overrides ReportFailIfInvalidDistance function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportFailIfInvalidDistance, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->ReportFailIfInvalidDistance(nullptr, 0));
}

/**
 * @tc.name: KnuckleContextImpl_ReportScreenCaptureGesture
 * @tc.desc: Test Overrides ReportScreenCaptureGesture function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportScreenCaptureGesture, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->ReportScreenCaptureGesture());
}

/**
 * @tc.name: KnuckleContextImpl_ReportKnuckleGestureFaildTimes
 * @tc.desc: Test Overrides ReportKnuckleGestureFaildTimes function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportKnuckleGestureFaildTimes, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->ReportKnuckleGestureFaildTimes());
}

/**
 * @tc.name: KnuckleContextImpl_ReportKnuckleGestureTrackLength
 * @tc.desc: Test Overrides ReportKnuckleGestureTrackLength function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportKnuckleGestureTrackLength, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->ReportKnuckleGestureTrackLength(0));
}

/**
 * @tc.name: KnuckleContextImpl_ReportKnuckleGestureTrackTime
 * @tc.desc: Test Overrides ReportKnuckleGestureTrackTime function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportKnuckleGestureTrackTime, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    std::vector<int64_t> gestureTimeStamps;
    ASSERT_NO_FATAL_FAILURE(ctx->ReportKnuckleGestureTrackTime(gestureTimeStamps));
}

/**
 * @tc.name: KnuckleContextImpl_ReportKnuckleGestureFromSuccessToFailTime
 * @tc.desc: Test Overrides ReportKnuckleGestureFromSuccessToFailTime function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportKnuckleGestureFromSuccessToFailTime, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->ReportKnuckleGestureFromSuccessToFailTime(0));
}

/**
 * @tc.name: KnuckleContextImpl_ReportSmartShotSuccTimes
 * @tc.desc: Test Overrides ReportSmartShotSuccTimes function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportSmartShotSuccTimes, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->ReportSmartShotSuccTimes());
}

/**
 * @tc.name: KnuckleContextImpl_ReportKnuckleDrawSSuccessTimes
 * @tc.desc: Test Overrides ReportKnuckleDrawSSuccessTimes function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportKnuckleDrawSSuccessTimes, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->ReportKnuckleDrawSSuccessTimes());
}

/**
 * @tc.name: KnuckleContextImpl_ReportKnuckleGestureFromFailToSuccessTime
 * @tc.desc: Test Overrides ReportKnuckleGestureFromFailToSuccessTime function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_ReportKnuckleGestureFromFailToSuccessTime, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->ReportKnuckleGestureFromFailToSuccessTime(0));
}

/**
 * @tc.name: KnuckleContextImpl_GetBundleName
 * @tc.desc: Test Overrides GetBundleName function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_GetBundleName, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    std::string bundleName = ctx->GetBundleName("");
    EXPECT_EQ(bundleName, "");
}

/**
 * @tc.name: KnuckleContextImpl_LaunchAbility
 * @tc.desc: Test Overrides LaunchAbility function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_LaunchAbility, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    Ability ability;
    int64_t delay = 0;
    ASSERT_NO_FATAL_FAILURE(ctx->LaunchAbility(ability, delay));
}

/**
 * @tc.name: KnuckleContextImpl_SyncKnuckleStatus
 * @tc.desc: Test Overrides SyncKnuckleStatus function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_SyncKnuckleStatus, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    ASSERT_NE(ctx, nullptr);
    ASSERT_NO_FATAL_FAILURE(ctx->SyncKnuckleStatus(false));
}

/**
 * @tc.name: KnuckleContextImpl_UpdateDisplayId
 * @tc.desc: Test Overrides UpdateDisplayId function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleHandlerComponentTest, KnuckleContextImpl_UpdateDisplayId, TestSize.Level1)
{
    std::shared_ptr<KnuckleContextImpl> ctx = std::make_shared<KnuckleContextImpl>();
    int32_t displayId = 0;
    ASSERT_NO_FATAL_FAILURE(ctx->UpdateDisplayId(displayId));
}
} // namespace OHOS
} // namespace MMI