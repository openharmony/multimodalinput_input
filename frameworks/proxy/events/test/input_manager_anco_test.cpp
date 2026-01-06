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

#include "define_multimodal.h"
#include "input_manager.h"
#include "anco_channel.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputManagerAncoTest"

namespace OHOS {
namespace MMI {
using namespace testing::ext;

class InputManagerAncoTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class AncoMonitor final : public IAncoConsumer {
public:
    AncoMonitor() = default;
    ~AncoMonitor() override = default;

    int32_t SyncInputEvent(std::shared_ptr<PointerEvent> pointerEvent) override;
    int32_t SyncInputEvent(std::shared_ptr<KeyEvent> keyEvent) override;
    int32_t UpdateWindowInfo(std::shared_ptr<AncoWindows> windows) override;
    int32_t SyncKnuckleStatus(bool isKnuckleEnable) override;
    int32_t UpdateOneHandData(const AncoOneHandData &oneHandData) override;
    int32_t UpdateExcludedKeyEventWindow(
        const AncoExcludedKeyEventWindow &excludedKeyEventWindow) override;
};

int32_t AncoMonitor::SyncInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    std::cout << "No:" << pointerEvent->GetId() << ",S:" << pointerEvent->GetSourceType()
        << ",A:" << pointerEvent->GetPointerAction() << std::endl;
    return RET_OK;
}

int32_t AncoMonitor::SyncInputEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    std::cout << "No:" << keyEvent->GetId() << ",K:" << keyEvent->GetKeyCode()
        << ",A:" << keyEvent->GetKeyAction() << std::endl;
    return RET_OK;
}

int32_t AncoMonitor::UpdateWindowInfo(std::shared_ptr<AncoWindows> windows)
{
    return RET_OK;
}

int32_t AncoMonitor::SyncKnuckleStatus(bool isKnuckleEnable)
{
    return RET_OK;
}

int32_t AncoMonitor::UpdateOneHandData(const AncoOneHandData &oneHandData)
{
    return RET_OK;
}

int32_t AncoMonitor::UpdateExcludedKeyEventWindow(
    const AncoExcludedKeyEventWindow &excludedKeyEventWindow)
{
    return RET_OK;
}

/**
 * @tc.name: InputManagerAncoTest_SyncPointerEvent_001
 * @tc.desc: Verify key event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerAncoTest, InputManagerAncoTest_SyncPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto monitor = std::make_shared<AncoMonitor>();
    ASSERT_EQ(InputManager::GetInstance()->AncoAddConsumer(monitor), RET_OK);
    std::this_thread::sleep_for(std::chrono::minutes(1));
    ASSERT_EQ(InputManager::GetInstance()->AncoRemoveConsumer(monitor), RET_OK);
}

/**
 * @tc.name: InputManagerAncoTest_UpdateExcludedKeyEventWindow_001
 * @tc.desc: UpdateExcludedKeyEventWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerAncoTest, InputManagerAncoTest_UpdateExcludedKeyEventWindow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto monitor = std::make_shared<AncoMonitor>();
    AncoExcludedKeyEventWindow data;
    data.windowIds = {1001, 1002, 1003};
    ASSERT_TRUE(monitor->UpdateExcludedKeyEventWindow(data), RET_OK);
}

/**
 * @tc.name: InputManagerAncoTest_AncoExcludedKeyEventWindow_001
 * @tc.desc: MarshallingAndUmarshallingTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerAncoTest, InputManagerAncoTest_AncoExcludedKeyEventWindow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AncoExcludedKeyEventWindow originalWindow;
    originalWindow.windowIds = {1001, 1002, 1003};

    Parcel parcel;
    ASSERT_TRUE(originalWindow.Marshalling(parcel));

    auto decodedWindow = AncoExcludedKeyEventWindow::Unmarshalling(parcel);
    ASSERT_NE(decodedWindow, nullptr);

    ASSERT_EQ(decodedWindow->windowIds.size(), 3);
    ASSERT_EQ(decodedWindow->windowIds[0], 1001);
    ASSERT_EQ(decodedWindow->windowIds[1], 1002);
    ASSERT_EQ(decodedWindow->windowIds[2], 1003);

    delete decodedWindow;
}

/**
 * @tc.name: InputManagerAncoTest_SyncPointerEvent_001
 * @tc.desc: EmptyWindowIdsTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerAncoTest, InputManagerAncoTest_AncoExcludedKeyEventWindow_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AncoExcludedKeyEventWindow emptyWindow;
    Parcel parcel;

    ASSERT_TRUE(emptyWindow.Marshalling(parcel));
    auto decodedWindow = AncoExcludedKeyEventWindow::Unmarshalling(parcel);

    ASSERT_NE(decodedWindow, nullptr);
    ASSERT_TRUE(decodedWindow->windowIds.empty());

    delete decodedWindow;
}

/**
 * @tc.name: InputManagerAncoTest_SyncPointerEvent_001
 * @tc.desc: ReadFromParcelFailureTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerAncoTest, InputManagerAncoTest_AncoExcludedKeyEventWindow_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel testParcel;
    auto failedWindow = AncoExcludedKeyEventWindow::Unmarshalling(testParcel);

    ASSERT_EQ(failedWindow, nullptr);
}

/**
 * @tc.name: InputManagerAncoTest_AncoChannel_001
 * @tc.desc: UpdateExcludedKeyEventWindowNormalTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerAncoTest, InputManagerAncoTest_AncoChannel_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AncoExcludedKeyEventWindow testWindow;
    testWindow.windowIds = {1001, 1002, 1003};
    auto ancoMonitor = std::make_shared<AncoMonitor>();
    sptr<IAncoChannel> channel = sptr<AncoChannel>::MakeSptr(ancoMonitor);
    auto result = channel->UpdateExcludedKeyEventWindow(testWindow);
    ASSERT_EQ(result, RET_OK);
}

/**
 * @tc.name: InputManagerAncoTest_AncoChannel_002
 * @tc.desc: ReadFromParcelFailureTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerAncoTest, InputManagerAncoTest_AncoChannel_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<IAncoChannel> channel = sptr<AncoChannel>::MakeSptr(nullptr);
    AncoExcludedKeyEventWindow testWindow;
    auto result = channel->UpdateExcludedKeyEventWindow(testWindow);
    ASSERT_EQ(result, RET_ERR);
}
} // namespace MMI
} // namespace OHOS
