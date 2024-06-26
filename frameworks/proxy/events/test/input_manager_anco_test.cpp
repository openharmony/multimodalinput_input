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
        << ",A:" << keyEvent->GetKeyrAction() << std::endl;
    return RET_OK;
}

int32_t AncoMonitor::UpdateWindowInfo(std::shared_ptr<AncoWindows> windows)
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
} // namespace MMI
} // namespace OHOS
