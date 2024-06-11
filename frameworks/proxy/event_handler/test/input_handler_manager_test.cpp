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

#include "input_handler_manager.h"


namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputHandlerManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};


class MyInputHandlerManager : public InputHandlerManager {
public:
    MyInputHandlerManager() = default;
    ~MyInputHandlerManager() override = default;

protected:
    InputHandlerType GetHandlerType() const override
    {
        return InputHandlerType::INTERCEPTOR;
    }
};

/**
 * @tc.name: InputHandlerManagerTest_FindHandler_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_FindHandler_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    int32_t handlerId = 1;
    ASSERT_NO_FATAL_FAILURE(manager.FindHandler(handlerId));
    handlerId = -1;
    ASSERT_NO_FATAL_FAILURE(manager.FindHandler(handlerId));
}

/**
 * @tc.name: InputHandlerManagerTest_AddMouseEventId_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_AddMouseEventId_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    ASSERT_NO_FATAL_FAILURE(manager.AddMouseEventId(pointerEvent));
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ASSERT_NO_FATAL_FAILURE(manager.AddMouseEventId(pointerEvent));
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    ASSERT_NO_FATAL_FAILURE(manager.AddMouseEventId(pointerEvent));
}

/**
 * @tc.name: InputHandlerManagerTest_HasHandler_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_HasHandler_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    int32_t handlerId = 1;
    ASSERT_NO_FATAL_FAILURE(manager.HasHandler(handlerId));
    handlerId = -1;
    ASSERT_NO_FATAL_FAILURE(manager.HasHandler(handlerId));
}

/**
 * @tc.name: InputHandlerManagerTest_OnDispatchEventProcessed_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputHandlerManagerTest, InputHandlerManagerTest_OnDispatchEventProcessed_001, TestSize.Level1)
{
    MyInputHandlerManager manager;
    int32_t eventId = 1;
    int64_t actionTime = 2;
    ASSERT_NO_FATAL_FAILURE(manager.OnDispatchEventProcessed(eventId, actionTime));
    eventId = -1;
    actionTime = -2;
    ASSERT_NO_FATAL_FAILURE(manager.OnDispatchEventProcessed(eventId, actionTime));
}
} // namespace MMI
} // namespace OHOS