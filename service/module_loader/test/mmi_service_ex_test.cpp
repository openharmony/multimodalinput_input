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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "input_handler_type.h"
#include "mmi_service.h"
#include "mmi_log.h"
#include "mock.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MMIServiceExTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
constexpr int32_t REMOVE_OBSERVER { -2 };
} // namespace

class MMIServiceExTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void MMIServiceExTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}

void MMIServiceExTest::TearDownTestCase()
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}

/**
 * @tc.name: MMIServiceExTest_AddInputHandler
 * @tc.desc: Test the function AddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServiceExTest, MMIServiceExTest_AddInputHandler, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, PostSyncTask(_)).WillRepeatedly(Return(RET_OK));
    MMIService mmiService;
    InputHandlerType handlerType = INTERCEPTOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_POINTER;
    int32_t priority = 1;
    uint32_t deviceTags = 1;
    NapProcess::GetInstance()->napClientPid_ = REMOVE_OBSERVER;
    EXPECT_EQ(mmiService.AddInputHandler(handlerType, eventType, priority, deviceTags), RET_OK);
}

/**
 * @tc.name: MMIServiceExTest_SetMouseScrollRows
 * @tc.desc: Cover the else branch of if (ret != RET_OK)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServiceExTest, MMIServiceExTest_SetMouseScrollRows, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, PostSyncTask(_)).WillRepeatedly(Return(RET_OK));
    MMIService mmiService;
    int32_t rows = 10;
    EXPECT_EQ(mmiService.SetMouseScrollRows(rows), RET_OK);
}

/**
 * @tc.name: MMIServiceExTest_SetMouseScrollRows_001
 * @tc.desc: Cover if (ret != RET_OK) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServiceExTest, MMIServiceExTest_SetMouseScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, PostSyncTask(_)).WillRepeatedly(Return(RET_ERR));
    MMIService mmiService;
    int32_t rows = 10;
    EXPECT_EQ(mmiService.SetMouseScrollRows(rows), RET_ERR);
}

/**
 * @tc.name: MMIServiceExTest_SetPointerSpeed
 * @tc.desc: Cover the else branch of if (ret != RET_OK)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServiceExTest, MMIServiceExTest_SetPointerSpeed, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, PostSyncTask(_)).WillRepeatedly(Return(RET_OK));
    MMIService mmiService;
    int32_t speed = 10;
    EXPECT_EQ(mmiService.SetPointerSpeed(speed), RET_OK);
}

/**
 * @tc.name: MMIServiceExTest_SetPointerSpeed_001
 * @tc.desc: Cover if (ret != RET_OK) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServiceExTest, MMIServiceExTest_SetPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, PostSyncTask(_)).WillRepeatedly(Return(RET_ERR));
    MMIService mmiService;
    int32_t speed = 10;
    EXPECT_EQ(mmiService.SetPointerSpeed(speed), RET_ERR);
}


/**
 * @tc.name: MMIServiceExTest_SetKeyboardRepeatDelay
 * @tc.desc: Cover the else branch of if (ret != RET_OK)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServiceExTest, MMIServiceExTest_SetKeyboardRepeatDelay, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, PostSyncTask(_)).WillRepeatedly(Return(RET_OK));
    MMIService mmiService;
    int32_t speed = 10;
    EXPECT_EQ(mmiService.SetKeyboardRepeatDelay(speed), RET_OK);
}

/**
 * @tc.name: MMIServiceExTest_SetKeyboardRepeatDelay_001
 * @tc.desc: Cover if (ret != RET_OK) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServiceExTest, MMIServiceExTest_SetKeyboardRepeatDelay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, PostSyncTask(_)).WillRepeatedly(Return(RET_ERR));
    MMIService mmiService;
    int32_t delay = 100;
    EXPECT_EQ(mmiService.SetKeyboardRepeatDelay(delay), RET_ERR);
}
} // namespace MMI
} // namespace OHOS