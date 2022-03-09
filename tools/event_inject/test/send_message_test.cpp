/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "send_message.h"
#include <gtest/gtest.h>

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
} // namespace

class SendMessageTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:Test_GetDevIndexName
 * @tc.desc:Verify SendMessage function GetDevIndexName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SendMessageTest, Test_GetDevIndexName, TestSize.Level1)
{
    SendMessage sendMessage;
    const std::string deviceName = "mouse";
    auto ret = sendMessage.GetDevIndexName(deviceName);
    EXPECT_EQ(ret, 32);
}
} // namespace MMI
} // namespace OHOS