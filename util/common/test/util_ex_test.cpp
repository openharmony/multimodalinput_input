/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "proto.h"
#include "util_ex.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS;
} // namespace
class UtilExTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:EnumAdd_001
 * @tc.desc:Verify enum add
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilExTest, EnumAdd_001, TestSize.Level1)
{
    MmiMessageId messageId1 = MmiMessageId::INVALID;
    auto messageId2 = EnumAdd(messageId1, 1);
    EXPECT_EQ(messageId2, MmiMessageId::LIBINPUT_EVENT_DEVICE_ADDED);
}

/**
 * @tc.name:EnumAdd_002
 * @tc.desc:Verify enum add
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilExTest, EnumAdd_002, TestSize.Level1)
{
    MmiMessageId messageId1 = MmiMessageId::LIBINPUT_EVENT_DEVICE_ADDED;
    auto messageId2 = EnumAdd(messageId1, -1);
    EXPECT_EQ(messageId2, MmiMessageId::INVALID);
}
} // namespace MMI
} // namespace OHOS