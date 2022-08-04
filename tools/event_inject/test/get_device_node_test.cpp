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

#include <gtest/gtest.h>

#include "msg_head.h"
#include "proto.h"
#define private public
#include "get_device_node.h"
#undef private

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
} // namespace

class GetDeviceNodeTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:Test_GetDeviceNodeTestCmdError
 * @tc.desc:Verify ReadDeviceFile function right argument passed in
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetDeviceNodeTest, Test_GetDeviceNodeTestCmdError, TestSize.Level1)
{
    GetDeviceNode getDeviceNode;
    int32_t ret = 0;
    if (getDeviceNode.ReadDeviceFile().empty()) {
        ret = -1;
        EXPECT_EQ(ret, RET_ERR);
    }
    EXPECT_GT(ret, 0);
}
} // namespace MMI
} // namespace OHOS