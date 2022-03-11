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

#include "injection_tools_help_func.h"
#include "msg_head.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
} // namespace

class InjectionToolsHelpFuncTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
};

/**
 * @tc.name:Test_InjectionToolsHelpFuncTest
 * @tc.desc:Verify InjectionToolsHelpFunc function GetHelpText
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InjectionToolsHelpFuncTest, Test_InjectionToolsHelpFuncTest, TestSize.Level1)
{
    InjectionToolsHelpFunc injectionToolsHelpFunc;
    auto ret = injectionToolsHelpFunc.GetHelpText();
    EXPECT_EQ(ret.empty(), false);
}
} // namespace MMI
} // namespace OHOS