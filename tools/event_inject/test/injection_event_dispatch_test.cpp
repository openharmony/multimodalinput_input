/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "injection_event_dispatch.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InjectionEventDispatchTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:Test_Init
 * @tc.desc:Verify InjectionEventDispatch Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InjectionEventDispatchTest, Test_Init, TestSize.Level1)
{
    InjectionEventDispatch injectionEventDispatch;
    injectionEventDispatch.Init();
}

/**
 * @tc.name:Test_OnJson
 * @tc.desc:Verify InjectionEventDispatch OnJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InjectionEventDispatchTest, Test_OnJson, TestSize.Level1)
{
    const std::string path = "/data/json/Test_InjectionEventDispatchTestOnJson.json";
    InjectionEventDispatch injectionEventDispatch;
    injectionEventDispatch.injectArgvs_.push_back("json");
    injectionEventDispatch.injectArgvs_.push_back(path);
    int32_t ret = injectionEventDispatch.OnJson();
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace MMI
} // namespace OHOS
