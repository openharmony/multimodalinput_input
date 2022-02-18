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
#define private public
#include "injection_event_dispatch.h"
#undef private

// head file
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

class InjectionEventDispatchTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(InjectionEventDispatchTest, Test_Init, TestSize.Level1)
{
    InjectionEventDispatch injectionEventDispatch;
    injectionEventDispatch.Init();
}

HWTEST_F(InjectionEventDispatchTest, Test_OnJson, TestSize.Level1)
{
#ifdef OHOS_BUILD
    const std::string path = "/data/json/Test_InjectionEventDispatchTestOnJson.json";
#else
    const std::string path = "temp/Test_InjectionEventDispatchTestOnJson.json";
#endif
    InjectionEventDispatch injectionEventDispatch;
    injectionEventDispatch.injectArgvs_.push_back("json");
    injectionEventDispatch.injectArgvs_.push_back(path);
    int32_t ret = injectionEventDispatch.OnJson();
    EXPECT_EQ(ret, RET_ERR);
}

HWTEST_F(InjectionEventDispatchTest, Test_GetStartSocketPermission, TestSize.Level1)
{
    const std::string id = "aisensor";
    InjectionEventDispatch injectionEventDispatch;
    int32_t ret = injectionEventDispatch.GetStartSocketPermission(id);
    EXPECT_EQ(ret, false);
}

HWTEST_F(InjectionEventDispatchTest, Test_GetFunId, TestSize.Level1)
{
    InjectionEventDispatch injectionEventDispatch;
    injectionEventDispatch.funId_ = "aisensor";
    auto ret = injectionEventDispatch.GetFunId();
    EXPECT_EQ(ret, "aisensor");
}

HWTEST_F(InjectionEventDispatchTest, Test_OnHelp, TestSize.Level1)
{
    InjectionEventDispatch injectionEventDispatch;
    injectionEventDispatch.funId_ = "aisensor";
    auto ret = injectionEventDispatch.OnHelp();
    EXPECT_EQ(ret, RET_OK);
}

HWTEST_F(InjectionEventDispatchTest, Test_OnAisensor, TestSize.Level1)
{
    int32_t argc = 3;
    char argv[3][16] = {"functionName", "aisensor-all", "2"};
    InjectionEventDispatch injectionEventDispatch;
    std::vector<std::string> argvs;
    for (int32_t i = 0; i < argc; i++) {
        argvs.push_back(argv[i]);
    }
    injectionEventDispatch.Init();
    auto ret = injectionEventDispatch.VirifyArgvs(argc, argvs);
    injectionEventDispatch.Run();
    EXPECT_EQ(ret, true);
}

HWTEST_F(InjectionEventDispatchTest, Test_OnAisensorEach, TestSize.Level1)
{
    int32_t argc = 4;
    char argv[4][16] = { "functionName", "aisensor-each", "1103", "1" };
    InjectionEventDispatch injectionEventDispatch;
    std::vector<std::string> argvs;
    for (int32_t i = 0; i < argc; i++) {
        argvs.push_back(argv[i]);
    }
    injectionEventDispatch.Init();
    auto ret = injectionEventDispatch.VirifyArgvs(argc, argvs);
    injectionEventDispatch.Run();
    EXPECT_EQ(ret, true);
}

HWTEST_F(InjectionEventDispatchTest, Test_OnKnuckleAll, TestSize.Level1)
{
    int32_t argc = 3;
    char argv[3][16] = {"functionName", "knuckle-all", "2"};
    InjectionEventDispatch injectionEventDispatch;
    std::vector<std::string> argvs;
    for (int32_t i = 0; i < argc; i++) {
        argvs.push_back(argv[i]);
    }
    injectionEventDispatch.Init();
    auto ret = injectionEventDispatch.VirifyArgvs(argc, argvs);
    injectionEventDispatch.Run();
    EXPECT_EQ(ret, false);
}

HWTEST_F(InjectionEventDispatchTest, Test_OnKnuckleEach, TestSize.Level1)
{
    int32_t argc = 4;
    char argv[4][16] = {"functionName", "knuckle-each", "4001", "1"};
    InjectionEventDispatch injectionEventDispatch;
    std::vector<std::string> argvs;
    for (int32_t i = 0; i < argc; i++) {
        argvs.push_back(argv[i]);
    }
    injectionEventDispatch.Init();
    auto ret = injectionEventDispatch.VirifyArgvs(argc, argvs);
    injectionEventDispatch.Run();
    EXPECT_EQ(ret, false);
}
} // namespace
