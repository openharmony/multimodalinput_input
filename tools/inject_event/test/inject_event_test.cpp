/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "input_manager_command.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace std;
class InjectEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:InjectEvent_InjectMouse_001
 * @tc.desc: test inject interface
 * @tc.type: FUNC
 * @tc.require: AR000GJN3F
 */
HWTEST_F(InjectEventTest, InjectEvent_InjectMouse_001, TestSize.Level1)
{}

/**
 * @tc.name:InjectEvent_InjectMouse_002
 * @tc.desc: test inject interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQBJ
 */
HWTEST_F(InjectEventTest, InjectEvent_InjectMouse_002, TestSize.Level1)
{}
}