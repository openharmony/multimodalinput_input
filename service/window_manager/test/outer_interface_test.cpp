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
#ifdef OHOS_WESTEN_MODEL
#include "outer_interface.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

class OuterInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(OuterInterfaceTest, DistributedEventHandler_001, TestSize.Level1)
{
    OuterInterface outerInterface;
    std::string keyEventStr = "KeyEvent1";
    KeyEventValueTransformations keyEventValue = {};
    keyEventValue.keyEvent = keyEventStr;
    KEY_STATE state = KEY_STATE_RELEASED;
    outerInterface.DistributedEventHandler(keyEventValue, state, 1);
}

HWTEST_F(OuterInterfaceTest, DistributedEventHandler_002, TestSize.Level1)
{
    OuterInterface outerInterface;
    std::string keyEventStr = "KeyEvent2";
    KeyEventValueTransformations keyEventValue = {};
    keyEventValue.keyEvent = keyEventStr;
    KEY_STATE state = KEY_STATE_RELEASED;
    outerInterface.DistributedEventHandler(keyEventValue, state, 2);
}

HWTEST_F(OuterInterfaceTest, DistributedEventHandler_003, TestSize.Level1)
{
    OuterInterface outerInterface;
    std::string keyEventStr = "KeyEvent3";
    KeyEventValueTransformations keyEventValue = {};
    keyEventValue.keyEvent = keyEventStr;
    KEY_STATE state = KEY_STATE_RELEASED;
    outerInterface.DistributedEventHandler(keyEventValue, state, 3);
}

HWTEST_F(OuterInterfaceTest, IsFocusChange, TestSize.Level1)
{
    OuterInterface outerInterface;
    int srcSurfaceId = 1;
    int desSurfaceId = 2;
    EXPECT_TRUE((outerInterface.IsFocusChange(srcSurfaceId, desSurfaceId)) == desSurfaceId);
}

HWTEST_F(OuterInterfaceTest, notifyFocusChange, TestSize.Level1)
{
    OuterInterface outerInterface;
    EXPECT_TRUE((outerInterface.notifyFocusChange(1, 1)) == RET_ERR);
}

HWTEST_F(OuterInterfaceTest, GetSystemEventAttrByKeyValue, TestSize.Level1)
{
    OuterInterface outerInterface;
    EXPECT_TRUE((outerInterface.GetSystemEventAttrByKeyValue(3)) == MMI_SYSTEM_SERVICE_AND_APP);
}
} // namespace
#endif