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

#include "common_event_handler.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

class CommonEventHandlerApiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(CommonEventHandlerApiTest, Api_Test_OnShowMenu, TestSize.Level1)
{
    CommonEventHandler commonEventHandlerTest;
    const MultimodalEvent event;
    auto retShowMenu = commonEventHandlerTest.OnShowMenu(event);
    EXPECT_EQ(retShowMenu, false);
}

HWTEST_F(CommonEventHandlerApiTest, Api_Test_OnSend, TestSize.Level1)
{
    CommonEventHandler commonEventHandlerTest;
    const MultimodalEvent event;
    auto retOnSend = commonEventHandlerTest.OnSend(event);
    EXPECT_EQ(retOnSend, false);
}

HWTEST_F(CommonEventHandlerApiTest, Api_Test_OnCopy, TestSize.Level1)
{
    CommonEventHandler commonEventHandlerTest;
    const MultimodalEvent event;
    auto retOnCopy = commonEventHandlerTest.OnCopy(event);
    EXPECT_EQ(retOnCopy, false);
}

HWTEST_F(CommonEventHandlerApiTest, Api_Test_OnPaste, TestSize.Level1)
{
    CommonEventHandler commonEventHandlerTest;
    const MultimodalEvent event;
    auto retOnPaste = commonEventHandlerTest.OnPaste(event);
    EXPECT_EQ(retOnPaste, false);
}

HWTEST_F(CommonEventHandlerApiTest, Api_Test_OnCut, TestSize.Level1)
{
    CommonEventHandler commonEventHandlerTest;
    const MultimodalEvent event;
    auto retOnCut = commonEventHandlerTest.OnCut(event);
    EXPECT_EQ(retOnCut, false);
}

HWTEST_F(CommonEventHandlerApiTest, Api_Test_OnUndo, TestSize.Level1)
{
    CommonEventHandler commonEventHandlerTest;
    const MultimodalEvent event;
    auto retOnUndo = commonEventHandlerTest.OnUndo(event);
    EXPECT_EQ(retOnUndo, false);
}

HWTEST_F(CommonEventHandlerApiTest, Api_Test_OnRefresh, TestSize.Level1)
{
    CommonEventHandler commonEventHandlerTest;
    const MultimodalEvent event;
    auto retOnRefresh = commonEventHandlerTest.OnRefresh(event);
    EXPECT_EQ(retOnRefresh, false);
}

HWTEST_F(CommonEventHandlerApiTest, Api_Test_OnStartDrag, TestSize.Level1)
{
    CommonEventHandler commonEventHandlerTest;
    const MultimodalEvent event;
    auto retOnStartDrag = commonEventHandlerTest.OnStartDrag(event);
    EXPECT_EQ(retOnStartDrag, false);
}

HWTEST_F(CommonEventHandlerApiTest, Api_Test_OnCancel, TestSize.Level1)
{
    CommonEventHandler commonEventHandlerTest;
    const MultimodalEvent event;
    auto retOnCancel = commonEventHandlerTest.OnCancel(event);
    EXPECT_EQ(retOnCancel, false);
}

HWTEST_F(CommonEventHandlerApiTest, Api_Test_OnEnter, TestSize.Level1)
{
    CommonEventHandler commonEventHandlerTest;
    const MultimodalEvent event;
    auto retOnEnter = commonEventHandlerTest.OnEnter(event);
    EXPECT_EQ(retOnEnter, false);
}

HWTEST_F(CommonEventHandlerApiTest, Api_Test_OnPrevious, TestSize.Level1)
{
    CommonEventHandler commonEventHandlerTest;
    const MultimodalEvent event;
    auto retOnPrevious = commonEventHandlerTest.OnPrevious(event);
    EXPECT_EQ(retOnPrevious, false);
}

HWTEST_F(CommonEventHandlerApiTest, Api_Test_OnNext, TestSize.Level1)
{
    CommonEventHandler commonEventHandlerTest;
    const MultimodalEvent event;
    auto retOnNext = commonEventHandlerTest.OnNext(event);
    EXPECT_EQ(retOnNext, false);
}

HWTEST_F(CommonEventHandlerApiTest, Api_Test_OnBack, TestSize.Level1)
{
    CommonEventHandler commonEventHandlerTest;
    const MultimodalEvent event;
    auto retOnBack = commonEventHandlerTest.OnBack(event);
    EXPECT_EQ(retOnBack, false);
}

HWTEST_F(CommonEventHandlerApiTest, Api_Test_OnPrint, TestSize.Level1)
{
    CommonEventHandler commonEventHandlerTest;
    const MultimodalEvent event;
    auto retOnPrint = commonEventHandlerTest.OnPrint(event);
    EXPECT_EQ(retOnPrint, false);
}
} // namespace
