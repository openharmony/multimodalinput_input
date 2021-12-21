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
#include "common_event_handler.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

class CommonEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: OnShowMenu
 * @tc.desc: commond event handle OnShowMenu
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, construct, TestSize.Level1)
{
    CommonEventHandler commonHandleTmp;
}

/**
 * @tc.name: OnShowMenu
 * @tc.desc: commond event handle OnShowMenu
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, OnShowMenu, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    CommonEventHandler commonEventHandle;
    bool retResult = commonEventHandle.OnShowMenu(multiModalEvent);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: OnSend
 * @tc.desc: commond event handle OnSend
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, OnSend, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    CommonEventHandler commonEventHandle;
    bool retResult = commonEventHandle.OnSend(multiModalEvent);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: OnCopy
 * @tc.desc: commond event handle OnCopy
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, OnCopy, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    CommonEventHandler commonEventHandle;
    bool retResult = commonEventHandle.OnCopy(multiModalEvent);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: OnPaste
 * @tc.desc: commond event handle OnPaste
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, OnPaste, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    CommonEventHandler commonEventHandle;
    bool retResult = commonEventHandle.OnPaste(multiModalEvent);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: OnCut
 * @tc.desc: commond event handle OnCut
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, OnCut, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    CommonEventHandler commonEventHandle;
    bool retResult = commonEventHandle.OnCut(multiModalEvent);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: OnUndo
 * @tc.desc: commond event handle OnUndo
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, OnUndo, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    CommonEventHandler commonEventHandle;
    bool retResult = commonEventHandle.OnUndo(multiModalEvent);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: OnRefresh
 * @tc.desc: commond event handle OnRefresh
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, OnRefresh, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    CommonEventHandler commonEventHandle;
    bool retResult = commonEventHandle.OnRefresh(multiModalEvent);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: OnStartDrag
 * @tc.desc: commond event handle OnStartDrag
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, OnStartDrag, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    CommonEventHandler commonEventHandle;
    bool retResult = commonEventHandle.OnStartDrag(multiModalEvent);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: OnCancel
 * @tc.desc: commond event handle OnCancel
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, OnCancel, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    CommonEventHandler commonEventHandle;
    bool retResult = commonEventHandle.OnCancel(multiModalEvent);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: OnEnter
 * @tc.desc: commond event handle OnEnter
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, OnEnter, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    CommonEventHandler commonEventHandle;
    bool retResult = commonEventHandle.OnEnter(multiModalEvent);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: OnNext
 * @tc.desc: commond event handle OnNext
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, OnNext, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    CommonEventHandler commonEventHandle;
    bool retResult = commonEventHandle.OnNext(multiModalEvent);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: OnBack
 * @tc.desc: commond event handle OnBack
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, OnBack, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    CommonEventHandler commonEventHandle;
    bool retResult = commonEventHandle.OnBack(multiModalEvent);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: OnPrevious
 * @tc.desc: commond event handle OnPrint
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, OnPrint, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    CommonEventHandler commonEventHandle;
    bool retResult = commonEventHandle.OnPrint(multiModalEvent);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: OnPrevious
 * @tc.desc: commond event handle OnPrevious
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(CommonEventHandlerTest, OnPrevious, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    CommonEventHandler commonEventHandle;
    bool retResult = commonEventHandle.OnPrevious(multiModalEvent);
    EXPECT_FALSE(retResult);
}
} // namespace
