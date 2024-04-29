/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <libinput.h>

#include "multimodal_input_connect_stub.h"
#include "mmi_service.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class MultimodalInputConnectStubTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDoen() {}
};

/**
 * @tc.name: StubHandleAllocSocketFd_001
 * @tc.desc: Test the function StubHandleAllocSocketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubHandleAllocSocketFd_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubHandleAllocSocketFd(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubAddInputEventFilter_001
 * @tc.desc: Test the function StubAddInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAddInputEventFilter_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 22;
    int32_t ret = stub->StubAddInputEventFilter(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubRemoveInputEventFilter_001
 * @tc.desc: Test the function StubRemoveInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputEventFilter_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 201;
    int32_t ret = stub->StubRemoveInputEventFilter(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetMouseScrollRows_001
 * @tc.desc: Test the function StubSetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseScrollRows_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetMouseScrollRows(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetCustomCursor_001
 * @tc.desc: Test the function StubSetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetCustomCursor_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetCustomCursor(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetMouseIcon_001
 * @tc.desc: Test the function StubSetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseIcon_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetMouseIcon(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetMouseHotSpot_001
 * @tc.desc: Test the function StubSetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseHotSpot_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetMouseHotSpot(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubGetMouseScrollRows_001
 * @tc.desc: Test the function StubGetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetMouseScrollRows_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubGetMouseScrollRows(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetPointerSize_001
 * @tc.desc: Test the function StubSetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerSize_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetPointerSize(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetNapStatus_001
 * @tc.desc: Test the function StubSetNapStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetNapStatus_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetNapStatus(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubGetPointerSize_001
 * @tc.desc: Test the function StubGetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerSize_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubGetPointerSize(data, reply);
    EXPECT_EQ(ret, returnCode);
}
} // namespace MMI
} // namespace OHOS