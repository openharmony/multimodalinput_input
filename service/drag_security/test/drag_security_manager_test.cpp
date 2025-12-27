/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>

#include "drag_security_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DragSecurityManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
} // namespace

class DragSecurityManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
protected:
    DragSecurityManager dragSecurityManager_;
};

/**
 * @tc.name: DragSecurityManagerTest_GenerateSignature_001
 * @tc.desc: DragSecurityManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragSecurityManagerTest, DragSecurityManagerTest_GenerateSignature_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

#ifdef OHOS_BUILD_ENABLE_DRAG_SECURITY
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03};
    DragSecurityData dragEventData;
    dragEventData.timestampMs = 123456789;
    dragEventData.coordinateX = 100.0;
    dragEventData.coordinateY = 200.0;

    std::vector<uint8_t> signature = dragSecurityManager_.GenerateSignature(nonce, dragEventData);

    EXPECT_FALSE(signature.empty());
#else

    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    EXPECT_NO_THROW(dragSecurityManager_.DragSecurityUpdatePointerEvent(pointerEvent));
#endif
}

/**
 * @tc.name: DragSecurityManagerTest_GenerateSignature_002
 * @tc.desc: DragSecurityManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragSecurityManagerTest, DragSecurityManagerTest_GenerateSignature_002, TestSize.Level1)
{
#ifdef OHOS_BUILD_ENABLE_DRAG_SECURITY
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03};
    DragSecurityData dragEventData;
    dragEventData.timestampMs = 123456789;
    dragEventData.coordinateX = 100.0;
    dragEventData.coordinateY = 200.0;

    std::vector<uint8_t> result = dragSecurityManager_.GenerateSignature(nonce, dragEventData);
    EXPECT_FALSE(result.empty());
#else
    DragSecurityManager dragSecurityManager;
    auto pointerEvent = std::make_shared<PointerEvent>(1);
    pointerEvent->SetDistributeEventTime(123456789);

    EXPECT_NO_THROW(dragSecurityManager_.DragSecurityUpdatePointerEvent(pointerEvent));
#endif
}

/**
 * @tc.name: DragSecurityManagerTest_DeliverNonce_001
 * @tc.desc: Test DeliverNonce with valid nonce
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragSecurityManagerTest, DragSecurityManagerTest_DeliverNonce_001, TestSize.Level1)
{
    std::string validNonce = "test_nonce";
    int32_t result = dragSecurityManager_.DeliverNonce(validNonce);

    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: DragSecurityManagerTest_DeliverNonce_002
 * @tc.desc: Test DeliverNonce with empty nonce
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragSecurityManagerTest, DragSecurityManagerTest_DeliverNonce_002, TestSize.Level1)
{
    std::string emptyNonce = "";
    int32_t result = dragSecurityManager_.DeliverNonce(emptyNonce);

    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: DragSecurityManagerTest_GetNonce_001
 * @tc.desc: Test GetNonce when nonce is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragSecurityManagerTest, DragSecurityManagerTest_GetNonce_001, TestSize.Level1)
{
    DragSecurityManager manager;
    std::string nonce = manager.GetNonce();

    EXPECT_TRUE(nonce.empty());
}

/**
 * @tc.name: DragSecurityManagerTest_GetNonce_002
 * @tc.desc: Test GetNonce after DeliverNonce
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragSecurityManagerTest, DragSecurityManagerTest_GetNonce_002, TestSize.Level1)
{
    DragSecurityManager manager;
    std::string testNonce = "test_nonce_123";
    manager.DeliverNonce(testNonce);

    std::string nonce = manager.GetNonce();

    EXPECT_EQ(nonce, testNonce);
}

/**
 * @tc.name: DragSecurityManagerTest_ResetNonce_001
 * @tc.desc: Test ResetNonce functionality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragSecurityManagerTest, DragSecurityManagerTest_ResetNonce_001, TestSize.Level1)
{
    DragSecurityManager manager;
    std::string testNonce = "test_nonce_123";
    manager.DeliverNonce(testNonce);

    std::string nonceBeforeReset = manager.GetNonce();
    EXPECT_EQ(nonceBeforeReset, testNonce);

    manager.ResetNonce();

    std::string nonceAfterReset = manager.GetNonce();
    EXPECT_TRUE(nonceAfterReset.empty());
}

#ifdef OHOS_BUILD_ENABLE_DRAG_SECURITY

/**
 * @tc.name: DragSecurityManagerTest_SerializeDragEventData_002
 * @tc.desc: Test SerializeDragEventData with zero values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragSecurityManagerTest, DragSecurityManagerTest_SerializeDragEventData_002, TestSize.Level1)
{
    DragSecurityData data;
    data.timestampMs = 0;
    data.coordinateX = 0.0;
    data.coordinateY = 0.0;

    std::string result = dragSecurityManager_.SerializeDragEventData(data);

    std::string expected = "0|0|0";
    EXPECT_EQ(result, expected);
}

/**
 * @tc.name: DragSecurityManagerTest_GetCurrentTimesTampMs_001
 * @tc.desc: Test GetCurrentTimesTampMs returns valid timestamp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragSecurityManagerTest, DragSecurityManagerTest_GetCurrentTimesTampMs_001, TestSize.Level1)
{
    uint64_t before = dragSecurityManager_.GetCurrentTimesTampMs();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    uint64_t after = dragSecurityManager_.GetCurrentTimesTampMs();

    EXPECT_GT(after, before);
}
#endif // OHOS_BUILD_ENABLE_DRAG_SECURITY
} // namespace MMI
} // namespace OHOS