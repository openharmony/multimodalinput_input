/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include <semaphore.h>

#include "accesstoken_kit.h"
#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_handler_manager.h"
#include "input_manager.h"
#include "multimodal_event_handler.h"
#include "nativetoken_kit.h"
#include "pointer_event.h"
#include "proto.h"
#include "token_setproc.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputManagerManualTest"

namespace OHOS {
namespace MMI {
using namespace Security::AccessToken;
using Security::AccessToken::AccessTokenID;
namespace {
using namespace testing::ext;
HapInfoParams infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "inputManagerManualTest",
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = true
};

PermissionDef infoManagerTestPermDef = {
    .permissionName = "ohos.permission.test",
    .bundleName = "inputManagerManualTest",
    .grantMode = 1,
    .availableLevel = APL_SYSTEM_CORE,
    .label = "label",
    .labelId = 1,
    .description = "test input event filter",
    .descriptionId = 1,
};

PermissionStateFull infoManagerTestState = {
    .permissionName = "ohos.permission.test",
    .isGeneral = true,
    .resDeviceID = { "local" },
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .grantFlags = { 1 },
};

HapPolicyParams infoManagerTestPolicyPrams = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain",
    .permList = { infoManagerTestPermDef },
    .permStateList = { infoManagerTestState }
};
} // namespace

class AccessToken {
public:
    AccessToken()
    {
        currentID_ = GetSelfTokenID();
        AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestInfoParms, infoManagerTestPolicyPrams);
        accessID_ = tokenIdEx.tokenIDEx;
        SetSelfTokenID(accessID_);
    }
    ~AccessToken()
    {
        AccessTokenKit::DeleteToken(accessID_);
        SetSelfTokenID(currentID_);
    }
private:
    uint64_t currentID_ = 0;
    uint64_t accessID_ = 0;
};

class InputManagerManualTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: StartBytrace_001
 * @tc.desc: Verify keyevent start bytrace
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerManualTest, StartBytrace_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetId(0);
    BytraceAdapter::StartBytrace(keyEvent);
    ASSERT_EQ(keyEvent->GetId(), 0);
}

/**
 * @tc.name: StartBytrace_002
 * @tc.desc: Verify keyevent start bytrace
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerManualTest, StartBytrace_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetId(0);
    keyEvent->SetKeyCode(0);
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::KEY_INTERCEPT_EVENT);
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::KEY_LAUNCH_EVENT);
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::KEY_SUBSCRIBE_EVENT);
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::KEY_DISPATCH_EVENT);
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::POINT_INTERCEPT_EVENT);
    ASSERT_EQ(keyEvent->GetKeyCode(), 0);
}

/**
 * @tc.name: StartBytrace_003
 * @tc.desc: Verify pointerEvent start bytrace
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerManualTest, StartBytrace_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP);
    ASSERT_EQ(pointerEvent->GetSourceType(), PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
}

/**
 * @tc.name: StartBytrace_004
 * @tc.desc: Verify pointerEvent start bytrace
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerManualTest, StartBytrace_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    BytraceAdapter::StartBytrace(BytraceAdapter::TRACE_START, BytraceAdapter::START_EVENT);
    BytraceAdapter::StartBytrace(BytraceAdapter::TRACE_START, BytraceAdapter::LAUNCH_EVENT);
    BytraceAdapter::StartBytrace(BytraceAdapter::TRACE_START, BytraceAdapter::STOP_EVENT);
    BytraceAdapter::StartBytrace(BytraceAdapter::TRACE_STOP, BytraceAdapter::START_EVENT);
    BytraceAdapter::StartBytrace(BytraceAdapter::TRACE_STOP, BytraceAdapter::LAUNCH_EVENT);
    BytraceAdapter::StartBytrace(BytraceAdapter::TRACE_STOP, BytraceAdapter::STOP_EVENT);
    ASSERT_EQ(pointerEvent->GetSourceType(), PointerEvent::SOURCE_TYPE_MOUSE);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
/**
 * @tc.name: HandlePointerEventFilter_002
 * @tc.desc: Max filter number check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerManualTest, HandleKeyEventFilter_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct KeyFilter : public IInputEventFilter {
        bool OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override
        {
            MMI_HILOGI("KeyFilter::OnInputEvent enter,pid:%{public}d", getpid());
            return false;
        }
        bool OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override { return false; }
    };
    auto filter = std::make_shared<KeyFilter>();
    uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
    const int32_t filterId = InputManager::GetInstance()->AddInputEventFilter(filter, 220, touchTags);
    ASSERT_NE(filterId, RET_ERR);
    auto retCode = InputManager::GetInstance()->RemoveInputEventFilter(filterId);
    ASSERT_EQ(retCode, RET_OK);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD
} // namespace MMI
} // namespace OHOS