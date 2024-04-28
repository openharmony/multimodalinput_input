/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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
#include <chrono>
#include <fstream>
#include <filesystem>

#include "key_command_handler.h"
#include "input_event_handler.h"
#include "mmi_log.h"
#include "timer_manager.h"

// Ability manager stub header
#include "ability_manager_client.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TwoFingerLongTouchTest"

namespace OHOS {
namespace MMI {

namespace {
using namespace testing::ext;
constexpr std::chrono::milliseconds WAIT_TIME_MS(50);

const std::string TEST_DIR = "/data/test";
const std::string TEST_JSON = "/data/test/test.json";

const std::string BINDLE_NAME = "bindle_name";
const std::string ABILITY_NAME = "test_ability";
const std::string ACTION = "some_action";
const std::string TYPE = "some_type";
const std::string DEVICE_ID = "device_id";
const std::string URI = "uri";
const std::string ENTITY = "entity";
const std::string KEY = "key";
const std::string VALUE = "value";

constexpr unsigned ENTITY_NUM = 2;
constexpr unsigned PARAMETERS_NUM = 2;
constexpr int32_t DEFX = 50;
constexpr int32_t DEFY = 50;
constexpr int32_t LESS_THEN_THRESHOLD = 10;
constexpr int32_t GREATER_THEN_THRESHOLD = 20;
} // namespace

class TestCommandHandler final : public IInputEventHandler {
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    virtual void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) {}
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    virtual void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) {}
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    virtual void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) {}
#endif // OHOS_BUILD_ENABLE_TOUCH
};

const std::string ABILITY_CONFIG_JSON = \
"{\n" \
"    \"Shortkeys\": [\n" \
"    ],\n" \
"    \"Sequences\" : [\n" \
"    ],\n" \
"    \"TwoFingerGesture\" : {\n" \
"        \"abilityStartDelay\" : 20,\n" \
"        \"ability\" : {\n" \
"            \"bundleName\" : \"bindle_name\",\n" \
"            \"abilityName\" : \"test_ability\",\n" \
"            \"action\" : \"some_action\",\n" \
"            \"type\" : \"some_type\",\n" \
"            \"deviceId\" : \"device_id\",\n" \
"            \"uri\" : \"uri\",\n" \
"            \"entities\" : [\n" \
"                \"entity1\",\n" \
"                \"entity2\"\n" \
"            ],\n" \
"            \"params\" : [\n" \
"                {\n" \
"                    \"key\" : \"key1\",\n" \
"                    \"value\" : \"value1\"\n" \
"                },\n" \
"                {\n" \
"                    \"key\" : \"key2\",\n" \
"                    \"value\" : \"value2\"\n" \
"                }\n" \
"            ]\n" \
"        }\n" \
"    }\n" \
"}\n";

class TwoFingerLongTouchTest : public testing::Test {
public:
    std::shared_ptr<TestCommandHandler> eventTestCommandHandler_ { nullptr };
    std::shared_ptr<KeyCommandHandler> eventKeyCommandHandler_ { nullptr };
    void SetupKeyCommandHandler();
    std::shared_ptr<PointerEvent> SetupPointerEvent(int32_t action, int32_t pointerId, int32_t finger_num,
                                                    int32_t dispX = DEFX, int32_t dispY = DEFY);
    bool CreateTestJson(const std::string &contentJson);
    void Delay(std::chrono::milliseconds delayMs);
    static void AbilityCallback(const AAFwk::Want &want, ErrCode err);

    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    TwoFingerLongTouchTest()
    {
        SetupKeyCommandHandler();
        CreateTestJson(ABILITY_CONFIG_JSON);
    }

    ~TwoFingerLongTouchTest() {}

    static inline bool abilityStarted_;
    static inline ErrCode err_;
};

void TwoFingerLongTouchTest::SetupKeyCommandHandler()
{
    eventTestCommandHandler_ = std::make_shared<TestCommandHandler>();
    eventKeyCommandHandler_ = std::make_shared<KeyCommandHandler>();
    eventKeyCommandHandler_->SetNext(eventTestCommandHandler_);

    AAFwk::AbilityManagerClient::GetInstance()->SetCallback(TwoFingerLongTouchTest::AbilityCallback);

    abilityStarted_ = false;
    err_ = ERR_OK;
}

std::shared_ptr<PointerEvent> TwoFingerLongTouchTest::SetupPointerEvent(int32_t action,
                                                                        int32_t pointerId,
                                                                        int32_t finger_num,
                                                                        int32_t dispX, int32_t dispY)
{
    constexpr int32_t twoFinger = 2;
    constexpr int32_t coordOffset = 25;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(action);

    pointerEvent->SetPointerId(pointerId);

    PointerEvent::PointerItem item1;
    item1.SetPointerId(0);
    item1.SetDisplayX(dispX);
    item1.SetDisplayY(dispY);
    pointerEvent->AddPointerItem(item1);

    if (finger_num == twoFinger) {
        PointerEvent::PointerItem item2;
        item2.SetPointerId(1);
        item2.SetDisplayX(dispX + coordOffset);
        item2.SetDisplayY(dispY + coordOffset);
        pointerEvent->AddPointerItem(item2);
    }

    return pointerEvent;
}

bool TwoFingerLongTouchTest::CreateTestJson(const std::string &contentJson)
{
    // Check test directory presence and create it if required
    if (!std::filesystem::exists(TEST_DIR)) {
        if (!std::filesystem::create_directory(TEST_DIR)) {
            return false;
        }
    }

    std::fstream file;
    file.open(TEST_JSON, std::ios::out | std::ios::trunc);

    if (!file.is_open()) {
        return false;
    }
    file << contentJson;

    file.close();

    return true;
}

void TwoFingerLongTouchTest::Delay(std::chrono::milliseconds delayMs)
{
    std::this_thread::sleep_for(delayMs);
}

void TwoFingerLongTouchTest::AbilityCallback(const AAFwk::Want &want, ErrCode err)
{
    EXPECT_EQ(want.bundleName_, BINDLE_NAME);
    EXPECT_EQ(want.abilityName_, ABILITY_NAME);
    EXPECT_EQ(want.action_, ACTION);
    EXPECT_EQ(want.type_, TYPE);
    EXPECT_EQ(want.deviceId_, DEVICE_ID);
    EXPECT_EQ(want.uri_, URI);

    EXPECT_EQ(want.entities_.size(), ENTITY_NUM);
    if (want.entities_.size() == ENTITY_NUM) {
        for (unsigned i = 0; i < want.entities_.size(); ++i) {
            std::string entity = want.entities_[i];
            std::string expected = ENTITY.data() + std::to_string(i + 1);
            EXPECT_EQ(entity, expected);
        }
    }

    EXPECT_EQ(want.params_.size(), PARAMETERS_NUM);
    if (want.params_.size() == PARAMETERS_NUM) {
        for (unsigned i = 0; i < want.params_.size(); ++i) {
            std::string key = KEY.data() + std::to_string(i + 1);
            std::string value = VALUE.data() + std::to_string(i + 1);
            auto item = want.params_.find(key);
            EXPECT_NE(item, want.params_.end());

            if (item != want.params_.end()) {
                EXPECT_EQ(item->first, key);
                EXPECT_EQ(item->second, value);
            }
        }
    }

    TwoFingerLongTouchTest::abilityStarted_ = true;
    TwoFingerLongTouchTest::err_ = err;
}

/**
 * @tc.name: TwoFingerLongTouchTest_001
 * @tc.desc: Test two finger long touch pointer event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerLongTouchTest, TwoFingerLongTouchTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(eventTestCommandHandler_, nullptr);
    ASSERT_NE(eventKeyCommandHandler_, nullptr);
    abilityStarted_ = false;

    auto pointerEvent1 = SetupPointerEvent(PointerEvent::POINTER_ACTION_DOWN, 0, 2);
    ASSERT_NE(pointerEvent1, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent1);

    Delay(WAIT_TIME_MS);
    TimerMgr->ProcessTimers();

    auto pointerEvent2 = SetupPointerEvent(PointerEvent::POINTER_ACTION_UP, 0, 2);
    ASSERT_NE(pointerEvent2, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent2);

    EXPECT_TRUE(abilityStarted_);
    EXPECT_EQ(ERR_OK, err_);
}

/**
 * @tc.name: TwoFingerLongTouchTest_002
 * @tc.desc: Test one finger long touch pointer event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerLongTouchTest, TwoFingerLongTouchTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(eventTestCommandHandler_, nullptr);
    ASSERT_NE(eventKeyCommandHandler_, nullptr);
    abilityStarted_ = false;

    auto pointerEvent1 = SetupPointerEvent(PointerEvent::POINTER_ACTION_DOWN, 0, 1);
    ASSERT_NE(pointerEvent1, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent1);

    Delay(WAIT_TIME_MS);
    TimerMgr->ProcessTimers();

    auto pointerEvent2 = SetupPointerEvent(PointerEvent::POINTER_ACTION_UP, 0, 1);
    ASSERT_NE(pointerEvent2, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent2);

    EXPECT_FALSE(abilityStarted_);
}

/**
 * @tc.name: TwoFingerLongTouchTest_003
 * @tc.desc: Test two finger long touch gesture interruption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerLongTouchTest, TwoFingerLongTouchTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(eventTestCommandHandler_, nullptr);
    ASSERT_NE(eventKeyCommandHandler_, nullptr);
    abilityStarted_ = false;

    auto pointerEvent1 = SetupPointerEvent(PointerEvent::POINTER_ACTION_DOWN, 0, 2);
    ASSERT_NE(pointerEvent1, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent1);

    auto pointerEvent2 = SetupPointerEvent(PointerEvent::POINTER_ACTION_UP, 0, 2);
    ASSERT_NE(pointerEvent2, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent2);

    Delay(WAIT_TIME_MS);
    TimerMgr->ProcessTimers();

    EXPECT_FALSE(abilityStarted_);
}

/**
 * @tc.name: TwoFingerLongTouchTest_004
 * @tc.desc: Test two finger long touch gesture moving inside threshold
 *           (And one more unregistered event outside of threshold)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerLongTouchTest, TwoFingerLongTouchTest_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(eventTestCommandHandler_, nullptr);
    ASSERT_NE(eventKeyCommandHandler_, nullptr);
    abilityStarted_ = false;

    auto pointerEvent1 = SetupPointerEvent(PointerEvent::POINTER_ACTION_DOWN, 0, 1);
    ASSERT_NE(pointerEvent1, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent1);

    auto pointerEvent2 = SetupPointerEvent(PointerEvent::POINTER_ACTION_DOWN, 0, 2);
    ASSERT_NE(pointerEvent2, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent2);

    auto pointerEvent3 = SetupPointerEvent(PointerEvent::POINTER_ACTION_MOVE, 0, 2,
                                           DEFX + LESS_THEN_THRESHOLD, DEFY + LESS_THEN_THRESHOLD);
    ASSERT_NE(pointerEvent3, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent3);

    auto pointerEvent4 = SetupPointerEvent(PointerEvent::POINTER_ACTION_MOVE, 2, 1,
                                           DEFX + GREATER_THEN_THRESHOLD, DEFY + GREATER_THEN_THRESHOLD);
    ASSERT_NE(pointerEvent4, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent4);

    Delay(WAIT_TIME_MS);
    TimerMgr->ProcessTimers();

    EXPECT_TRUE(abilityStarted_);
    EXPECT_EQ(ERR_OK, err_);
}

/**
 * @tc.name: TwoFingerLongTouchTest_005
 * @tc.desc: Test two finger long touch gesture moving outside threshold
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerLongTouchTest, TwoFingerLongTouchTest_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(eventTestCommandHandler_, nullptr);
    ASSERT_NE(eventKeyCommandHandler_, nullptr);
    abilityStarted_ = false;

    auto pointerEvent1 = SetupPointerEvent(PointerEvent::POINTER_ACTION_DOWN, 0, 1);
    ASSERT_NE(pointerEvent1, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent1);

    auto pointerEvent2 = SetupPointerEvent(PointerEvent::POINTER_ACTION_DOWN, 0, 2);
    ASSERT_NE(pointerEvent2, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent2);

    auto pointerEvent3 = SetupPointerEvent(PointerEvent::POINTER_ACTION_MOVE, 0, 2,
                                           DEFX + GREATER_THEN_THRESHOLD, DEFY + GREATER_THEN_THRESHOLD);
    ASSERT_NE(pointerEvent3, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent3);

    Delay(WAIT_TIME_MS);
    TimerMgr->ProcessTimers();

    EXPECT_FALSE(abilityStarted_);
}

/**
 * @tc.name: TwoFingerLongTouchTest_006
 * @tc.desc: Test to return error while ability is launching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerLongTouchTest, TwoFingerLongTouchTest_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(eventTestCommandHandler_, nullptr);
    ASSERT_NE(eventKeyCommandHandler_, nullptr);
    abilityStarted_ = false;

    AAFwk::AbilityManagerClient::GetInstance()->SetErrCode(ERR_INVALID_OPERATION);

    auto pointerEvent1 = SetupPointerEvent(PointerEvent::POINTER_ACTION_DOWN, 0, 2);
    ASSERT_NE(pointerEvent1, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent1);

    Delay(WAIT_TIME_MS);
    TimerMgr->ProcessTimers();

    auto pointerEvent2 = SetupPointerEvent(PointerEvent::POINTER_ACTION_UP, 0, 2);
    ASSERT_NE(pointerEvent2, nullptr);
    eventKeyCommandHandler_->HandleTouchEvent(pointerEvent2);

    AAFwk::AbilityManagerClient::GetInstance()->SetErrCode(ERR_OK);

    EXPECT_TRUE(abilityStarted_);
    EXPECT_EQ(ERR_INVALID_OPERATION, err_);
}

const std::string TEST_JSON_1 = "";
const std::string TEST_JSON_2 =
    "{ \"TwoFingerGesture\" : [] }\n";
const std::string TEST_JSON_3 =
    "{ \"TwoFingerGesture\" : {} }\n";
const std::string TEST_JSON_4 =
    "{ \"TwoFingerGesture\" : {\"abilityStartDelay\" : 200} }\n";
const std::string TEST_JSON_5 =
    "{ \"TwoFingerGesture\" : {\"abilityStartDelay\" : -1} }\n";
const std::string TEST_JSON_6 =
    "{ \"TwoFingerGesture\" : {\"abilityStartDelay\" : \"abc\"} }\n";
const std::string TEST_JSON_7 =
    "{ \"TwoFingerGesture\" : {\"abilityStartDelay\" : 200, \"ability\" : []} }\n";
const std::string TEST_JSON_8 =
    "{ \"TwoFingerGesture\" : {\"abilityStartDelay\" : 200, \"ability\" : {\"bundleName\"}} }\n";
const std::string TEST_JSON_9 =
    "{ \"TwoFingerGesture\" : {\"abilityStartDelay\" : 200, \"ability\" : {\"entities\" : {}}} }\n";
const std::string TEST_JSON_10 =
    "{ \"TwoFingerGesture\" : {\"abilityStartDelay\" : 200, \"ability\" : {\"entities\" : [123]}} }\n";
const std::string TEST_JSON_11 =
    "{ \"TwoFingerGesture\" : {\"abilityStartDelay\" : 200, \"ability\" : {\"params\" : {}}} }\n";
const std::string TEST_JSON_12 =
    "{ \"TwoFingerGesture\" : {\"abilityStartDelay\" : 200, \"ability\" : {\"params\" : [[]]}} }\n";
const std::string TEST_JSON_13 =
    "{ \"TwoFingerGesture\" : {\"abilityStartDelay\" : 200, \"ability\" : {\"params\" : [{}]}} }\n";
const std::string TEST_JSON_14 =
    "{ \"TwoFingerGesture\" : {\"abilityStartDelay\" : 200, \"ability\" : {\"params\" : [{\"key\" : \"key1\"}]}} }\n";
const std::string TEST_JSON_15 =
    "{ \"TwoFingerGesture\" : {\"abilityStartDelay\" : 200, \"ability\" : {}} }\n";

/**
 * @tc.name: TwoFingerLongTouchTest_007
 * @tc.desc: Test JSON parsing error branches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerLongTouchTest, TwoFingerLongTouchTest_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(eventTestCommandHandler_, nullptr);
    ASSERT_NE(eventKeyCommandHandler_, nullptr);
    abilityStarted_ = false;

    ASSERT_TRUE(CreateTestJson(TEST_JSON_1));
    ASSERT_FALSE(eventKeyCommandHandler_->ParseJson(TEST_JSON));

    ASSERT_TRUE(CreateTestJson(TEST_JSON_2));
    ASSERT_FALSE(eventKeyCommandHandler_->ParseJson(TEST_JSON));

    ASSERT_TRUE(CreateTestJson(TEST_JSON_3));
    ASSERT_FALSE(eventKeyCommandHandler_->ParseJson(TEST_JSON));

    ASSERT_TRUE(CreateTestJson(TEST_JSON_4));
    ASSERT_FALSE(eventKeyCommandHandler_->ParseJson(TEST_JSON));

    ASSERT_TRUE(CreateTestJson(TEST_JSON_5));
    ASSERT_FALSE(eventKeyCommandHandler_->ParseJson(TEST_JSON));

    ASSERT_TRUE(CreateTestJson(TEST_JSON_6));
    ASSERT_FALSE(eventKeyCommandHandler_->ParseJson(TEST_JSON));

    ASSERT_TRUE(CreateTestJson(TEST_JSON_7));
    ASSERT_FALSE(eventKeyCommandHandler_->ParseJson(TEST_JSON));

    ASSERT_TRUE(CreateTestJson(TEST_JSON_8));
    ASSERT_FALSE(eventKeyCommandHandler_->ParseJson(TEST_JSON));

    ASSERT_TRUE(CreateTestJson(TEST_JSON_9));
    ASSERT_FALSE(eventKeyCommandHandler_->ParseJson(TEST_JSON));

    ASSERT_TRUE(CreateTestJson(TEST_JSON_10));
    ASSERT_FALSE(eventKeyCommandHandler_->ParseJson(TEST_JSON));

    ASSERT_TRUE(CreateTestJson(TEST_JSON_11));
    ASSERT_FALSE(eventKeyCommandHandler_->ParseJson(TEST_JSON));

    ASSERT_TRUE(CreateTestJson(TEST_JSON_12));
    ASSERT_FALSE(eventKeyCommandHandler_->ParseJson(TEST_JSON));

    ASSERT_TRUE(CreateTestJson(TEST_JSON_13));
    ASSERT_FALSE(eventKeyCommandHandler_->ParseJson(TEST_JSON));

    ASSERT_TRUE(CreateTestJson(TEST_JSON_14));
    ASSERT_FALSE(eventKeyCommandHandler_->ParseJson(TEST_JSON));

    ASSERT_TRUE(CreateTestJson(TEST_JSON_15));
    ASSERT_TRUE(eventKeyCommandHandler_->ParseJson(TEST_JSON));
}
} // namespace MMI
} // namespace OHOS
