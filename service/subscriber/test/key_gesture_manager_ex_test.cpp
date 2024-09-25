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

#include <fstream>
#include <gtest/gtest.h>

#include "key_gesture_manager.h"

#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyGestureManagerEXTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
} // namespace

class KeyGestureManagerEXTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class MyKeyGesture : public KeyGestureManager::KeyGesture {
public:
    MyKeyGesture() = default;
    ~MyKeyGesture() override = default;

    bool IsWorking() override
    {
        return true;
    }

    bool ShouldIntercept(std::shared_ptr<KeyOption> keyOption) const override
    {
        return true;
    }

    bool Intercept(std::shared_ptr<KeyEvent> keyEvent) override
    {
        return true;
    }

    void Dump(std::ostringstream &output) const override
    {
        output << "MyKeyGesture";
    }
};


void Function(std::shared_ptr<KeyEvent>) {}

/**
 * @tc.name: KeyGestureManagerEXTest_ResetTimer
 * @tc.desc: Test the funcation ResetTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerEXTest, KeyGestureManagerEXTest_ResetTimer, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler keyGestureMgr(1, 10, 500, myCallback);
    keyGestureMgr.timerId_ = 10;
    EXPECT_NO_FATAL_FAILURE(keyGestureMgr.ResetTimer());
    keyGestureMgr.timerId_ = -1;
    EXPECT_NO_FATAL_FAILURE(keyGestureMgr.ResetTimer());
}

/**
 * @tc.name: KeyGestureManagerEXTest_Run
 * @tc.desc: Test the funcation Run
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerEXTest, KeyGestureManagerEXTest_Run, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler keyGestureMgr(1, 10, 500, myCallback);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyGestureMgr.callback_ = Function;
    EXPECT_NO_FATAL_FAILURE(keyGestureMgr.Run(keyEvent));
    keyGestureMgr.callback_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(keyGestureMgr.Run(keyEvent));
}

/**
 * @tc.name: KeyGestureManagerEXTest_RunPending
 * @tc.desc: Test the funcation RunPending
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerEXTest, KeyGestureManagerEXTest_RunPending, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler keyGestureMgr(1, 10, 500, myCallback);
    keyGestureMgr.keyEvent_ = KeyEvent::Create();
    ASSERT_NE(keyGestureMgr.keyEvent_, nullptr);
    EXPECT_NO_FATAL_FAILURE(keyGestureMgr.RunPending());
    keyGestureMgr.keyEvent_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(keyGestureMgr.RunPending());
}

/**
 * @tc.name: KeyGestureManagerEXTest_RemoveHandler
 * @tc.desc: Test the funcation RemoveHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerEXTest, KeyGestureManagerEXTest_RemoveHandler, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler handler(100, 200, 500, myCallback);
    myKeyGesture->handlers_.push_back(handler);
    int32_t id = 1000;
    EXPECT_FALSE(myKeyGesture->RemoveHandler(id));
    id = 100;
    EXPECT_TRUE(myKeyGesture->RemoveHandler(id));
}

/**
 * @tc.name: KeyGestureManagerEXTest_RunHandler
 * @tc.desc: Test the funcation RunHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerEXTest, KeyGestureManagerEXTest_RunHandler, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler handler(100, 200, 500, myCallback);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t handlerId = 1000;
    myKeyGesture->handlers_.push_back(handler);
    EXPECT_NO_FATAL_FAILURE(myKeyGesture->RunHandler(handlerId, keyEvent));
    handlerId = 100;
    EXPECT_NO_FATAL_FAILURE(myKeyGesture->RunHandler(handlerId, keyEvent));
}

/**
 * @tc.name: KeyGestureManagerEXTest_ShowHandlers
 * @tc.desc: Test the funcation ShowHandlers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerEXTest, KeyGestureManagerEXTest_ShowHandlers, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler handler1(100, 1000, 500, myCallback);
    KeyGestureManager::Handler handler2(200, 2000, 500, myCallback);
    KeyGestureManager::Handler handler3(300, 3000, 500, myCallback);
    KeyGestureManager::Handler handler4(400, 4000, 500, myCallback);
    KeyGestureManager::Handler handler5(500, 5000, 500, myCallback);
    KeyGestureManager::Handler handler6(600, 6000, 500, myCallback);
    myKeyGesture->handlers_.push_back(handler1);
    myKeyGesture->handlers_.push_back(handler2);
    myKeyGesture->handlers_.push_back(handler3);
    myKeyGesture->handlers_.push_back(handler4);
    myKeyGesture->handlers_.push_back(handler5);
    myKeyGesture->handlers_.push_back(handler6);

    std::string prefix = "prefix";
    std::set<int32_t> foregroundPids = { 100, 200 };
    EXPECT_NO_FATAL_FAILURE(myKeyGesture->ShowHandlers(prefix, foregroundPids));
}
} // namespace MMI
} // namespace OHOS
