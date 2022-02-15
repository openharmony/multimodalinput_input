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

#include "multimodal_event_handler.h"
#include <gtest/gtest.h>
#include "input_filter_manager.h"
#include "key_event_handler.h"
#include "mmi_client.h"
#include "mmi_token.h"
#include "proto.h"
#include "run_shell_util.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

namespace {
    constexpr int32_t HOS_KEY_BACK = 2;
    constexpr bool ACTION_DOWN = true;
    constexpr bool ACTION_UP = false;
    constexpr int32_t NANOSECOND_TO_MILLISECOND = 1000000;
    constexpr int32_t SEC_TO_NANOSEC = 1000000000;
    constexpr bool ISINTERCEPTED_TRUE = true;
    constexpr int32_t SLEEP = 3000;
    const std::regex REGEX_FIND_PID(" ");
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InjectDemo" };
}

template<class T>
StandEventPtr CreateEvent()
{
    return StandEventPtr(new T());
}

class AppKeyEventHandle : public KeyEventHandler {
public:
    AppKeyEventHandle() {}
    ~AppKeyEventHandle() {}

    virtual bool OnKey(const OHOS::KeyEvent& keyEvent) override
    {
        MMI_LOGT("AppKeyEventHandle::Onkey KeyCode:%{public}d", keyEvent.GetKeyCode());
        return true;
    }
};

class MultimodalEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    static int64_t GetNanoTime();
    static void RegisterStandardizedEventHandle();
    static void UnregisterStandardizedEventHandle();

    static sptr<MMIToken> remoteObject_;
    static int32_t windowId_;
    static std::map<std::string, StandEventPtr> handerMap_;
};
std::map<std::string, StandEventPtr> MultimodalEventHandlerTest::handerMap_;
int32_t MultimodalEventHandlerTest::windowId_ = 0;
sptr<MMIToken> MultimodalEventHandlerTest::remoteObject_ = nullptr;
void MultimodalEventHandlerTest::SetUpTestCase()
{
    windowId_ = getpid();
    MMI_LOGD("Inject windowId_:%{public}d", windowId_);
    std::string u8String = "InjecDemo\n";
    auto wsConvert = std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {};
    auto u16String = wsConvert.from_bytes(u8String);
    remoteObject_ = MMIToken::Create(u16String);
    remoteObject_->SetName("TestHapName");
    remoteObject_->SetBundlerName("TestBundlerName");
    RegisterStandardizedEventHandle();
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP));
}

void MultimodalEventHandlerTest::TearDownTestCase()
{
    UnregisterStandardizedEventHandle();
}

void MultimodalEventHandlerTest::RegisterStandardizedEventHandle()
{
    MMI_LOGI("MMIClientDemo RegisterStandardizedEventHandle enter.");
    using namespace OHOS::MMI;
    auto appKey = CreateEvent<AppKeyEventHandle>();
    handerMap_[std::string("AppKeyEventHandle")] = appKey;
    MMIEventHdl.RegisterStandardizedEventHandle(remoteObject_, windowId_, appKey);
}

void MultimodalEventHandlerTest::UnregisterStandardizedEventHandle()
{
    MMI_LOGI("MMIClientDemo::UnregisterStandardizedEventHandle enter.");
    for (auto it = handerMap_.begin(); it != handerMap_.end();) {
        MMI_LOGT("UnregisterStandardizedEventHandle:%{public}s", it->first.c_str());
        MMIEventHdl.UnregisterStandardizedEventHandle(remoteObject_, windowId_, it->second);
        handerMap_.erase(it++);
    }
}

int64_t MultimodalEventHandlerTest::GetNanoTime()
{
    timespec time = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &time);
    return static_cast<uint64_t>(time.tv_sec) * SEC_TO_NANOSEC + time.tv_nsec;
}


HWTEST_F(MultimodalEventHandlerTest, TEST_GetAbilityInfoVec, TestSize.Level1)
{
    MultimodalEventHandler multimodalEventHandler;
    multimodalEventHandler.GetAbilityInfoVec();
}

/**
 * @tc.name:MultimodalEventHandler_InjectKeyEvent_001
 * @tc.desc: test inject interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQL7  AR000GJNL7
 * @tc.author: yirenjie
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_InjectKeyEvent_001, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string command = "Inject keyCode = 2";
    std::vector<std::string> log;
    ASSERT_TRUE(runCommand.RunShellCommand(command, log) == RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP));
    OHOS::KeyEvent injectDownEvent;
    uint64_t downTime = static_cast<uint64_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_TRUE(response);

    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<uint64_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    EXPECT_TRUE(response);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP));
    std::vector<std::string> vLog;
    ASSERT_TRUE(runCommand.RunShellCommand(command, vLog) == RET_OK);
    ASSERT_TRUE(vLog.size() > 0);
    if (log.empty()) {
        EXPECT_TRUE(vLog.size() > log.size());
        EXPECT_TRUE(vLog.back().find(command) != vLog.back().npos);
    } else {
        EXPECT_TRUE(std::strcmp(vLog.back().c_str(), log.back().c_str()) != 0);
    }
}

/**
 * @tc.name:MultimodalEventHandler_InjectKeyEvent_003
 * @tc.desc: test inject interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQL7  AR000GJNL7
 * @tc.author: yirenjie
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_InjectKeyEvent_003, TestSize.Level1)
{
    OHOS::KeyEvent injectDownEvent;
    int32_t downTime = -1;
    injectDownEvent.Initialize(0, ACTION_DOWN, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_FALSE(response);
}

/**
 * @tc.name:MultimodalEventHandler_InjectKeyEvent_004
 * @tc.desc: test inject interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQL7  AR000GJNL7
 * @tc.author: yirenjie
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_InjectKeyEvent_004, TestSize.Level1)
{
    OHOS::KeyEvent injectDownEvent;
    int32_t downTime = 0;
    injectDownEvent.Initialize(0, ACTION_DOWN, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_TRUE(response);

    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    EXPECT_TRUE(response);
}

/**
 * @tc.name:MultimodalEventHandler_InjectKeyEvent_005
 * @tc.desc: test inject interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQL7  AR000GJNL7
 * @tc.author: yirenjie
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_InjectKeyEvent_005, TestSize.Level1)
{
    OHOS::KeyEvent injectDownEvent;
    int32_t downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    int32_t keyCode = -1;
    injectDownEvent.Initialize(0, ACTION_DOWN, keyCode, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_FALSE(response);
}

/**
 * @tc.name:MultimodalEventHandler_InjectKeyEvent_006
 * @tc.desc: test inject interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQL7  AR000GJNL7
 * @tc.author: yirenjie
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_InjectKeyEvent_006, TestSize.Level1)
{
    OHOS::KeyEvent injectDownEvent;
    int32_t downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    int32_t keyCode = 0;
    injectDownEvent.Initialize(0, ACTION_DOWN, keyCode, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_TRUE(response);

    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, keyCode, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    EXPECT_TRUE(response);
}

/**
 * @tc.name:MultimodalEventHandler_AddKeyBoardFilter_001
 * @tc.desc:verify the interface add a filter and success call the callback function
 * @tc.type: FUNC
 * @tc.require: SR000GGQL6  AR000GJNGU
 * @tc.author: mengxinhai
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_AddKeyBoardFilter_001, TestSize.Level1)
{
    std::string name = "KeyBoardFilter";
    InputFilterMgr.FilterKeyEvent(name, LOW_AUTHORITY, [](KeyBoardEvent event){
        EXPECT_TRUE(event.GetKeyCode() == HOS_KEY_BACK);
        MMI_LOGD("filter 1 receive keycode:%{public}d", event.GetKeyCode());
    });
    OHOS::KeyEvent injectDownEvent;
    uint64_t downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_TRUE(response);

    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    sleep(5);
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(1) == RET_OK);
    EXPECT_TRUE(response);
}

/**
 * @tc.name:MultimodalEventHandler_AddKeyBoardFilter_002
 * @tc.desc:Verify the same permissions to call the first filter added
 * @tc.type: FUNC
 * @tc.require: SR000GGQL6  AR000GJNGU
 * @tc.author: mengxinhai
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_AddKeyBoardFilter_002, TestSize.Level1)
{
    std::string name = "KeyBoardFilter";
    InputFilterMgr.FilterKeyEvent(name, LOW_AUTHORITY, [](KeyBoardEvent event){
        EXPECT_TRUE(event.GetKeyCode() == HOS_KEY_BACK);
        MMI_LOGD("filter 1 receive keycode:%{public}d", event.GetKeyCode());
    });
    InputFilterMgr.FilterKeyEvent(name, LOW_AUTHORITY, [](KeyBoardEvent event){
        EXPECT_TRUE(false);
        MMI_LOGD("filter 2 receive keycode:%{public}d", event.GetKeyCode());
    });
    OHOS::KeyEvent injectDownEvent;
    int32_t downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_TRUE(response);

    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    EXPECT_TRUE(response);
    sleep(5);
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(2) == RET_OK);
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(3) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_AddKeyBoardFilter_003
 * @tc.desc:Verify the highest authority for calling
 * @tc.type: FUNC
 * @tc.require: SR000GGQL6  AR000GJNGU
 * @tc.author: mengxinhai
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_AddKeyBoardFilter_003, TestSize.Level1)
{
    std::string name = "KeyBoardFilter";
    InputFilterMgr.FilterKeyEvent(name, LOW_AUTHORITY, [](KeyBoardEvent event){
        EXPECT_TRUE(false);
        MMI_LOGD("filter 1 receive keycode:%{public}d", event.GetKeyCode());
    });
    InputFilterMgr.FilterKeyEvent(name, MIDDLE_AUTHORITY, [](KeyBoardEvent event){
        EXPECT_TRUE(event.GetKeyCode() == HOS_KEY_BACK);
        MMI_LOGD("filter 2 receive keycode:%{public}d", event.GetKeyCode());
    });
    OHOS::KeyEvent injectDownEvent;
    int32_t downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_TRUE(response);

    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    EXPECT_TRUE(response);
    sleep(5);
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(4) == RET_OK);
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(5) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_RemoveKeyBoardFilter_001
 * @tc.desc:Verify whether the event is filtered after deleting the filter
 * @tc.type: FUNC
 * @tc.require: SR000GGQL6  AR000GJNGU
 * @tc.author: mengxinhai
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_RemoveKeyBoardFilter_001, TestSize.Level1)
{
    std::string name = "KeyBoardFilter";
    InputFilterMgr.FilterKeyEvent(name, LOW_AUTHORITY, [](KeyBoardEvent event){
        EXPECT_TRUE(false);
        MMI_LOGD("filter 1 receive keycode:%{public}d", event.GetKeyCode());
    });
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(6) == RET_OK);
    OHOS::KeyEvent injectDownEvent;
    int32_t downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_TRUE(response);

    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    EXPECT_TRUE(response);
    sleep(5);
}

/**
 * @tc.name:MultimodalEventHandler_RemoveKeyBoardFilter_002
 * @tc.desc:Verify the filter called after removing the highest authority
 * @tc.type: FUNC
 * @tc.require: SR000GGQL6  AR000GJNGU
 * @tc.author: mengxinhai
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_RemoveKeyBoardFilter_002, TestSize.Level1)
{
    std::string name = "KeyBoardFilter";
    InputFilterMgr.FilterKeyEvent(name, LOW_AUTHORITY, [](KeyBoardEvent event){
        EXPECT_TRUE(event.GetKeyCode() == HOS_KEY_BACK);
        MMI_LOGD("filter 1 receive keycode:%{public}d", event.GetKeyCode());
    });
    InputFilterMgr.FilterKeyEvent(name, MIDDLE_AUTHORITY, [](KeyBoardEvent event){
        EXPECT_TRUE(false);
        MMI_LOGD("filter 2 receive keycode:%{public}d", event.GetKeyCode());
    });
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(8) == RET_OK);
    sleep(5);
    OHOS::KeyEvent injectDownEvent;
    int32_t downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_TRUE(response);

    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    EXPECT_TRUE(response);
    sleep(5);
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(7) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_RemoveKeyBoardFilter_003
 * @tc.desc:Verify and remove the first filter added under the same permission
 * @tc.type: FUNC
 * @tc.require: SR000GGQL6  AR000GJNGU
 * @tc.author: mengxinhai
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_RemoveKeyBoardFilter_003, TestSize.Level1)
{
    std::string name = "KeyBoardFilter";
    InputFilterMgr.FilterKeyEvent(name, LOW_AUTHORITY, [](KeyBoardEvent event){
        EXPECT_TRUE(false);
        MMI_LOGD("filter 1 receive keycode:%{public}d", event.GetKeyCode());
    });
    InputFilterMgr.FilterKeyEvent(name, LOW_AUTHORITY, [](KeyBoardEvent event){
        EXPECT_TRUE(event.GetKeyCode() == HOS_KEY_BACK);
        MMI_LOGD("filter 2 receive keycode:%{public}d", event.GetKeyCode());
    });
    InputFilterMgr.FilterKeyEvent(name, LOW_AUTHORITY, [](KeyBoardEvent event){
        EXPECT_TRUE(false);
        MMI_LOGD("filter 3 receive keycode:%{public}d", event.GetKeyCode());
    });
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(9) == RET_OK);
    OHOS::KeyEvent injectDownEvent;
    int32_t downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_TRUE(response);

    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    EXPECT_TRUE(response);
    sleep(5);
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(10) == RET_OK);
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(11) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_filterAbnormal_001
 * @tc.desc:Verify Abnormal entry
 * @tc.type: FUNC
 * @tc.require: SR000GGQL6  AR000GJNGU
 * @tc.author: mengxinhai
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_filterAbnormal_001, TestSize.Level1)
{
    std::string name = "KeyBoardFilter";
    EXPECT_TRUE(InputFilterMgr.FilterKeyEvent(name, LOW_AUTHORITY, nullptr) == RET_ERR);
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(1) == RET_ERR);

    InputFilterMgr.FilterKeyEvent(name, LOW_AUTHORITY, [](KeyBoardEvent event){
        MMI_LOGD("filter 1 receive keycode:%{public}d", event.GetKeyCode());
    });
    InputFilterMgr.FilterKeyEvent(name, MIDDLE_AUTHORITY, [](KeyBoardEvent event){
        MMI_LOGD("filter 2 receive keycode:%{public}d", event.GetKeyCode());
    });
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(20) == RET_ERR);

    OHOS::KeyEvent injectDownEvent;
    int32_t downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectDownEvent.Initialize(0, ACTION_DOWN, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_TRUE(response);

    OHOS::KeyEvent injectUpEvent;
    downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    injectUpEvent.Initialize(0, ACTION_UP, HOS_KEY_BACK, downTime, 0, "", 0, 0, "", 0, false, 0,
        ISINTERCEPTED_TRUE);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    EXPECT_TRUE(response);
    sleep(5);
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(12) == RET_OK);
    EXPECT_TRUE(InputFilterMgr.UnFilterKeyEvent(13) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_AddPointerFilter_001
 * @tc.desc:verify the interface add a filter and success call the callback function
 * @tc.type: FUNC
 * @tc.require: SR000GGQL0  AR000GJN6R
 * @tc.author: wangyyuan
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_AddPointerFilter_001, TestSize.Level1)
{
    std::string name = "PointerFilter";
    InputFilterMgr.RegisterPointerEventInterceptor(name, LOW_AUTHORITY, [](MouseEvent event){
        MMI_LOGD("filter 1 receive pointercode:%{public}d", event.GetActionButton());
    });
    sleep(20);
    EXPECT_TRUE(InputFilterMgr.UnRegisterPointerEventInterceptor(14) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_AddPointerFilter_002
 * @tc.desc:Verify the same permissions to call the first filter added
 * @tc.type: FUNC
 * @tc.require: SR000GGQL0  AR000GJN6R
 * @tc.author: wangyuan
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_AddPointerFilter_002, TestSize.Level1)
{
    std::string name = "PointerFilter";
    InputFilterMgr.RegisterPointerEventInterceptor(name, LOW_AUTHORITY, [](MouseEvent event){
        MMI_LOGD("filter 1 receive pointercode:%{public}d", event.GetActionButton());
    });
    InputFilterMgr.RegisterPointerEventInterceptor(name, LOW_AUTHORITY, [](MouseEvent event){
        EXPECT_TRUE(false);
        MMI_LOGD("filter 2 receive pointercode:%{public}d", event.GetActionButton());
    });
    sleep(20);
    EXPECT_TRUE(InputFilterMgr.UnRegisterPointerEventInterceptor(15) == RET_OK);
    EXPECT_TRUE(InputFilterMgr.UnRegisterPointerEventInterceptor(16) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_AddPointerFilter_003
 * @tc.desc:Verify the highest authority for calling
 * @tc.type: FUNC
 * @tc.require: SR000GGQL0  AR000GJN6R
 * @tc.author: wangyuan
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_AddPointerFilter_003, TestSize.Level1)
{
    std::string name = "PointerFilter";
    InputFilterMgr.RegisterPointerEventInterceptor(name, LOW_AUTHORITY, [](MouseEvent event){
        EXPECT_TRUE(false);
        MMI_LOGD("filter 1 receive pointercode:%{public}d", event.GetActionButton());
    });
    InputFilterMgr.RegisterPointerEventInterceptor(name, MIDDLE_AUTHORITY, [](MouseEvent event){
        MMI_LOGD("filter 2 receive pointercode:%{public}d", event.GetActionButton());
    });
    sleep(20);
    EXPECT_TRUE(InputFilterMgr.UnRegisterPointerEventInterceptor(17) == RET_OK);
    EXPECT_TRUE(InputFilterMgr.UnRegisterPointerEventInterceptor(18) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_RemovePointerFilter_001
 * @tc.desc:Verify whether the event is filtered after deleting the filter
 * @tc.type: FUNC
 * @tc.require: SR000GGQL0  AR000GJN6R
 * @tc.author: wangyuan
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_RemovePointerFilter_001, TestSize.Level1)
{
    std::string name = "PointerFilter";
    InputFilterMgr.RegisterPointerEventInterceptor(name, LOW_AUTHORITY, [](MouseEvent event){
        EXPECT_TRUE(false);
        MMI_LOGD("filter 1 receive pointercode:%{public}d", event.GetActionButton());
    });
    EXPECT_TRUE(InputFilterMgr.UnRegisterPointerEventInterceptor(19) == RET_OK);
    sleep(20);
}

/**
 * @tc.name:MultimodalEventHandler_RemovePointerFilter_002
 * @tc.desc:Verify the filter called after removing the highest authority
 * @tc.type: FUNC
 * @tc.require: SR000GGQL0  AR000GJN6R
 * @tc.author: wangyuan
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_RemovePointerFilter_002, TestSize.Level1)
{
    std::string name = "PointerFilter";
    InputFilterMgr.RegisterPointerEventInterceptor(name, LOW_AUTHORITY, [](MouseEvent event){
        MMI_LOGD("filter 1 receive pointercode:%{public}d", event.GetActionButton());
    });
    InputFilterMgr.RegisterPointerEventInterceptor(name, MIDDLE_AUTHORITY, [](MouseEvent event){
        EXPECT_TRUE(false);
        MMI_LOGD("filter 2 receive pointercode:%{public}d", event.GetActionButton());
    });
    EXPECT_TRUE(InputFilterMgr.UnRegisterPointerEventInterceptor(21) == RET_OK);
    sleep(20);
    EXPECT_TRUE(InputFilterMgr.UnRegisterPointerEventInterceptor(20) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_RemovePointerFilter_003
 * @tc.desc:Verify and remove the first filter added under the same permission
 * @tc.type: FUNC
 * @tc.require: SR000GGQL0  AR000GJN6R
 * @tc.author: wangyuan
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_RemovePointerFilter_003, TestSize.Level1)
{
    std::string name = "PointerFilter";
    InputFilterMgr.RegisterPointerEventInterceptor(name, LOW_AUTHORITY, [](MouseEvent event){
        EXPECT_TRUE(false);
        MMI_LOGD("filter 1 receive pointercode:%{public}d", event.GetActionButton());
    });
    InputFilterMgr.RegisterPointerEventInterceptor(name, LOW_AUTHORITY, [](MouseEvent event){
        MMI_LOGD("filter 2 receive pointercode:%{public}d", event.GetActionButton());
    });
    InputFilterMgr.RegisterPointerEventInterceptor(name, LOW_AUTHORITY, [](MouseEvent event){
        EXPECT_TRUE(false);
        MMI_LOGD("filter 3 receive pointercode:%{public}d", event.GetActionButton());
    });
    EXPECT_TRUE(InputFilterMgr.UnRegisterPointerEventInterceptor(22) == RET_OK);
    sleep(20);
    EXPECT_TRUE(InputFilterMgr.UnRegisterPointerEventInterceptor(23) == RET_OK);
    EXPECT_TRUE(InputFilterMgr.UnRegisterPointerEventInterceptor(24) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_PointerInterceptorAbnormal_001
 * @tc.desc:Verify Abnormal entry
 * @tc.type: FUNC
 * @tc.require: SR000GGQL0  AR000GJN6R
 * @tc.author: wangyuan
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_PointerInterceptorAbnormal_001, TestSize.Level1)
{
    std::string name = "PointerFilter";
    EXPECT_TRUE(InputFilterMgr.RegisterPointerEventInterceptor(name, LOW_AUTHORITY, nullptr) == RET_ERR);

    InputFilterMgr.RegisterPointerEventInterceptor(name, LOW_AUTHORITY, [](MouseEvent event){
        MMI_LOGD("filter 1 receive pointercode:%{public}d", event.GetActionButton());
    });
    InputFilterMgr.RegisterPointerEventInterceptor(name, MIDDLE_AUTHORITY, [](MouseEvent event){
        MMI_LOGD("filter 2 receive pointercode:%{public}d", event.GetActionButton());
    });
    EXPECT_TRUE(InputFilterMgr.UnRegisterPointerEventInterceptor(40) == RET_ERR);
    sleep(20);
    EXPECT_TRUE(InputFilterMgr.UnRegisterPointerEventInterceptor(25) == RET_OK);
    EXPECT_TRUE(InputFilterMgr.UnRegisterPointerEventInterceptor(26) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_AddTouchFilter_001
 * @tc.desc:verify the interface add a filter and success call the callback function
 * @tc.type: FUNC
 * @tc.require: SR000GGQL9  AR000GJO00
 * @tc.author: libangwu
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_AddTouchFilter_001, TestSize.Level1)
{
    std::string name1 = "TouchFilter";
    bool isFilter = false;
    int32_t filterId = InputFilterMgr.FilterTouchEvent(name1, LOW_AUTHORITY, [&isFilter](TouchEvent event){
        isFilter = true;
        MMI_LOGD("filter receive action:%{public}d", event.GetAction());
    });
    sleep(5);
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(filterId) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_AddTouchFilter_002
 * @tc.desc:Verify the same permissions to call the first filter added
 * @tc.type: FUNC
 * @tc.require: SR000GGQL9  AR000GJO00
 * @tc.author: libangwu
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_AddTouchFilter_002, TestSize.Level1)
{
    std::string name1 = "TouchFilter1";
    bool isFilter = false;
    int32_t filterId1 = InputFilterMgr.FilterTouchEvent(name1, LOW_AUTHORITY, [&isFilter](TouchEvent event){
        isFilter = true;
        MMI_LOGD("filter 1 receive action:%{public}d", event.GetAction());
    });
    std::string name2 = "TouchFilter2";
    int32_t filterId2 = InputFilterMgr.FilterTouchEvent(name2, LOW_AUTHORITY, [&isFilter](TouchEvent event){
        isFilter = false;
        MMI_LOGD("filter 2 receive action:%{public}d", event.GetAction());
    });
    sleep(5);
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(filterId1) == RET_OK);
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(filterId2) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_AddTouchFilter_003
 * @tc.desc:Verify the highest authority for calling
 * @tc.type: FUNC
 * @tc.require: SR000GGQL9  AR000GJO00
 * @tc.author: libangwu
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_AddTouchFilter_003, TestSize.Level1)
{
    std::string name1 = "TouchFilter1";
    bool isFilter = false;
    int32_t filterId1 = InputFilterMgr.FilterTouchEvent(name1, LOW_AUTHORITY, [&isFilter](TouchEvent event){
        isFilter = false;
        MMI_LOGD("filter 1 receive action:%{public}d", event.GetAction());
    });
    std::string name2 = "TouchFilter2";
    int32_t filterId2 = InputFilterMgr.FilterTouchEvent(name2, MIDDLE_AUTHORITY, [&isFilter](TouchEvent event){
        isFilter = true;
        MMI_LOGD("filter 2 receive action:%{public}d", event.GetAction());
    });
    sleep(5);
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(filterId1) == RET_OK);
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(filterId2) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_RemoveTouchFilter_001
 * @tc.desc:Verify the highest authority for calling
 * @tc.type: FUNC
 * @tc.require: SR000GGQL9  AR000GJO00
 * @tc.author: libangwu
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_RemoveTouchFilter_001, TestSize.Level1)
{
    std::string name = "TouchFilter";
    int32_t filterId = InputFilterMgr.FilterTouchEvent(name, LOW_AUTHORITY, [](TouchEvent event){
        EXPECT_TRUE(false);
        MMI_LOGD("filter 1 receive action:%{public}d", event.GetAction());
    });
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(filterId) == RET_OK);
    sleep(5);
}

/**
 * @tc.name:MultimodalEventHandler_RemoveTouchFilter_002
 * @tc.desc:Verify the filter called after removing the highest authority
 * @tc.type: FUNC
 * @tc.require: SR000GGQL9  AR000GJO00
 * @tc.author: libangwu
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_RemoveTouchFilter_002, TestSize.Level1)
{
    std::string name1 = "TouchFilter1";
    bool isFilter = false;
    int32_t filterId1 = InputFilterMgr.FilterTouchEvent(name1, LOW_AUTHORITY, [&isFilter](TouchEvent event){
        isFilter = true;
        MMI_LOGD("filter 1 receive action:%{public}d", event.GetAction());
    });
    std::string name2 = "TouchFilter2";
    int32_t filterId2 = InputFilterMgr.FilterTouchEvent(name2, MIDDLE_AUTHORITY, [&isFilter](TouchEvent event){
        isFilter = false;
        MMI_LOGD("filter 2 receive action:%{public}d", event.GetAction());
    });
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(filterId2) == RET_OK);
    sleep(5);
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(filterId1) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_RemoveTouchFilter_003
 * @tc.desc:Verify and remove the first filter added under the same permission
 * @tc.type: FUNC
 * @tc.require: SR000GGQL9  AR000GJO00
 * @tc.author: libangwu
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_RemoveTouchFilter_003, TestSize.Level1)
{
    std::string name1 = "TouchFilter1";
    bool isFilter = false;
    int32_t filterId1 = InputFilterMgr.FilterTouchEvent(name1, LOW_AUTHORITY, [&isFilter](TouchEvent event){
        isFilter = false;
        MMI_LOGD("filter 1 receive action:%{public}d", event.GetAction());
    });
    std::string name2 = "TouchFilter2";
    int32_t filterId2 = InputFilterMgr.FilterTouchEvent(name2, LOW_AUTHORITY, [&isFilter](TouchEvent event){
        isFilter = true;
        MMI_LOGD("filter 2 receive action:%{public}d", event.GetAction());
    });
    std::string name3 = "TouchFilter3";
    int32_t filterId3 = InputFilterMgr.FilterTouchEvent(name3, LOW_AUTHORITY, [&isFilter](TouchEvent event){
        isFilter = false;
        MMI_LOGD("filter 3 receive action:%{public}d", event.GetAction());
    });
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(filterId1) == RET_OK);
    sleep(5);
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(filterId2) == RET_OK);
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(filterId3) == RET_OK);
}

/**
 * @tc.name:MultimodalEventHandler_TouchFilterAbnormal_001
 * @tc.desc:Verify Abnormal entry
 * @tc.type: FUNC
 * @tc.require: SR000GGQL9  AR000GJO00
 * @tc.author: libangwu
 */
HWTEST_F(MultimodalEventHandlerTest, MultimodalEventHandler_TouchFilterAbnormal_001, TestSize.Level1)
{
    std::string name1 = "TouchFilter";
    bool isFilter = false;
    EXPECT_TRUE(InputFilterMgr.FilterTouchEvent(name1, LOW_AUTHORITY, nullptr) == RET_ERR);
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(1) == RET_ERR);

    std::string name2 = "TouchFilter2";
    int32_t filterId2 = InputFilterMgr.FilterTouchEvent(name2, LOW_AUTHORITY, [&isFilter](TouchEvent event){
        isFilter = false;
        MMI_LOGD("filter 2 receive action:%{public}d", event.GetAction());
    });
    std::string name3 = "TouchFilter3";
    int32_t filterId3 = InputFilterMgr.FilterTouchEvent(name3, MIDDLE_AUTHORITY, [&isFilter](TouchEvent event){
        isFilter = true;
        MMI_LOGD("filter 3 receive action:%{public}d", event.GetAction());
    });
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(filterId3+10) == RET_ERR);
    sleep(5);
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(filterId2) == RET_OK);
    EXPECT_TRUE(InputFilterMgr.UnFilterTouchEvent(filterId3) == RET_OK);
}
}