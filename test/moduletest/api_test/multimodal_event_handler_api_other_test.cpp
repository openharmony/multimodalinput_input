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

#include "multimodal_event_handler.h"
#include <codecvt>
#include <gtest/gtest.h>
#include "error_multimodal.h"
#include "key_event_handler.h"
#include "log.h"
#include "media_event_handler.h"
#include "mmi_client.h"
#include "mmi_token.h"
#include "proto.h"
#include "touch_event_handler.h"
#include "util_ex.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

class MultimodalEventHandlerApiOtherTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class MMIClientDemo {
public:
    bool isTestCase_ = true;
};

class AppKeyEventHandle : public KeyEventHandler {
public:
    AppKeyEventHandle()
    {
        type_ = EnumAdd(MmiMessageId::KEY_EVENT_BEGIN, 1);
    }
    ~AppKeyEventHandle() {}
    virtual bool OnKey(const OHOS::KeyEvent& keylEvent) override
    {
        return true;
    }
};

class AppTouchEventHandle : public TouchEventHandler {
public:
    AppTouchEventHandle()
    {
        type_ = EnumAdd(MmiMessageId::TOUCH_EVENT_BEGIN, 1);
    }
    ~AppTouchEventHandle() {}
    virtual bool OnTouch(const TouchEvent& touchEvent) override
    {
        return true;
    }
};

class AppMediaEventHandle : public MediaEventHandler {
public:
    AppMediaEventHandle()
    {
        type_ = EnumAdd(MmiMessageId::MEDIA_EVENT_BEGIN, 1);
    }
    ~AppMediaEventHandle() {}
    virtual bool OnPlay(const MultimodalEvent& event) override
    {
        return true;
    }
    virtual bool OnPause(const MultimodalEvent& event) override
    {
        return true;
    }
    virtual bool OnMediaControl(const MultimodalEvent& event) override
    {
        return true;
    }
};

template<class T>
StandEventPtr CreateEvent()
{
    return StandEventPtr(new T());
}

static std::map<std::string, StandEventPtr> g_handerMap;

HWTEST_F(MultimodalEventHandlerApiOtherTest, Api_Test_RegisterStandardizedEventHandle_01, TestSize.Level1)
{
    std::string u8String = "\nTest!\n";
    auto wsConvert = std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {};
    auto u16String = wsConvert.from_bytes(u8String);
    auto remoteObject = MMIToken::Create(u16String);
    int32_t windowId = getpid();

    auto appTouch = CreateEvent<AppTouchEventHandle>();
    MMIEventHdl.RegisterStandardizedEventHandle(remoteObject, windowId, appTouch);
    g_handerMap[std::string("AppTouchEventHandle")] = appTouch;

    auto appMedia = CreateEvent<AppMediaEventHandle>();
    MMIEventHdl.RegisterStandardizedEventHandle(remoteObject, windowId, appMedia);
    g_handerMap[std::string("AppMediaEventHandle")] = appMedia;

    auto appKey = CreateEvent<AppKeyEventHandle>();
    MMIEventHdl.RegisterStandardizedEventHandle(remoteObject, windowId, appKey);
    auto retRegister = MMIEventHdl.RegisterStandardizedEventHandle(remoteObject, windowId, appKey);
    g_handerMap[std::string("AppKeyEventHandle")] = appKey;

    EXPECT_EQ(retRegister, MMI_STANDARD_EVENT_INVALID_PARAMETER);
}

HWTEST_F(MultimodalEventHandlerApiOtherTest, Api_Test_GetAbilityInfoVec, TestSize.Level1)
{
    MultimodalEventHandler multimodalEventHandlerTest;
    sptr<IRemoteObject> token = nullptr;
    int32_t windowId = 2;
    StandEventPtr standardizedEventHandle = nullptr;
    auto ret = multimodalEventHandlerTest.RegisterStandardizedEventHandle(token, windowId, standardizedEventHandle);
    auto retAbilityInfoVec = multimodalEventHandlerTest.GetAbilityInfoVec();
    int32_t retWindowId = 0;
    auto iter = retAbilityInfoVec.cbegin();
    for (; iter != retAbilityInfoVec.cend(); iter++) {
        retWindowId = iter[0].windowId;
    }
    EXPECT_EQ(retWindowId, windowId);
    EXPECT_EQ(ret, MMI_STANDARD_EVENT_INVALID_PARAMETER);
}

HWTEST_F(MultimodalEventHandlerApiOtherTest, Api_Test_RegisterStandardizedEventHandle_02, TestSize.Level1)
{
    MultimodalEventHandler multimodalEventHandlerTest;
    sptr<IRemoteObject> token = nullptr;
    int32_t windowId = 1;
    StandEventPtr standardizedEventHandle = nullptr;
    auto ret = multimodalEventHandlerTest.RegisterStandardizedEventHandle(token, windowId, standardizedEventHandle);
    EXPECT_EQ(ret, MMI_STANDARD_EVENT_INVALID_PARAMETER);
}

HWTEST_F(MultimodalEventHandlerApiOtherTest, Api_Test_UnregisterStandardizedEventHandle, TestSize.Level1)
{
    std::string u8String = "\nTest!\n";
    auto wsConvert = std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {};
    auto u16String = wsConvert.from_bytes(u8String);
    auto remoteObject = MMIToken::Create(u16String);
    int32_t windowId = getpid();
    int32_t retUnRegister = -10;
    auto appKey = CreateEvent<AppKeyEventHandle>();
    MMIEventHdl.RegisterStandardizedEventHandle(remoteObject, windowId, appKey);
    g_handerMap[std::string("AppKeyEventHandle0")] = appKey;
    MMIEventHdl.RegisterStandardizedEventHandle(remoteObject, windowId, appKey);
    g_handerMap[std::string("AppKeyEventHandle1")] = appKey;
    for (auto it = g_handerMap.begin(); it != g_handerMap.end();)
    {
        retUnRegister = MMIEventHdl.UnregisterStandardizedEventHandle(remoteObject, windowId, it->second);
        g_handerMap.erase(it++);
    }
    EXPECT_EQ(retUnRegister, MMI_STANDARD_EVENT_INVALID_PARAMETER);
}
} // namespace
