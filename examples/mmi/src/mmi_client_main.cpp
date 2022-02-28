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

#include "mmi_client.h"

#include <codecvt>
#include <csignal>
#include <locale>

#include "common_event_handler.h"
#include "key_event_handler.h"
#include "media_event_handler.h"
#include "mmi_token.h"
#include "multimodal_event_handler.h"
#include "system_event_handler.h"
#include "telephone_event_handler.h"
#include "touch_event_handler.h"

namespace {
using namespace OHOS;
using namespace OHOS::MMI;

constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MMIClientDemo" }; // namespace

class AppKeyEventHandle : public KeyEventHandler {
public:
    AppKeyEventHandle() {}
    ~AppKeyEventHandle() {}

    virtual bool OnKey(const OHOS::KeyEvent& keylEvent) override
    {
        MMI_LOGD("enter");
        return true;
    }
};

class AppTouchEventHandle : public TouchEventHandler {
public:
    AppTouchEventHandle() {}
    ~AppTouchEventHandle() {}

    virtual bool OnTouch(const TouchEvent& touchEvent) override
    {
        MMI_LOGD("enter");
        return true;
    }
};

class AppCommonEventHandle : public CommonEventHandler {
public:
    AppCommonEventHandle() {}
    ~AppCommonEventHandle() {}

    virtual bool OnShowMenu(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnSend(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnCopy(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnPaste(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnCut(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnUndo(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnRefresh(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnStartDrag(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnCancel(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnEnter(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnPrevious(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnNext(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnBack(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnPrint(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }
};

class AppMediaEventHandle : public MediaEventHandler {
public:
    AppMediaEventHandle() {}
    ~AppMediaEventHandle() {}

    virtual bool OnPlay(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnPause(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnMediaControl(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }
};

class AppSystemEventHandle : public SystemEventHandler {
public:
    AppSystemEventHandle() {}
    ~AppSystemEventHandle() {}

    virtual bool OnClosePage(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnLaunchVoiceAssistant(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnMute(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnScreenShot(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnScreenSplit(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnStartScreenRecord(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnStopScreenRecord(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnGotoDesktop(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnRecent(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnShowNotification(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnLockScreen(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnSearch(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }
};

class AppTelephoneEventHandle : public TelephoneEventHandler {
public:
    AppTelephoneEventHandle() {}
    ~AppTelephoneEventHandle() {}

    virtual bool OnAnswer(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnRefuse(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnHangup(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }

    virtual bool OnTelephoneControl(const MultimodalEvent& event) override
    {
        MMI_LOGD("enter");
        return true;
    }
};

template<class T>
StandEventPtr CreateEvent()
{
    return StandEventPtr(new T());
}

class MMIClientDemo {
public:
    MMIClientDemo()
    {
        windowId_ = getpid();
        std::string u8String = "hello world!\n";
        auto wsConvert = std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {};
        auto u16String = wsConvert.from_bytes(u8String);
        remoteObject_ = MMIToken::Create(u16String);
        remoteObject_->SetName("TestHapName");
        remoteObject_->SetBundlerName("TestBundlerName");
    }
    ~MMIClientDemo()
    {
        MMI_LOGI("in %s enter", __func__);
        UnregisterStandardizedEventHandle();
        MMI_LOGI("in %s leave", __func__);
    }

    void RegisterStandardizedEventHandle()
    {
        MMI_LOGD("enter");

        MMI_LOGD("Register key event");

        using namespace OHOS::MMI;

        auto appKey = CreateEvent<AppKeyEventHandle>();
        handerMap_[std::string("AppKeyEventHandle")] = appKey;
        MMIEventHdl.RegisterStandardizedEventHandle(remoteObject_, windowId_, appKey);

        MMI_LOGD("Register touch event");
        auto appTouch = CreateEvent<AppTouchEventHandle>();
        handerMap_[std::string("AppTouchEventHandle")] = appTouch;
        MMIEventHdl.RegisterStandardizedEventHandle(remoteObject_, windowId_, appTouch);

        MMI_LOGD("Register Common event");
        auto appCommon = CreateEvent<AppCommonEventHandle>();
        handerMap_[std::string("AppCommonEventHandle")] = appCommon;
        MMIEventHdl.RegisterStandardizedEventHandle(remoteObject_, windowId_, appCommon);

        MMI_LOGD("Register Media event");
        auto appMedia = CreateEvent<AppMediaEventHandle>();
        handerMap_[std::string("AppMediaEventHandle")] = appMedia;
        MMIEventHdl.RegisterStandardizedEventHandle(remoteObject_, windowId_, appMedia);

        MMI_LOGD("Register System event");
        auto appSystem = CreateEvent<AppSystemEventHandle>();
        handerMap_[std::string("AppSystemEventHandle")] = appSystem;
        MMIEventHdl.RegisterStandardizedEventHandle(remoteObject_, windowId_, appSystem);

        MMI_LOGD("Register Telephone event");
        auto appTelephone = CreateEvent<AppTelephoneEventHandle>();
        handerMap_[std::string("AppTelephoneEventHandle")] = appTelephone;
        MMIEventHdl.RegisterStandardizedEventHandle(remoteObject_, windowId_, appTelephone);
    }

    void UnregisterStandardizedEventHandle()
    {
        MMI_LOGD("enter");
        for (auto it = handerMap_.begin(); it != handerMap_.end();) {
            MMI_LOGD("%{public}s", it->first.c_str());
            MMIEventHdl.UnregisterStandardizedEventHandle(remoteObject_, windowId_, it->second);
            handerMap_.erase(it++);
        }
    }
private:
    sptr<MMIToken> remoteObject_ = nullptr;
    int32_t windowId_;
    std::map<std::string, StandEventPtr> handerMap_;
};

static std::atomic_bool g_clientExit(false);

void RunClient()
{
    MMI_LOGD("begin");
    MMIClientDemo client;
    client.RegisterStandardizedEventHandle();

    while (!g_clientExit) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    client.UnregisterStandardizedEventHandle();
    MMI_LOGD("end");
}

void ClientStopHandler(int32_t signalNo)
{
    MMI_LOGI("client will exit! %d", signalNo);
    g_clientExit = true;
}
} // namespace

int32_t main(int32_t argc, char* argv[])
{
#ifdef OHOS_BUILD_MMI_DEBUG
    VerifyLogManagerRun();
#endif
    const sighandler_t ret = signal(SIGTERM, ClientStopHandler);
    if (ret == SIG_ERR) {
        MMI_LOGD("signal ret SIG_ERR");
        return RET_ERR;
    }

    RunClient();

    while (!g_clientExit) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    MMI_LOGD("leave");

    return 0;
}

