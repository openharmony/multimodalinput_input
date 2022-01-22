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
#ifndef OHOS_JS_REGISTER_EVENTS_H
#define OHOS_JS_REGISTER_EVENTS_H

#include <array>
#include "event_factory.h"
#include "js_register_module.h"

#define EVENT_COUNT 33
#define TOUCH_COUNT 1
#define KEY_COUNT 1
#define DEVICE_COUNT 2

namespace OHOS {
namespace MMI {
enum ENUM_EVENT_CALLBACK {
    ON_SHOW_MENU = 0,
    ON_SEND = 1,
    ON_COPY = 2,
    ON_PASTE = 3,
    ON_CUT = 4,
    ON_UNDO = 5,
    ON_REFRESH = 6,
    ON_START_DRAG = 7,
    ON_CANCEL = 8,
    ON_ENTER = 9,
    ON_PREVIOUS = 10,
    ON_NEXT = 11,
    ON_BACK = 12,
    ON_PRINT = 13,
    ON_ANSWER = 14,
    ON_REFUSE = 15,
    ON_HANGUP = 16,
    ON_TELEPHONE_CONTROL = 17,
    ON_PLAY  = 18,
    ON_PAUSE = 19,
    ON_MEDIA_CONTROL = 20,
    ON_SCREEN_SHOT = 21,
    ON_SCREEN_SPLIT = 22,
    ON_START_SCREEN_RECORD = 23,
    ON_STOP_SCREEN_RECORD = 24,
    ON_GOTO_DESKTOP = 25,
    ON_RECENT = 26,
    ON_SHOW_NOTIFICATION = 27,
    ON_LOCK_SCREEN = 28,
    ON_SEARCH = 29,
    ON_CLOSE_PAGE = 30,
    ON_LAUNCH_VOICE_ASSISTANT = 31,
    ON_MUTE = 32,
    INVALID_EVENT,
};

const std::array<std::string, EVENT_COUNT> eventTable = {
    "showMenu", "send", "copy", "paste", "cut", "undo", "refresh", "startDrag", "cancel", "enter",
    "previous", "next", "back", "print", "answer", "refuse", "hangup", "telephoneControl", "play",
    "pause", "mediaControl", "screenShot", "screenSplit", "startScreenRecord", "stopScreenRecord",
    "gotoDesktop", "recent", "showNotification", "lockScreen", "search", "closePage",
    "launchVoiceAssistant", "mute"
};

enum ENUM_KEY_EVENT {
    ON_KEY = 0,
};
const std::array<std::string, KEY_COUNT> keyTable = {"key"};

enum ENUM_TOUCH_EVENT {
    ON_TOUCH = 0,
};
const std::array<std::string, TOUCH_COUNT> touchTable = {"touch"};

enum ENUM_DEVICE_EVENT {
    ON_DEVICE_ADD = 0,
    ON_DEVICE_REMOVE = 1,
};
const std::array<std::string, DEVICE_COUNT> deviceTable = {"deviceAdd", "deviceRemove"};

void InitJsEvents();
uint32_t GetHandleType(const std::string& name);
uint32_t GetHandleType(uint32_t eventType);
int32_t AddEventCallback(const napi_env& env, CallbackMap& jsEvent, const EventInfo &event);
int32_t DelEventCallback(const napi_env& env, CallbackMap& jsEvent, const EventInfo &event);
uint32_t GetEventCallbackNum(const CallbackMap& jsEvent);

bool SendMultimodalEvent(const napi_env& env, const CallbackMap& jsEvent, int32_t type,
                         const MultimodalEvent& event);

// class
class AppSystemEventHandle : public SystemEventHandler {
public:
    explicit AppSystemEventHandle(const napi_env& env);
    ~AppSystemEventHandle() = default;
    CallbackMap jsEvent = {};

    virtual bool OnScreenShot(const MultimodalEvent& multimodalEvent);
    virtual bool OnScreenSplit(const MultimodalEvent& multimodalEvent);
    virtual bool OnStartScreenRecord(const MultimodalEvent& multimodalEvent);
    virtual bool OnStopScreenRecord(const MultimodalEvent& multimodalEvent);
    virtual bool OnGotoDesktop(const MultimodalEvent& multimodalEvent);
    virtual bool OnRecent(const MultimodalEvent& multimodalEvent);
    virtual bool OnShowNotification(const MultimodalEvent& multimodalEvent);
    virtual bool OnLockScreen(const MultimodalEvent& multimodalEvent);
    virtual bool OnSearch(const MultimodalEvent& multimodalEvent);
    virtual bool OnClosePage(const MultimodalEvent& multimodalEvent);
    virtual bool OnLaunchVoiceAssistant(const MultimodalEvent& multimodalEvent);
    virtual bool OnMute(const MultimodalEvent& multimodalEvent);
private:
    napi_env env = nullptr;
};

class AppCommonEventHandle : public CommonEventHandler {
public:
    explicit AppCommonEventHandle(const napi_env& env);
    ~AppCommonEventHandle() = default;
    CallbackMap jsEvent = {};

    virtual bool OnShowMenu(const MultimodalEvent& multimodalEvent);
    virtual bool OnSend(const MultimodalEvent& multimodalEvent);
    virtual bool OnCopy(const MultimodalEvent& multimodalEvent);
    virtual bool OnPaste(const MultimodalEvent& multimodalEvent);
    virtual bool OnCut(const MultimodalEvent& multimodalEvent);
    virtual bool OnUndo(const MultimodalEvent& multimodalEvent);
    virtual bool OnRefresh(const MultimodalEvent& multimodalEvent);
    virtual bool OnStartDrag(const MultimodalEvent& multimodalEvent);
    virtual bool OnCancel(const MultimodalEvent& multimodalEvent);
    virtual bool OnEnter(const MultimodalEvent& multimodalEvent);
    virtual bool OnPrevious(const MultimodalEvent& multimodalEvent);
    virtual bool OnNext(const MultimodalEvent& multimodalEvent);
    virtual bool OnBack(const MultimodalEvent& multimodalEvent);
    virtual bool OnPrint(const MultimodalEvent& multimodalEvent);
private:
    napi_env env = nullptr;
};

class AppTelephoneEventHandle : public TelephoneEventHandler {
public:
    explicit AppTelephoneEventHandle(const napi_env& env);
    ~AppTelephoneEventHandle() = default;
    CallbackMap jsEvent = {};

    virtual bool OnAnswer(const MultimodalEvent& multimodalEvent);
    virtual bool OnRefuse(const MultimodalEvent& multimodalEvent);
    virtual bool OnHangup(const MultimodalEvent& multimodalEvent);
    virtual bool OnTelephoneControl(const MultimodalEvent& multimodalEvent);
private:
    napi_env env = nullptr;
};

class AppMediaEventHandle : public MediaEventHandler {
public:
    explicit AppMediaEventHandle(const napi_env& env);
    ~AppMediaEventHandle() = default;
    CallbackMap jsEvent = {};

    virtual bool OnPlay(const MultimodalEvent& multimodalEvent);
    virtual bool OnPause(const MultimodalEvent& multimodalEvent);
    virtual bool OnMediaControl(const MultimodalEvent& multimodalEvent);
private:
    napi_env env = nullptr;
};

class AppKeyEventHandle : public KeyEventHandler {
public:
    explicit AppKeyEventHandle(const napi_env& env);
    ~AppKeyEventHandle() = default;
    CallbackMap jsEvent = {};

    virtual bool OnKey(const OHOS::KeyEvent& keyEvent);
private:
    napi_env env = nullptr;
    bool SendEvent(const std::string& name, const OHOS::KeyEvent& event) const;
};

class AppTouchEventHandle : public TouchEventHandler {
public:
    explicit AppTouchEventHandle(const napi_env& env);
    ~AppTouchEventHandle() = default;
    CallbackMap jsEvent = {};

    virtual bool OnTouch(const TouchEvent& touchEvent);
private:
    napi_env env = nullptr;
    bool SendEvent(const std::string& name, const TouchEvent& event) const;
    void PrepareData(const napi_env &env, napi_value argv, const TouchEvent& event) const;
};

class AppDeviceEventHandle : public DeviceHandler {
public:
    explicit AppDeviceEventHandle(const napi_env& env);
    ~AppDeviceEventHandle() = default;
    CallbackMap jsEvent = {};

    virtual bool OnDeviceAdd(const DeviceEvent& deviceEvent) override;
    virtual bool OnDeviceRemove(const DeviceEvent& deviceEvent) override;
private:
    napi_env env = nullptr;
    bool SendEvent(const std::string& name, const DeviceEvent& event) const;
};
}
}
#endif
