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

#include "js_register_module.h"
#include <cinttypes>
#ifdef OHOS_WESTEN_MODEL
    #include "js_register_event.h"
    #include "js_register_handle.h"
    #include "multi_input_common.h"
#else
    #include "input_manager.h"
#endif // OHOS_WESTEN_MODEL

#include "js_register_util.h"

namespace OHOS {
namespace MMI {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JSRegisterMoudle" };
#ifdef OHOS_WESTEN_MODEL
    constexpr size_t EVENT_NAME_LEN = 64;
    constexpr size_t ARGC_NUM = 2;
    constexpr size_t ARGC_UT_NUM = 2;
    constexpr size_t ARGV_FIRST = 0;
    constexpr size_t ARGV_SECOND = 1;
#endif // OHOS_WESTEN_MODEL
}

#ifdef OHOS_WESTEN_MODEL
template<class T>
static StandEventPtr CreateEvent(napi_env env)
{
    return StandEventPtr(new T(env));
}

static napi_value GetEventInfo(napi_env env, napi_callback_info info, EventInfo& event)
{
    size_t argc = ARGC_NUM;
    napi_value argv[ARGC_NUM] = { 0 };
    napi_status status = napi_generic_failure;

    status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        MMI_LOGE("get cb info failed");
        return nullptr;
    }
    if (argc < ARGC_NUM) {
        MMI_LOGE("argc is not require Argc");
        return nullptr;
    }

    napi_valuetype eventValueType = {};
    napi_typeof(env, argv[ARGV_FIRST], &eventValueType);
    if (eventValueType != napi_string) {
        MMI_LOGE("parameter1 is not napi_string");
        return nullptr;
    }

    napi_valuetype eventHandleType = {};
    napi_typeof(env, argv[ARGV_SECOND], &eventHandleType);
    if (eventValueType != napi_function) {
        MMI_LOGE("parameter2 is not napi_function");
        return nullptr;
    }

    char eventName[EVENT_NAME_LEN] = { 0 };
    size_t typeLen = 0;
    napi_get_value_string_utf8(env, argv[ARGV_FIRST], eventName, EVENT_NAME_LEN - 1, &typeLen);

    event.handle = argv[ARGV_SECOND];
    event.name = eventName;
    event.type = GetHandleType(event.name);
    event.winId = 0;
    MMI_LOGD("event info, type:%{public}d,name:%{public}s", event.type, event.name.c_str());

    napi_value result = {};
    napi_create_int32(env, SUCCESS_CODE, &result);
    return result;
}

static int32_t RegisterTypeCode(napi_env env, JSRegisterHandle &registerHandle, const EventInfo &event)
{
    int32_t response = ERROR_CODE;
    if (SYSTEM_TYPE_CODE == event.type) {
        auto systemEventHandle = CreateEvent<AppSystemEventHandle>(env);
        response = registerHandle.Register(systemEventHandle, event.winId, event.type);
    } else if (COMMON_TYPE_CODE == event.type) {
        auto commonEventHandle = CreateEvent<AppCommonEventHandle>(env);
        response = registerHandle.Register(commonEventHandle, event.winId, event.type);
    } else if (TELEPHONE_TYPE_CODE == event.type) {
        auto telephoneEventHandle = CreateEvent<AppTelephoneEventHandle>(env);
        response = registerHandle.Register(telephoneEventHandle, event.winId, event.type);
    } else if (MEDIA_TYPE_CODE == event.type) {
        auto mediaEventHandle = CreateEvent<AppMediaEventHandle>(env);
        response = registerHandle.Register(mediaEventHandle, event.winId, event.type);
    } else if (EVENT_TYPE_CODE == event.type) {
        auto keyEventHandle = CreateEvent<AppKeyEventHandle>(env);
        response = registerHandle.Register(keyEventHandle, event.winId, event.type);
    } else if (TOUCH_TYPE_CODE == event.type) {
        auto touchEventHandle = CreateEvent<AppTouchEventHandle>(env);
        response = registerHandle.Register(touchEventHandle, event.winId, event.type);
    } else if (DEVICE_TYPE_CODE == event.type) {
        auto deviceEventHandle = CreateEvent<AppDeviceEventHandle>(env);
        response = registerHandle.Register(deviceEventHandle, event.winId, event.type);
    }

    return response;
}

static napi_value OnEvent(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_create_int32(env, MMI_STANDARD_EVENT_INVALID_PARAM, &result);

    EventInfo event = {};
    if (GetEventInfo(env, info, event) == nullptr) {
        MMI_LOGE("GetEventInfo failed");
        return result;
    }
    if (event.type == INVALID_TYPE_CODE) {
        MMI_LOGE("invalid registerHandle type:%{public}d", event.type);
        return result;
    }

    JSRegisterHandle registerHandle(env);
    int32_t response = MMI_STANDARD_EVENT_SUCCESS;
    if (!registerHandle.CheckRegistered(event.winId, event.type)) {
        response = RegisterTypeCode(env, registerHandle, event);
        if (response != MMI_STANDARD_EVENT_SUCCESS) {
            MMI_LOGD("register failed, response=%d", response);
            napi_create_int32(env, response, &result);
            return result;
        }
    }
    StandEventPtr eventHandle = registerHandle.GetEventHandle(event.winId, event.type);
    if (eventHandle == nullptr) {
        MMI_LOGE("register handle not exited");
        return result;
    }

    response = AddEvent(env, eventHandle, event);
    if (response == JS_CALLBACK_EVENT_FAILED) {
        MMI_LOGD("add event failed");
        return result;
    }

    napi_create_int32(env, response, &result);
    return result;
}

static napi_value OffEvent(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_create_int32(env, MMI_STANDARD_EVENT_INVALID_PARAM, &result);

    EventInfo event = {};
    if (GetEventInfo(env, info, event) == nullptr) {
        MMI_LOGE("GetEventInfo failed");
        return result;
    }

    JSRegisterHandle registerHandle(env);
    StandEventPtr eventHandle = registerHandle.GetEventHandle(event.winId, event.type);
    if (eventHandle == nullptr) {
        MMI_LOGE("event handle not exited");
        napi_create_int32(env, MMI_STANDARD_EVENT_NOT_EXIST, &result);
        return result;
    }

    if (!registerHandle.CheckRegistered(event.winId, event.type)) {
        MMI_LOGE("registerhandle not exited");
        return result;
    }

    int32_t response = DelEvent(env, eventHandle, event);
    if (response == JS_CALLBACK_EVENT_FAILED) {
        MMI_LOGE("del event error");
        return result;
    }

    if (!registerHandle.CheckUnregistered(event.winId, event.type)) {
        MMI_LOGE("no need unregister eventHandle");
        napi_create_int32(env, response, &result);
        return result;
    }

    response = registerHandle.Unregister(event.winId, event.type);
    napi_create_int32(env, response, &result);
    return result;
}
#endif // OHOS_WESTEN_MODEL

static napi_value InjectEvent(napi_env env, napi_callback_info info)
{
    MMI_LOGE("enter");
    napi_value result = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok) {
        MMI_LOGE("call napi_get_cb_info fail");
        napi_create_int32(env, MMI_STANDARD_EVENT_INVALID_PARAM, &result);
        return result;
    }
    NAPI_ASSERT(env, argc == 1, "paramater num error");

    napi_value keyHandle = nullptr;
    napi_get_named_property(env, argv[0], "KeyEvent", &keyHandle);
    napi_valuetype tmpType = napi_undefined;
    napi_typeof(env, keyHandle, &tmpType);
    NAPI_ASSERT(env, tmpType == napi_object, "parameter1 is not napi_object");

    bool isPressed = GetNamedPropertyBool(env, keyHandle, "isPressed");
    int32_t keyCode = GetNamedPropertyInt32(env, keyHandle, "keyCode");
    bool isIntercepted = GetNamedPropertyBool(env, keyHandle, "isIntercepted");
    int32_t keyDownDuration = GetNamedPropertyInt32(env, keyHandle, "keyDownDuration");
    isIntercepted = false;

#ifdef OHOS_WESTEN_MODEL
    OHOS::KeyEvent injectEvent;
    injectEvent.Initialize(0, isPressed, keyCode, keyDownDuration, 0, "", 0, 0, "", 0, false, 0, 0, isIntercepted);
    int32_t response = MMIEventHdl.InjectEvent(injectEvent);
    napi_create_int32(env, response, &result);
#else
    auto keyEvent = KeyEvent::Create();
    if (isPressed) {
        keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    } else {
        keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    }
    keyEvent->SetKeyCode(keyCode);
    if (!isIntercepted) {
        keyEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    }
    KeyEvent::KeyItem item;
    item.SetKeyCode(keyCode);
    item.SetPressed(isPressed);
    item.SetDownTime(static_cast<int64_t>(keyDownDuration));
    keyEvent->AddKeyItem(item);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    napi_create_int32(env, 0, &result);
#endif // OHOS_WESTEN_MODEL
    MMI_LOGE("leave");
    return result;
}

#ifdef OHOS_WESTEN_MODEL
// only support common/telephone/media/system event
static napi_value UnitTest(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    if (napi_create_int32(env, ERROR_CODE, &result) != napi_ok) {
        MMI_LOGE("call napi_create_int32 fail");
        return result;
    }
    size_t argc;
    napi_value argv[ARGC_UT_NUM] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    NAPI_ASSERT(env, argc == ARGC_UT_NUM, "paramater num error");

    napi_valuetype eventWinIdType = napi_undefined;
    napi_typeof(env, argv[ARGV_FIRST], &eventWinIdType);
    NAPI_ASSERT(env, eventWinIdType == napi_number, "parameter1 is not napi_number");
    int32_t winId = 0;
    napi_get_value_int32(env, argv[ARGV_FIRST], &winId);

    napi_valuetype eventObjType = napi_undefined;
    napi_typeof(env, argv[ARGV_SECOND], &eventObjType);
    NAPI_ASSERT(env, eventObjType == napi_object, "parameter2 is not napi_object");

    std::string uuid = GetNamedPropertyString(env, argv[ARGV_SECOND], "uuid");
    int64_t occurredTime = GetNamedPropertyInt64(env, argv[ARGV_SECOND], "occurredTime");
    int32_t sourceDevice = GetNamedPropertyInt32(env, argv[ARGV_SECOND], "sourceDevice");
    int32_t inputDeviceId = GetNamedPropertyInt32(env, argv[ARGV_SECOND], "inputDeviceId");
    uint32_t eventType = GetNamedPropertyUint32(env, argv[ARGV_SECOND], "type");
    if (eventType >= INVALID_EVENT) {
        JSRegisterHandle registerHandle(env);
        int32_t response = registerHandle.UnregisterAll();
        napi_create_int32(env, response, &result);
        return result;
    }

    MultimodalEvent multimodalEvent;
    multimodalEvent.Initialize(0, 0, uuid, sourceDevice, occurredTime, "", inputDeviceId,  false, 0);
    UnitSent(env, winId, eventType, multimodalEvent);

    if (napi_create_int32(env, SUCCESS_CODE, &result) != napi_ok) {
        MMI_LOGE("call napi_create_int32 fail");
        return result;
    }
    return result;
}

static napi_value SetInjectFile(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    if (napi_create_int32(env, ERROR_CODE, &result) != napi_ok) {
        MMI_LOGE("call napi_create_int32 fail");
        return result;
    }
    size_t argc;
    napi_value argv[ARGC_UT_NUM] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    napi_valuetype eventWinIdType = napi_undefined;
    napi_typeof(env, argv[ARGV_FIRST], &eventWinIdType);
    NAPI_ASSERT(env, eventWinIdType == napi_number, "parameter1 is not napi_number");
    int32_t winId = 0;
    napi_get_value_int32(env, argv[ARGV_FIRST], &winId);

    napi_valuetype eventObjType = napi_undefined;
    napi_typeof(env, argv[ARGV_SECOND], &eventObjType);
    NAPI_ASSERT(env, eventObjType == napi_object, "parameter2 is not napi_object");

    std::string virtualEventFileName = GetNamedPropertyString(env, argv[ARGV_SECOND], "eventFileName");
    std::string virtualEventValue = GetNamedPropertyString(env, argv[ARGV_SECOND], "jsonEvent");
    
    MultiInputCommon virtualInjectEvent;
    virtualInjectEvent.SetIniFile(virtualEventFileName, virtualEventValue);
    if (napi_create_int32(env, SUCCESS_CODE, &result) != napi_ok) {
        MMI_LOGE("call napi_create_int32 fail");
        return result;
    }
    return result;
}
#endif // OHOS_WESTEN_MODEL

EXTERN_C_START
static napi_value MmiInit(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
#ifdef OHOS_WESTEN_MODEL
        DECLARE_NAPI_FUNCTION("on", OnEvent),
        DECLARE_NAPI_FUNCTION("off", OffEvent),
        DECLARE_NAPI_FUNCTION("unitTest", UnitTest),
        DECLARE_NAPI_FUNCTION("setInjectFile", SetInjectFile)
#endif // OHOS_WESTEN_MODEL
        DECLARE_NAPI_FUNCTION("injectEvent", InjectEvent),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
#ifdef OHOS_WESTEN_MODEL
    InitJsEvents();
#endif // OHOS_WESTEN_MODEL
    return exports;
}
EXTERN_C_END

static napi_module mmiModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = MmiInit,
    .nm_modname = "inputEventClient",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&mmiModule);
}
} // namespace MMI
} // namespace OHOS

