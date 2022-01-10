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

#include "js_register_module.h"
#include <inttypes.h>
#include "js_register_event.h"
#include "js_register_handle.h"
#include "js_register_util.h"
#include "multi_input_common.h"

namespace OHOS {
    namespace MMI {
        const uint32_t EVENT_NAME_LEN = 64;
        const uint32_t ARGC_NUM = 2;
        const uint32_t ARGC_UT_NUM = 2;
        const uint32_t ARGV_FIRST = 0;
        const uint32_t ARGV_SECOND = 1;

        template<class T>
        static StandEventPtr CreateEvent(napi_env env)
        {
            return StandEventPtr(new T(env));
        }

        static napi_value GetEventInfo(napi_env env, napi_callback_info info, EventInfo& event)
        {
            size_t argc = ARGC_NUM;
            napi_value argv[ARGC_NUM] = { 0 };
            napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
            NAPI_ASSERT(env, argc == ARGC_NUM, "GetEventInfo: requires 2 parameter");

            napi_valuetype eventValueType = {};
            napi_typeof(env, argv[ARGV_FIRST], &eventValueType);
            NAPI_ASSERT(env, eventValueType == napi_string, "GetEventInfo: parameter1 is not napi_string");

            napi_valuetype eventHandleType = {};
            napi_typeof(env, argv[ARGV_SECOND], &eventHandleType);
            NAPI_ASSERT(env, eventHandleType == napi_function, "GetEventInfo: parameter2 is not napi_function");

            char eventName[EVENT_NAME_LEN] = { 0 };
            size_t typeLen = 0;
            napi_get_value_string_utf8(env, argv[ARGV_FIRST], eventName, EVENT_NAME_LEN - 1, &typeLen);

            event.handle = argv[ARGV_SECOND];
            event.name = eventName;
            event.type = GetHandleType(event.name);
            event.winId = 0;
            HILOG_INFO("GetEventInfo: winId=%{public}d", event.winId);
            HILOG_INFO("GetEventInfo: type=%{public}d", event.type);
            HILOG_INFO("GetEventInfo: name=%{public}s", event.name.c_str());

            napi_value result = {};
            napi_create_int32(env, SUCCESS_CODE, &result);
            return result;
        }

        static int32_t RegisterByTypeCode(napi_env env, JSRegisterHandle &registerHandle, const EventInfo &event)
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
            HILOG_DEBUG("OnEvent: enter");
            napi_value result = nullptr;
            napi_create_int32(env, MMI_STANDARD_EVENT_INVALID_PARAMETER, &result);

            static EventInfo event = {};
            if (GetEventInfo(env, info, event) == nullptr) {
                HILOG_ERROR("OnEvent: GetEventInfo failed");
                return result;
            }
            if (event.type == INVALID_TYPE_CODE) {
                HILOG_ERROR("OnEvent: invalid registerHandle type=%{public}d", event.type);
                return result;
            }

            JSRegisterHandle registerHandle(env);
            int32_t response = MMI_STANDARD_EVENT_SUCCESS;
            if (!registerHandle.CheckRegistered(event.winId, event.type)) {
                response = RegisterByTypeCode(env, registerHandle, event);
                if (response != MMI_STANDARD_EVENT_SUCCESS) {
                    HILOG_DEBUG("OnEvent: RegisterByTypeCode error response=%d", response);
                    napi_create_int32(env, response, &result);
                    return result;
                }
            }
            StandEventPtr eventHandle = registerHandle.GetEventHandle(event.winId, event.type);
            if (eventHandle == nullptr) {
                HILOG_ERROR("OnEvent: register handle not exited");
                return result;
            }

            response = AddEvent(env, eventHandle, event);
            if (response == JS_CALLBACK_EVENT_FAILED) {
                HILOG_DEBUG("OnEvent: AddEvent error.");
                return result;
            }

            HILOG_DEBUG("OnEvent: success");
            napi_create_int32(env, response, &result);
            return result;
        }

        static napi_value OffEvent(napi_env env, napi_callback_info info)
        {
            HILOG_DEBUG("OffEvent: enter");
            napi_value result = nullptr;
            napi_create_int32(env, MMI_STANDARD_EVENT_INVALID_PARAMETER, &result);

            static EventInfo event = {};
            if (GetEventInfo(env, info, event) == nullptr) {
                HILOG_ERROR("OffEvent: GetEventInfo failed");
                return result;
            }

            JSRegisterHandle registerHandle(env);
            StandEventPtr eventHandle = registerHandle.GetEventHandle(event.winId, event.type);
            if (eventHandle == nullptr) {
                HILOG_ERROR("OffEvent: event handle not exited");
                napi_create_int32(env, MMI_STANDARD_EVENT_NOT_EXIST, &result);
                return result;
            }

            if (!registerHandle.CheckRegistered(event.winId, event.type)) {
                HILOG_ERROR("OffEvent: registerhandle not exited");
                return result;
            }

            int32_t response = DelEvent(env, eventHandle, event);
            if (response == JS_CALLBACK_EVENT_FAILED) {
                HILOG_DEBUG("OffEvent: DelEvent error.");
                return result;
            }

            if (!registerHandle.CheckUnregistered(event.winId, event.type)) {
                HILOG_ERROR("OffEvent: no need unregister eventHandle");
                napi_create_int32(env, response, &result);
                return result;
            }

            response = registerHandle.Unregister(event.winId, event.type);
            napi_create_int32(env, response, &result);
            HILOG_DEBUG("OffEvent: success");
            return result;
        }

        static napi_value InjectEvent(napi_env env, napi_callback_info info)
        {
            HILOG_DEBUG("InjectEvent: enter");
            size_t argc = 1;
            napi_value argv[1] = { 0 };
            napi_valuetype tmpType = napi_undefined;
            napi_value result = nullptr;
            if (napi_create_int32(env, MMI_STANDARD_EVENT_INVALID_PARAMETER, &result) != napi_ok) {
                HILOG_ERROR("UnitTest: call napi_create_int32 fail.");
                return result;
            }

            if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok) {
                HILOG_ERROR("call napi_get_cb_info fail.");
                return result;
            }
            NAPI_ASSERT(env, argc == 1, "InjectEvent: paramater num error");

            napi_value keyHandle = nullptr;
            napi_get_named_property(env, argv[0], "KeyEvent", &keyHandle);
            napi_typeof(env, keyHandle, &tmpType);
            NAPI_ASSERT(env, tmpType == napi_object, "InjectEvent: parameter1 is not napi_object");

            bool isPressed = GetNamedPropertyBool(env, keyHandle, "isPressed");
            int32_t keyCode = GetNamedPropertyInt32(env, keyHandle, "keyCode");
            bool isIntercepted = GetNamedPropertyBool(env, keyHandle, "isIntercepted");
            int32_t keyDownDuration = GetNamedPropertyInt32(env, keyHandle, "keyDownDuration");

            OHOS::KeyEvent injectEvent;
            injectEvent.Initialize(0, isPressed, keyCode, keyDownDuration, 0, "", 0, 0, "", 0, false, 0, isIntercepted);
            int32_t response = MMIEventHdl.InjectEvent(injectEvent);
            HILOG_INFO("InjectEvent: response=%{public}d", response);

            if (napi_create_int32(env, response, &result) != napi_ok) {
                HILOG_ERROR("UnitTest: call napi_create_int32 fail.");
                return result;
            }
            HILOG_DEBUG("InjectEvent: success");
            return result;
        }

        // only support common/telephone/media/system event
        static napi_value UnitTest(napi_env env, napi_callback_info info)
        {
            HILOG_DEBUG("UnitTest: enter");
            size_t argc;
            napi_value argv[ARGC_UT_NUM] = { 0 };
            napi_value result = nullptr;
            if (napi_create_int32(env, ERROR_CODE, &result) != napi_ok) {
                HILOG_ERROR("UnitTest: call napi_create_int32 fail.");
                return result;
            }
            napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
            NAPI_ASSERT(env, argc == ARGC_UT_NUM, "UnitTest: paramater num error");

            napi_valuetype eventWinIdType = napi_undefined;
            napi_typeof(env, argv[ARGV_FIRST], &eventWinIdType);
            NAPI_ASSERT(env, eventWinIdType == napi_number, "UnitTest: parameter1 is not napi_number");
            int32_t winId = 0;
            napi_get_value_int32(env, argv[ARGV_FIRST], &winId);

            napi_valuetype eventObjType = napi_undefined;
            napi_typeof(env, argv[ARGV_SECOND], &eventObjType);
            NAPI_ASSERT(env, eventObjType == napi_object, "UnitTest: parameter2 is not napi_object");

            std::string uuid = GetNamedPropertyString(env, argv[ARGV_SECOND], "uuid");
            uint64_t occurredTime = GetNamedPropertyInt64(env, argv[ARGV_SECOND], "occurredTime");
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
                HILOG_ERROR("UnitTest: call napi_create_int32 fail.");
                return result;
            }
            HILOG_DEBUG("UnitTest: success");
            return result;
        }

        static napi_value SetInjectFile(napi_env env, napi_callback_info info)
        {
            HILOG_DEBUG("SetInjectFile: enter");
            size_t argc;
            napi_value argv[ARGC_UT_NUM] = { 0 };
            napi_value result = nullptr;
            if (napi_create_int32(env, ERROR_CODE, &result) != napi_ok) {
                HILOG_ERROR("InjectCmd: call napi_create_int32 fail.");
                return result;
            }
            napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

            napi_valuetype eventWinIdType = napi_undefined;
            napi_typeof(env, argv[ARGV_FIRST], &eventWinIdType);
            NAPI_ASSERT(env, eventWinIdType == napi_number, "SetInjectFile: parameter1 is not napi_number");
            int32_t winId = 0;
            napi_get_value_int32(env, argv[ARGV_FIRST], &winId);

            napi_valuetype eventObjType = napi_undefined;
            napi_typeof(env, argv[ARGV_SECOND], &eventObjType);
            NAPI_ASSERT(env, eventObjType == napi_object, "SetInjectFile: parameter2 is not napi_object");

            HILOG_DEBUG("SetInjectFile: GetNamedPropertyString enter");
            std::string virtualEventFileName = GetNamedPropertyString(env, argv[ARGV_SECOND], "eventFileName");
            std::string virtualEventValue = GetNamedPropertyString(env, argv[ARGV_SECOND], "jsonEvent");
            HILOG_DEBUG("SetInjectFile: GetNamedPropertyString out");
            MultiInputCommon virtualInjectEvent;
            virtualInjectEvent.SetIniFile(virtualEventFileName, virtualEventValue);
            HILOG_INFO("SetInjectFile: success. virtualEventValue=%s", virtualEventFileName.c_str());
            HILOG_INFO("SetInjectFile: success. virtualEventValue=%s", virtualEventValue.c_str());
            if (napi_create_int32(env, SUCCESS_CODE, &result) != napi_ok) {
                HILOG_ERROR("InjectCmd: call napi_create_int32 fail.");
                return result;
            }

            HILOG_INFO("SetInjectFile:End");
            return result;
        }

        EXTERN_C_START
        static napi_value MmiInit(napi_env env, napi_value exports)
        {
            HILOG_INFO("MmiInit: enter");
            napi_property_descriptor desc[] = {
                DECLARE_NAPI_FUNCTION("on", OnEvent),
                DECLARE_NAPI_FUNCTION("off", OffEvent),
                DECLARE_NAPI_FUNCTION("unitTest", UnitTest),
                DECLARE_NAPI_FUNCTION("injectEvent", InjectEvent),
                DECLARE_NAPI_FUNCTION("setInjectFile", SetInjectFile)
            };
            NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
            InitJsEvents();
            HILOG_INFO("MmiInit: success");
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
    }
}

