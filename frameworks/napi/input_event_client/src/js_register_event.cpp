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
#include "js_register_event.h"
#include <inttypes.h>
#include "define_multimodal.h"
#include "js_register_util.h"
#include "stylus_event.h"

namespace OHOS {
    namespace MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsRegisterEvent" };
    }
        static std::map<std::string, uint32_t> g_jsEventType = {};

        void InitJsEvents()
        {
            // common
            g_jsEventType[eventTable[ON_SHOW_MENU]] = COMMON_TYPE_CODE;
            g_jsEventType[eventTable[ON_SEND]] = COMMON_TYPE_CODE;
            g_jsEventType[eventTable[ON_COPY]] = COMMON_TYPE_CODE;
            g_jsEventType[eventTable[ON_PASTE]] = COMMON_TYPE_CODE;
            g_jsEventType[eventTable[ON_CUT]] = COMMON_TYPE_CODE;
            g_jsEventType[eventTable[ON_UNDO]] = COMMON_TYPE_CODE;
            g_jsEventType[eventTable[ON_REFRESH]] = COMMON_TYPE_CODE;
            g_jsEventType[eventTable[ON_START_DRAG]] = COMMON_TYPE_CODE;
            g_jsEventType[eventTable[ON_CANCEL]] = COMMON_TYPE_CODE;
            g_jsEventType[eventTable[ON_ENTER]] = COMMON_TYPE_CODE;
            g_jsEventType[eventTable[ON_PREVIOUS]] = COMMON_TYPE_CODE;
            g_jsEventType[eventTable[ON_NEXT]] = COMMON_TYPE_CODE;
            g_jsEventType[eventTable[ON_BACK]] = COMMON_TYPE_CODE;
            g_jsEventType[eventTable[ON_PRINT]] = COMMON_TYPE_CODE;

            // telephone
            g_jsEventType[eventTable[ON_ANSWER]] = TELEPHONE_TYPE_CODE;
            g_jsEventType[eventTable[ON_REFUSE]] = TELEPHONE_TYPE_CODE;
            g_jsEventType[eventTable[ON_HANGUP]] = TELEPHONE_TYPE_CODE;
            g_jsEventType[eventTable[ON_TELEPHONE_CONTROL]] = TELEPHONE_TYPE_CODE;

            // media
            g_jsEventType[eventTable[ON_PLAY]] = MEDIA_TYPE_CODE;
            g_jsEventType[eventTable[ON_PAUSE]] = MEDIA_TYPE_CODE;
            g_jsEventType[eventTable[ON_MEDIA_CONTROL]] = MEDIA_TYPE_CODE;

            // system
            g_jsEventType[eventTable[ON_SCREEN_SHOT]] = SYSTEM_TYPE_CODE;
            g_jsEventType[eventTable[ON_SCREEN_SPLIT]] = SYSTEM_TYPE_CODE;
            g_jsEventType[eventTable[ON_START_SCREEN_RECORD]] = SYSTEM_TYPE_CODE;
            g_jsEventType[eventTable[ON_STOP_SCREEN_RECORD]] = SYSTEM_TYPE_CODE;
            g_jsEventType[eventTable[ON_GOTO_DESKTOP]] = SYSTEM_TYPE_CODE;
            g_jsEventType[eventTable[ON_RECENT]] = SYSTEM_TYPE_CODE;
            g_jsEventType[eventTable[ON_SHOW_NOTIFICATION]] = SYSTEM_TYPE_CODE;
            g_jsEventType[eventTable[ON_LOCK_SCREEN]] = SYSTEM_TYPE_CODE;
            g_jsEventType[eventTable[ON_SEARCH]] = SYSTEM_TYPE_CODE;
            g_jsEventType[eventTable[ON_CLOSE_PAGE]] = SYSTEM_TYPE_CODE;
            g_jsEventType[eventTable[ON_LAUNCH_VOICE_ASSISTANT]] = SYSTEM_TYPE_CODE;
            g_jsEventType[eventTable[ON_MUTE]] = SYSTEM_TYPE_CODE;

            // key
            g_jsEventType[keyTable[ON_KEY]] = EVENT_TYPE_CODE;

            // touch
            g_jsEventType[touchTable[ON_TOUCH]] = TOUCH_TYPE_CODE;

            // device
            g_jsEventType[deviceTable[ON_DEVICE_ADD]] = DEVICE_TYPE_CODE;
            g_jsEventType[deviceTable[ON_DEVICE_REMOVE]] = DEVICE_TYPE_CODE;
            return;
        }

        uint32_t GetHandleType(const std::string& name)
        {
            uint32_t type = INVALID_TYPE_CODE;
            auto iter = g_jsEventType.find(name);
            if (iter != g_jsEventType.end()) {
                type =  iter->second;
            }
            return type;
        }

        uint32_t GetHandleType(uint32_t eventType)
        {
            uint32_t type = INVALID_TYPE_CODE;
            if (eventType < INVALID_EVENT) {
                auto iter = g_jsEventType.find(eventTable[eventType]);
                if (iter != g_jsEventType.end()) {
                    type =  iter->second;
                }
            }
            return type;
        }

        int32_t AddEventCallback(const napi_env& env, CallbackMap& jsEvent, const EventInfo &event)
        {
            HILOG_DEBUG("AddEventCallback: enter");
            auto iter = jsEvent.find(event.name);
            if (iter == jsEvent.end()) {
                HILOG_DEBUG("AddEventCallback: %{public}s has no callback function.", event.name.c_str());
                return JS_CALLBACK_EVENT_FAILED;
            }
            HILOG_DEBUG("AddEventCallback: event=%{public}s", event.name.c_str());
            HILOG_DEBUG("AddEventCallback: jsEvent size=%{public}d", static_cast<int32_t>(jsEvent.size()));

            auto it = iter->second.begin();
            while (it != iter->second.end()) {
                bool isEquals = false;
                napi_value handlerTemp = nullptr;
                napi_get_reference_value(env, *it, &handlerTemp);
                napi_strict_equals(env, handlerTemp, event.handle, &isEquals);
                if (isEquals) {
                    HILOG_DEBUG("AddEventCallback: %{public}s callback already exists.", event.name.c_str());
                    return JS_CALLBACK_EVENT_EXIST;
                }
                it++;
            }
            napi_ref callbackRef = nullptr;
            napi_create_reference(env, event.handle, 1, &callbackRef);
            iter->second.push_back(callbackRef);
            HILOG_DEBUG("AddEventCallback: callback size=%{public}d", static_cast<int32_t>(iter->second.size()));
            HILOG_DEBUG("AddEventCallback: success");
            return JS_CALLBACK_EVENT_SUCCESS;
        }

        int32_t DelEventCallback(const napi_env& env, CallbackMap& jsEvent, const EventInfo &event)
        {
            HILOG_DEBUG("DelEventCallback: enter");
            auto iter = jsEvent.find(event.name);
            if (iter == jsEvent.end()) {
                HILOG_DEBUG("DelEventCallback: %{public}s has no callback function.", event.name.c_str());
                return JS_CALLBACK_EVENT_FAILED;
            }
            HILOG_DEBUG("DelEventCallback: event=%{public}s", event.name.c_str());

            auto it = iter->second.begin();
            while (it != iter->second.end()) {
                bool isEquals = false;
                napi_value handlerTemp = nullptr;
                napi_get_reference_value(env, *it, &handlerTemp);
                napi_strict_equals(env, handlerTemp, event.handle, &isEquals);
                if (isEquals) {
                    napi_delete_reference(env, *it);
                    iter->second.erase(it);
                    HILOG_DEBUG("DelCallback: success. callback exists. size=%{public}d",
                                static_cast<int32_t>(iter->second.size()));
                    return JS_CALLBACK_EVENT_SUCCESS;
                }
                it++;
            }
            HILOG_DEBUG("DelEventCallback: callback size=%{public}d", static_cast<int32_t>(iter->second.size()));
            HILOG_DEBUG("DelEventCallback: success.");
            return JS_CALLBACK_EVENT_NOT_EXIST;
        }

        uint32_t GetEventCallbackNum(const CallbackMap& jsEvent)
        {
            uint32_t callbackNum = 0;
            auto iter = jsEvent.begin();
            while (iter != jsEvent.end()) {
                callbackNum += iter->second.size();
                iter++;
            }
            HILOG_DEBUG("GetEventCallbackNum: callbackNum=%{public}d", callbackNum);
            return callbackNum;
        }

        static void AddMultimodalData(const napi_env& env, napi_value argv, const MultimodalEvent& event)
        {
            napi_valuetype valueType = napi_undefined;
            NAPI_CALL_RETURN_VOID(env, napi_typeof(env, argv, &valueType));
            if (valueType != napi_object) {
                HILOG_ERROR("AddMultimodalData: argv is not napi_object");
                return;
            }

            SetNamedProperty(env, argv, "uuid", event.GetUuid());
            SetNamedProperty(env, argv, "occurredTime", event.GetOccurredTime());
            SetNamedProperty(env, argv, "sourceDevice", event.GetSourceDevice());
            SetNamedProperty(env, argv, "eventType", event.GetEventType());
            SetNamedProperty(env, argv, "highLevelEvent", event.GetHighLevelEvent());
            SetNamedProperty(env, argv, "deviceId", event.GetDeviceId());
            SetNamedProperty(env, argv, "inputDeviceId", event.GetInputDeviceId());
            SetNamedProperty(env, argv, "isHighLevelEvent", event.IsHighLevelInput());
            return;
        }

        static void AddMultimodalData(const napi_env& env, napi_value argv, const TouchEvent& event)
        {
            napi_valuetype valueType = napi_undefined;
            NAPI_CALL_RETURN_VOID(env, napi_typeof(env, argv, &valueType));
            if (valueType != napi_object) {
                HILOG_ERROR("AddMultimodalData: argv is not napi_object");
                return;
            }

            SetNamedProperty(env, argv, "uuid", event.GetUuid());
            SetNamedProperty(env, argv, "occurredTime", event.GetOccurredTime());
            SetNamedProperty(env, argv, "sourceDevice", event.GetSourceDevice());
            SetNamedProperty(env, argv, "eventType", event.GetEventType());
            SetNamedProperty(env, argv, "highLevelEvent", event.GetHighLevelEvent());
            SetNamedProperty(env, argv, "deviceId", event.GetDeviceId());
            SetNamedProperty(env, argv, "inputDeviceId", event.GetInputDeviceId());
            SetNamedProperty(env, argv, "isHighLevelEvent", event.IsHighLevelInput());
            return;
        }

        static void AddMultimodalData(const napi_env& env, napi_value argv, const OHOS::KeyEvent& event)
        {
            napi_valuetype valueType = napi_undefined;
            NAPI_CALL_RETURN_VOID(env, napi_typeof(env, argv, &valueType));
            if (valueType != napi_object) {
                HILOG_ERROR("AddMultimodalData: argv is not napi_object");
                return;
            }

            SetNamedProperty(env, argv, "uuid", event.GetUuid());
            SetNamedProperty(env, argv, "occurredTime", event.GetOccurredTime());
            SetNamedProperty(env, argv, "sourceDevice", event.GetSourceDevice());
            SetNamedProperty(env, argv, "eventType", event.GetEventType());
            SetNamedProperty(env, argv, "highLevelEvent", event.GetHighLevelEvent());
            SetNamedProperty(env, argv, "deviceId", event.GetDeviceId());
            SetNamedProperty(env, argv, "inputDeviceId", event.GetInputDeviceId());
            SetNamedProperty(env, argv, "isHighLevelEvent", event.IsHighLevelInput());
            return;
        }

        static void AddMultimodalData(const napi_env& env, napi_value argv, const MouseEvent& event)
        {
            napi_valuetype valueType = napi_undefined;
            NAPI_CALL_RETURN_VOID(env, napi_typeof(env, argv, &valueType));
            if (valueType != napi_object) {
                HILOG_ERROR("AddMultimodalData: argv is not napi_object");
                return;
            }

            SetNamedProperty(env, argv, "uuid", event.GetUuid());
            SetNamedProperty(env, argv, "occurredTime", event.GetOccurredTime());
            SetNamedProperty(env, argv, "sourceDevice", event.GetSourceDevice());
            SetNamedProperty(env, argv, "eventType", event.GetEventType());
            SetNamedProperty(env, argv, "highLevelEvent", event.GetHighLevelEvent());
            SetNamedProperty(env, argv, "deviceId", event.GetDeviceId());
            SetNamedProperty(env, argv, "inputDeviceId", event.GetInputDeviceId());
            SetNamedProperty(env, argv, "isHighLevelEvent", event.IsHighLevelInput());
            return;
        }

        static void AddMmiPoint(const napi_env& env, napi_value argv, const MmiPoint& mmiPoint)
        {
            napi_valuetype valueType = napi_undefined;
            NAPI_CALL_RETURN_VOID(env, napi_typeof(env, argv, &valueType));
            if (valueType != napi_object) {
                HILOG_ERROR("AddMmiPoint: argv is not napi_object");
                return;
            }
            napi_value jsPoint = nullptr;
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &jsPoint));
            SetNamedProperty(env, jsPoint, "px", mmiPoint.GetX());
            SetNamedProperty(env, jsPoint, "py", mmiPoint.GetY());
            SetNamedProperty(env, jsPoint, "pz", mmiPoint.GetZ());
            SetNamedProperty(env, jsPoint, "toString", mmiPoint.ToString());
            SetNamedProperty(env, argv, "mmiPoint", jsPoint);
            return;
        }

        static void AddMouseData(const napi_env& env, napi_value argv, const MouseEvent& event)
        {
            napi_valuetype valueType = napi_undefined;
            NAPI_CALL_RETURN_VOID(env, napi_typeof(env, argv, &valueType));
            if (valueType != napi_object) {
                HILOG_ERROR("AddMouseData: argv is not napi_object");
                return;
            }

            napi_value argvMouse = nullptr;
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &argvMouse));
            SetNamedProperty(env, argvMouse, "action", event.GetAction());
            SetNamedProperty(env, argvMouse, "actionButton", event.GetActionButton());
            SetNamedProperty(env, argvMouse, "pressedButtons", event.GetPressedButtons());

            AddMmiPoint(env, argvMouse, event.GetCursor());

            SetNamedProperty(env, argvMouse, "offsetX", event.GetXOffset());
            SetNamedProperty(env, argvMouse, "offsetY", event.GetYOffset());
            SetNamedProperty(env, argvMouse, "cursorDelta", event.GetCursorDelta(0));

            napi_value axisData = nullptr;
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &axisData));
            SetNamedProperty(env, axisData, "AXIS_X", event.GetAxisValue(AXIS_X));
            SetNamedProperty(env, axisData, "AXIS_Y", event.GetAxisValue(AXIS_Y));
            SetNamedProperty(env, axisData, "AXIS_Z", event.GetAxisValue(AXIS_Z));
            SetNamedProperty(env, axisData, "AXIS_ORIENTATION", event.GetAxisValue(AXIS_ORIENTATION));
            SetNamedProperty(env, axisData, "AXIS_RX", event.GetAxisValue(AXIS_RX));
            SetNamedProperty(env, axisData, "AXIS_RY", event.GetAxisValue(AXIS_RY));
            SetNamedProperty(env, axisData, "AXIS_RZ", event.GetAxisValue(AXIS_RZ));
            SetNamedProperty(env, axisData, "AXIS_HAT_X", event.GetAxisValue(AXIS_HAT_X));
            SetNamedProperty(env, axisData, "AXIS_HAT_Y", event.GetAxisValue(AXIS_HAT_Y));
            SetNamedProperty(env, axisData, "AXIS_LTRIGGER", event.GetAxisValue(AXIS_LTRIGGER));
            SetNamedProperty(env, axisData, "AXIS_THROTTLE", event.GetAxisValue(AXIS_THROTTLE));
            SetNamedProperty(env, axisData, "AXIS_WHEEL", event.GetAxisValue(AXIS_WHEEL));
            SetNamedProperty(env, axisData, "AXIS_DISTANCE", event.GetAxisValue(AXIS_DISTANCE));
            SetNamedProperty(env, axisData, "AXIS_TILT", event.GetAxisValue(AXIS_TILT));
            SetNamedProperty(env, axisData, "AXIS_TILT_X", event.GetAxisValue(AXIS_TILT_X));
            SetNamedProperty(env, axisData, "AXIS_TILT_Y", event.GetAxisValue(AXIS_TILT_Y));
            SetNamedProperty(env, argvMouse, "axis", axisData);

            AddMultimodalData(env, argvMouse, event);

            SetNamedProperty(env, argv, "mouseEvent", argvMouse);
            return;
        }

        static void AddStylusData(const napi_env& env, napi_value argv, const StylusEvent& event)
        {
            napi_valuetype valueType = napi_undefined;
            NAPI_CALL_RETURN_VOID(env, napi_typeof(env, argv, &valueType));
            if (valueType != napi_object) {
                HILOG_ERROR("AddStylusData: argv is not napi_object");
                return;
            }

            napi_value argvStylus = nullptr;
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &argvStylus));
            SetNamedProperty(env, argvStylus, "action", event.GetAction());
            SetNamedProperty(env, argvStylus, "buttons", event.GetButtons());

            AddMultimodalData(env, argvStylus, event);

            SetNamedProperty(env, argv, "stylusEvent", argvStylus);
            return;
        }

        bool SendMultimodalEvent(const napi_env& env, const CallbackMap& jsEvent, int32_t type,
                                 const MultimodalEvent& event)
        {
            HILOG_DEBUG("SendMultimodalEvent: event=%{public}s ", eventTable[type].c_str());
            HILOG_DEBUG("SendMultimodalEvent: CallbackMap size=%{public}d", static_cast<int32_t>(jsEvent.size()));
            size_t argc = 1;
            napi_value argv = nullptr;
            napi_value result = nullptr;
            napi_value thisVar = nullptr;
            bool getResult = false;
            if (napi_get_undefined(env, &thisVar) != napi_ok) {
                HILOG_ERROR("SendEvent: call napi_get_undefined fail.");
                return getResult;
            }
            if (napi_create_object(env, &result) != napi_ok) {
                HILOG_ERROR("SendEvent: call napi_create_object fail.");
                return getResult;
            }
            if (napi_create_object(env, &argv) != napi_ok) {
                HILOG_ERROR("SendEvent: call napi_create_object fail.");
                return getResult;
            }

            AddMultimodalData(env, argv, event);
            SetNamedProperty(env, argv, "type", type);

            auto iter = jsEvent.find(eventTable[type]);
            if (iter == jsEvent.end()) {
                HILOG_ERROR("SendMultimodalEvent: invalid event=%{public}s", eventTable[type].c_str());
                return false;
            }
            if (iter->second.size() == 0) {
                HILOG_DEBUG("SendMultimodalEvent: %{public}s has no callback function.", eventTable[type].c_str());
                return true;
            }

            for (auto it = iter->second.begin(); it != iter->second.end(); it++) {
                napi_value callback = nullptr;
                if (napi_get_reference_value(env, *it, &callback) != napi_ok) {
                    HILOG_ERROR("SendEvent: call napi_get_reference_value fail.");
                    return getResult;
                }
                napi_status status = napi_call_function(env, thisVar, callback, argc, &argv, &result);
                if (status != napi_ok) {
                    HILOG_ERROR("SendMultimodalEvent::napi_call_function failed.");
                    return false;
                }
                HILOG_DEBUG("SendMultimodalEvent: napi_call_function success");
            }

            HILOG_DEBUG("SendMultimodalEvent: success");
            return true;
        }

        AppSystemEventHandle::AppSystemEventHandle(const napi_env& env)
        {
            this->env = env;
            jsEvent[eventTable[ON_SCREEN_SHOT]] = {};
            jsEvent[eventTable[ON_SCREEN_SPLIT]] = {};
            jsEvent[eventTable[ON_START_SCREEN_RECORD]] = {};
            jsEvent[eventTable[ON_STOP_SCREEN_RECORD]] = {};
            jsEvent[eventTable[ON_GOTO_DESKTOP]] = {};
            jsEvent[eventTable[ON_RECENT]] = {};
            jsEvent[eventTable[ON_SHOW_NOTIFICATION]] = {};
            jsEvent[eventTable[ON_LOCK_SCREEN]] = {};
            jsEvent[eventTable[ON_SEARCH]] = {};
            jsEvent[eventTable[ON_CLOSE_PAGE]] = {};
            jsEvent[eventTable[ON_LAUNCH_VOICE_ASSISTANT]] = {};
            jsEvent[eventTable[ON_MUTE]] = {};
        }

        bool AppSystemEventHandle::OnScreenShot(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_SCREEN_SHOT, multimodalEvent);
        }

        bool AppSystemEventHandle::OnScreenSplit(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_SCREEN_SPLIT, multimodalEvent);
        }

        bool AppSystemEventHandle::OnStartScreenRecord(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_START_SCREEN_RECORD, multimodalEvent);
        }

        bool AppSystemEventHandle::OnStopScreenRecord(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_STOP_SCREEN_RECORD, multimodalEvent);
        }

        bool AppSystemEventHandle::OnGotoDesktop(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_GOTO_DESKTOP, multimodalEvent);
        }

        bool AppSystemEventHandle::OnRecent(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_RECENT, multimodalEvent);
        }

        bool AppSystemEventHandle::OnShowNotification(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_SHOW_NOTIFICATION, multimodalEvent);
        }

        bool AppSystemEventHandle::OnLockScreen(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_LOCK_SCREEN, multimodalEvent);
        }

        bool AppSystemEventHandle::OnSearch(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_SEARCH, multimodalEvent);
        }

        bool AppSystemEventHandle::OnClosePage(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_CLOSE_PAGE, multimodalEvent);
        }

        bool AppSystemEventHandle::OnLaunchVoiceAssistant(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_LAUNCH_VOICE_ASSISTANT, multimodalEvent);
        }

        bool AppSystemEventHandle::OnMute(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_MUTE, multimodalEvent);
        }

        // Common
        AppCommonEventHandle::AppCommonEventHandle(const napi_env& env)
        {
            this->env = env;
            jsEvent[eventTable[ON_SHOW_MENU]] = {};
            jsEvent[eventTable[ON_SEND]] = {};
            jsEvent[eventTable[ON_COPY]] = {};
            jsEvent[eventTable[ON_PASTE]] = {};
            jsEvent[eventTable[ON_CUT]] = {};
            jsEvent[eventTable[ON_UNDO]] = {};
            jsEvent[eventTable[ON_REFRESH]] = {};
            jsEvent[eventTable[ON_START_DRAG]] = {};
            jsEvent[eventTable[ON_CANCEL]] = {};
            jsEvent[eventTable[ON_ENTER]] = {};
            jsEvent[eventTable[ON_PREVIOUS]] = {};
            jsEvent[eventTable[ON_NEXT]] = {};
            jsEvent[eventTable[ON_BACK]] = {};
            jsEvent[eventTable[ON_PRINT]] = {};
        }

        bool AppCommonEventHandle::OnShowMenu(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_SHOW_MENU, multimodalEvent);
        }

        bool AppCommonEventHandle::OnSend(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_SEND, multimodalEvent);
        }

        bool AppCommonEventHandle::OnCopy(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_COPY, multimodalEvent);
        }

        bool AppCommonEventHandle::OnPaste(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_PASTE, multimodalEvent);
        }

        bool AppCommonEventHandle::OnCut(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_CUT, multimodalEvent);
        }

        bool AppCommonEventHandle::OnUndo(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_UNDO, multimodalEvent);
        }

        bool AppCommonEventHandle::OnRefresh(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_REFRESH, multimodalEvent);
        }

        bool AppCommonEventHandle::OnStartDrag(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_START_DRAG, multimodalEvent);
        }

        bool AppCommonEventHandle::OnCancel(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_CANCEL, multimodalEvent);
        }

        bool AppCommonEventHandle::OnEnter(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_ENTER, multimodalEvent);
        }

        bool AppCommonEventHandle::OnPrevious(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_PREVIOUS, multimodalEvent);
        }

        bool AppCommonEventHandle::OnNext(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_NEXT, multimodalEvent);
        }

        bool AppCommonEventHandle::OnBack(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_BACK, multimodalEvent);
        }

        bool AppCommonEventHandle::OnPrint(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_PRINT, multimodalEvent);
        }

        // Telephone
        AppTelephoneEventHandle::AppTelephoneEventHandle(const napi_env& env)
        {
            this->env = env;
            jsEvent[eventTable[ON_ANSWER]] = {};
            jsEvent[eventTable[ON_REFUSE]] = {};
            jsEvent[eventTable[ON_HANGUP]] = {};
            jsEvent[eventTable[ON_TELEPHONE_CONTROL]] = {};
        }

        bool AppTelephoneEventHandle::OnAnswer(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_ANSWER, multimodalEvent);
        }

        bool AppTelephoneEventHandle::OnRefuse(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_REFUSE, multimodalEvent);
        }

        bool AppTelephoneEventHandle::OnHangup(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_HANGUP, multimodalEvent);
        }

        bool AppTelephoneEventHandle::OnTelephoneControl(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_TELEPHONE_CONTROL, multimodalEvent);
        }

        // Media
        AppMediaEventHandle::AppMediaEventHandle(const napi_env& env)
        {
            this->env = env;
            jsEvent[eventTable[ON_PLAY]] = {};
            jsEvent[eventTable[ON_PAUSE]] = {};
            jsEvent[eventTable[ON_MEDIA_CONTROL]] = {};
        }

        bool AppMediaEventHandle::OnPlay(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_PLAY, multimodalEvent);
        }

        bool AppMediaEventHandle::OnPause(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_PAUSE, multimodalEvent);
        }

        bool AppMediaEventHandle::OnMediaControl(const MultimodalEvent& multimodalEvent)
        {
            return SendMultimodalEvent(env, jsEvent, ON_MEDIA_CONTROL, multimodalEvent);
        }

        // Key
        AppKeyEventHandle::AppKeyEventHandle(const napi_env& env)
        {
            this->env = env;
            jsEvent[keyTable[ON_KEY]] = {};
        }

        bool AppKeyEventHandle::OnKey(const OHOS::KeyEvent& keyEvent)
        {
            return SendEvent(keyTable[ON_KEY], keyEvent);
        }

        bool AppKeyEventHandle::SendEvent(const std::string& name, const OHOS::KeyEvent& event) const
        {
            HILOG_DEBUG("AppKeyEventHandle::SendEvent: event=%{public}s", name.c_str());
            size_t argc = 1;
            napi_value argv = nullptr;
            napi_value result = nullptr;
            napi_value thisVar = nullptr;
            bool getResult = false;
            if (napi_get_undefined(env, &thisVar) != napi_ok) {
                HILOG_ERROR("SendEvent: call napi_get_undefined fail.");
                return getResult;
            }
            if (napi_create_object(env, &result) != napi_ok) {
                HILOG_ERROR("SendEvent: call napi_create_object fail.");
                return getResult;
            }
            if (napi_create_object(env, &argv) != napi_ok) {
                HILOG_ERROR("SendEvent: call napi_create_object fail.");
                return getResult;
            }

            // KeyEvent
            SetNamedProperty(env, argv, "isPressed", event.IsKeyDown());
            SetNamedProperty(env, argv, "keyCode", event.GetKeyCode());
            SetNamedProperty(env, argv, "keyDownDuration", event.GetKeyDownDuration());

            // MultimodalEvent
            AddMultimodalData(env, argv, event);

            auto iter = jsEvent.find(name);
            if (iter == jsEvent.end()) {
                HILOG_ERROR("AppKeyEventHandle::SendEvent: invalid event=%{public}s", name.c_str());
                return false;
            }
            if (iter->second.size() == 0) {
                HILOG_DEBUG("AppKeyEventHandle::SendEvent: %{public}s has no callback function.", name.c_str());
                return true;
            }
            for (auto it = iter->second.begin(); it != iter->second.end(); it++) {
                napi_value callback = nullptr;
                if (napi_get_reference_value(env, *it, &callback) != napi_ok) {
                    HILOG_ERROR("SendEvent: call napi_get_reference_value fail.");
                    return getResult;
                }
                napi_status status = napi_call_function(env, thisVar, callback, argc, &argv, &result);
                if (status != napi_ok) {
                    HILOG_ERROR("AppKeyEventHandle::napi_call_function failed.");
                    return false;
                }
                HILOG_DEBUG("AppKeyEventHandle: napi_call_function ok");
            }

            HILOG_DEBUG("AppKeyEventHandle::SendEvent: success");
            return true;
        }

        // Touch
        AppTouchEventHandle::AppTouchEventHandle(const napi_env& env)
        {
            this->env = env;
            jsEvent[touchTable[ON_TOUCH]] = {};
        }

        bool AppTouchEventHandle::OnTouch(const TouchEvent& touchEvent)
        {
            return SendEvent(touchTable[ON_TOUCH], touchEvent);
        }

        bool AppTouchEventHandle::SendEvent(const std::string& name, const TouchEvent& event) const
        {
            HILOG_DEBUG("AppTouchEventHandle::SendEvent: event=%{public}s", name.c_str());
            size_t argc = 1;
            napi_value argv = nullptr;
            napi_value result = nullptr;
            napi_value thisVar = nullptr;
            bool getResult = false;
            if (napi_get_undefined(env, &thisVar) != napi_ok) {
                HILOG_ERROR("SendEvent: call napi_get_undefined fail.");
                return getResult;
            }
            if (napi_create_object(env, &result) != napi_ok) {
                HILOG_ERROR("SendEvent: call napi_create_object fail.");
                return getResult;
            }
            if (napi_create_object(env, &argv) != napi_ok) {
                HILOG_ERROR("SendEvent: call napi_create_object fail.");
                return getResult;
            }
            PrepareData(env, argv, event);

            auto iter = jsEvent.find(name);
            if (iter == jsEvent.end()) {
                HILOG_ERROR("AppTouchEventHandle::SendEvent: invalid event=%{public}s", name.c_str());
                return false;
            }
            if (iter->second.size() == 0) {
                HILOG_DEBUG("AppTouchEventHandle::SendEvent: %{public}s has no callback function.", name.c_str());
                return true;
            }

            for (auto it = iter->second.begin(); it != iter->second.end(); it++) {
                napi_value callback = nullptr;
                if (napi_get_reference_value(env, *it, &callback) != napi_ok) {
                    HILOG_ERROR("SendEvent: call napi_get_reference_value fail.");
                    return getResult;
                }
                napi_status status = napi_call_function(env, thisVar, callback, argc, &argv, &result);
                if (status != napi_ok) {
                    HILOG_ERROR("AppTouchEventHandle::napi_call_function failed.");
                    return false;
                }
                HILOG_DEBUG("AppTouchEventHandle: napi_call_function success");
            }
            HILOG_DEBUG("AppTouchEventHandle::SendEvent: success");
            return true;
        }

        void AppTouchEventHandle::PrepareData(const napi_env& env, napi_value argv,
                                              const TouchEvent& event) const
        {
            // touch
            SetNamedProperty(env, argv, "action", event.GetAction());
            SetNamedProperty(env, argv, "index", event.GetIndex());
            SetNamedProperty(env, argv, "forcePrecision", event.GetForcePrecision());
            SetNamedProperty(env, argv, "maxForce", event.GetMaxForce());
            SetNamedProperty(env, argv, "tapCount", event.GetTapCount());
            SetNamedProperty(env, argv, "isStandard", event.GetIsStandard());

            // ManipulationEvent
            SetNamedProperty(env, argv, "startTime", event.GetStartTime());
            SetNamedProperty(env, argv, "operationState", event.GetPhase());
            int32_t pointerCount = event.GetPointerCount();
            SetNamedProperty(env, argv, "pointerCount", pointerCount);

            napi_value fingerInfos;
            NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &fingerInfos));
            for (auto i = 0; i < pointerCount; i++) {
                napi_value fingerData = nullptr;
                NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &fingerData));
                SetNamedProperty(env, fingerData, "pointerId", event.GetPointerId(i));
                SetNamedProperty(env, fingerData, "touchArea", event.GetForce(i));
                SetNamedProperty(env, fingerData, "touchPressure", event.GetRadius(i));
                AddMmiPoint(env, fingerData, event.GetPointerPosition(i));
                NAPI_CALL_RETURN_VOID(env, napi_set_element(env, fingerInfos, i, fingerData));
            }
            SetNamedProperty(env, argv, "fingerInfos", fingerInfos);
            AddMultimodalData(env, argv, event);

            int32_t deviceEventType = event.GetOriginEventType();
            SetNamedProperty(env, argv, "deviceEventType", deviceEventType);
            HILOG_DEBUG("AppTouchEventHandle::SendEvent: deviceEventType=%{public}d", deviceEventType);
            if (deviceEventType == MOUSE_EVENT) {
                HILOG_DEBUG("AppTouchEventHandle::SendEvent: mouseEvent");
                MouseEvent* mouseEvent = (MouseEvent*)event.GetMultimodalEvent();
                AddMouseData(env, argv, *mouseEvent);
            } else if (deviceEventType == STYLUS_EVENT) {
                HILOG_DEBUG("AppTouchEventHandle::SendEvent: stylusEvent");
                StylusEvent* stylusEvent = (StylusEvent*)event.GetMultimodalEvent();
                CHK(stylusEvent, ERROR_NULL_POINTER);
                AddStylusData(env, argv, *stylusEvent);
            }
        }

        // Device
        AppDeviceEventHandle::AppDeviceEventHandle(const napi_env& env)
        {
            this->env = env;
            jsEvent[deviceTable[ON_DEVICE_ADD]] = {};
            jsEvent[deviceTable[ON_DEVICE_REMOVE]] = {};
        }

        bool AppDeviceEventHandle::OnDeviceAdd(const DeviceEvent& deviceEvent)
        {
            return SendEvent(deviceTable[ON_DEVICE_ADD], deviceEvent);
        }

        bool AppDeviceEventHandle::OnDeviceRemove(const DeviceEvent& deviceEvent)
        {
            return SendEvent(deviceTable[ON_DEVICE_REMOVE], deviceEvent);
        }

        bool AppDeviceEventHandle::SendEvent(const std::string& name, const DeviceEvent& event) const
        {
            HILOG_DEBUG("AppDeviceEventHandle::SendEvent: event=%{public}s", name.c_str());
            size_t argc = 1;
            napi_value argv = nullptr;
            napi_value result = nullptr;
            napi_value thisVar = nullptr;
            bool getResult = false;
            if (napi_get_undefined(env, &thisVar) != napi_ok) {
                HILOG_ERROR("SendEvent: call napi_get_undefined fail.");
                return getResult;
            }
            if (napi_create_object(env, &result) != napi_ok) {
                HILOG_ERROR("SendEvent: call napi_create_object fail.");
                return getResult;
            }
            if (napi_create_object(env, &argv) != napi_ok) {
                HILOG_ERROR("SendEvent: call napi_create_object fail.");
                return getResult;
            }
            // DeviceEvent
            SetNamedProperty(env, argv, "name", event.GetName());
            SetNamedProperty(env, argv, "sysName", event.GetSysName());
            SetNamedProperty(env, argv, "inputDeviceId", event.GetInputDeviceId());

            // MultimodalEvent
            SetNamedProperty(env, argv, "uuid", event.GetUuid());
            SetNamedProperty(env, argv, "occurredTime", event.GetOccurredTime());
            SetNamedProperty(env, argv, "sourceDevice", event.GetSourceDevice());
            SetNamedProperty(env, argv, "eventType", event.GetEventType());
            SetNamedProperty(env, argv, "highLevelEvent", event.GetHighLevelEvent());
            SetNamedProperty(env, argv, "deviceId", event.GetDeviceId());
            SetNamedProperty(env, argv, "inputDeviceId", event.GetInputDeviceId());
            SetNamedProperty(env, argv, "isHighLevelEvent", event.IsHighLevelInput());

            auto iter = jsEvent.find(name);
            if (iter == jsEvent.end()) {
                HILOG_ERROR("AppDeviceEventHandle::SendEvent: invalid event=%{public}s", name.c_str());
                return false;
            }
            if (iter->second.size() == 0) {
                HILOG_DEBUG("AppDeviceEventHandle::SendEvent: %{public}s has no callback function.", name.c_str());
                return true;
            }

            for (auto it = iter->second.begin(); it != iter->second.end(); it++) {
                napi_value callback = nullptr;
                if (napi_get_reference_value(env, *it, &callback) != napi_ok) {
                    HILOG_ERROR("SendEvent: call napi_get_reference_value fail.");
                    return callback;
                }
                napi_create_int32(env, SUCCESS_CODE, &result);
                napi_status status = napi_call_function(env, thisVar, callback, argc, &argv, &result);
                if (status != napi_ok) {
                    HILOG_ERROR("AppDeviceEventHandle::napi_call_function failed.");
                    return false;
                }
                HILOG_DEBUG("AppDeviceEventHandle: napi_call_function success");
            }

            HILOG_DEBUG("AppDeviceEventHandle::SendEvent: success ");
            return true;
        }
    }
}
