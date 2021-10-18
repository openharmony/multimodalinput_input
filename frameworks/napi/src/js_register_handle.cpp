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
#include "js_register_handle.h"
#include "js_register_event.h"
#include "mmi_token.h"
#include <inttypes.h>

namespace OHOS {
    namespace MMI {
        struct RegisterHanldeInfo {
            sptr<MMIToken> remoteObj;
            int32_t winId;
            std::shared_ptr<EventContext> context;
        };
        std::map<std::string, RegisterHanldeInfo> g_registerMap = {};

        int32_t AddEvent(const napi_env& env, StandEventPtr &eventHandle, const EventInfo &event)
        {
            int32_t ret = JS_CALLBACK_EVENT_FAILED;
            if (SYSTEM_TYPE_CODE == event.type) {
                auto systemEventHandle = (AppSystemEventHandle*)(eventHandle.GetRefPtr());
                ret = AddEventCallback(env, systemEventHandle->jsEvent, event);
            } else if (COMMON_TYPE_CODE == event.type) {
                auto commonEventHandle = (AppCommonEventHandle*)(eventHandle.GetRefPtr());
                ret = AddEventCallback(env, commonEventHandle->jsEvent, event);
            } else if (TELEPHONE_TYPE_CODE == event.type) {
                auto telephoneEventHandle = (AppTelephoneEventHandle*)(eventHandle.GetRefPtr());
                ret = AddEventCallback(env, telephoneEventHandle->jsEvent, event);
            } else if (MEDIA_TYPE_CODE == event.type) {
                auto mediaEventHandle = (AppMediaEventHandle*)(eventHandle.GetRefPtr());
                ret = AddEventCallback(env, mediaEventHandle->jsEvent, event);
            } else if (EVENT_TYPE_CODE == event.type) {
                auto keyEventHandle = (AppKeyEventHandle*)(eventHandle.GetRefPtr());
                ret = AddEventCallback(env, keyEventHandle->jsEvent, event);
            } else if (TOUCH_TYPE_CODE == event.type) {
                auto touchEventHandle = (AppTouchEventHandle*)(eventHandle.GetRefPtr());
                ret = AddEventCallback(env, touchEventHandle->jsEvent, event);
            } else if (DEVICE_TYPE_CODE == event.type) {
                auto deviceEventHandle = (AppDeviceEventHandle*)(eventHandle.GetRefPtr());
                ret = AddEventCallback(env, deviceEventHandle->jsEvent, event);
            }
            return ret;
        }

        int32_t DelEvent(const napi_env& env, StandEventPtr &eventHandle, const EventInfo &event)
        {
            int32_t ret = JS_CALLBACK_EVENT_FAILED;
            if (SYSTEM_TYPE_CODE == event.type) {
                auto systemEventHandle = (AppSystemEventHandle*)(eventHandle.GetRefPtr());
                ret = DelEventCallback(env, systemEventHandle->jsEvent, event);
            } else if (COMMON_TYPE_CODE == event.type) {
                auto commonEventHandle = (AppCommonEventHandle*)(eventHandle.GetRefPtr());
                ret = DelEventCallback(env, commonEventHandle->jsEvent, event);
            } else if (TELEPHONE_TYPE_CODE == event.type) {
                auto telephoneEventHandle = (AppTelephoneEventHandle*)(eventHandle.GetRefPtr());
                ret = DelEventCallback(env, telephoneEventHandle->jsEvent, event);
            } else if (MEDIA_TYPE_CODE == event.type) {
                auto mediaEventHandle = (AppMediaEventHandle*)(eventHandle.GetRefPtr());
                ret = DelEventCallback(env, mediaEventHandle->jsEvent, event);
            } else if (EVENT_TYPE_CODE == event.type) {
                auto keyEventHandle = (AppKeyEventHandle*)(eventHandle.GetRefPtr());
                ret = DelEventCallback(env, keyEventHandle->jsEvent, event);
            } else if (TOUCH_TYPE_CODE == event.type) {
                auto touchEventHandle = (AppTouchEventHandle*)(eventHandle.GetRefPtr());
                ret = DelEventCallback(env, touchEventHandle->jsEvent, event);
            } else if (DEVICE_TYPE_CODE == event.type) {
                auto deviceEventHandle = (AppDeviceEventHandle*)(eventHandle.GetRefPtr());
                ret = DelEventCallback(env, deviceEventHandle->jsEvent, event);
            }
            return ret;
        }

        void UnitSent(napi_env env, int32_t winId, uint32_t eventType, const MultimodalEvent& event)
        {
            HILOG_DEBUG("UnitSent: enter");
            uint32_t type = GetHandleType(eventType);
            std::string registerHandle = std::to_string(winId) + "," + std::to_string(type);
            HILOG_DEBUG("UnitSent: registerHandle=%{public}s", registerHandle.c_str());
            auto iter = g_registerMap.find(registerHandle);
            if (iter == g_registerMap.end()) {
                HILOG_ERROR("UnitSent: registerHandle %s not existed.", registerHandle.c_str());
                return;
            }

            StandEventPtr eventHandle = iter->second.context->pevent;
            if (SYSTEM_TYPE_CODE == type) {
                auto systemEventHandle = (AppSystemEventHandle*)(eventHandle.GetRefPtr());
                SendMultimodalEvent(env, systemEventHandle->jsEvent, eventType, event);
            } else if (COMMON_TYPE_CODE == type) {
                auto commonEventHandle = (AppCommonEventHandle*)(eventHandle.GetRefPtr());
                SendMultimodalEvent(env, commonEventHandle->jsEvent, eventType, event);
            } else if (TELEPHONE_TYPE_CODE == type) {
                auto telephoneEventHandle = (AppTelephoneEventHandle*)(eventHandle.GetRefPtr());
                SendMultimodalEvent(env, telephoneEventHandle->jsEvent, eventType, event);
            } else if (MEDIA_TYPE_CODE == type) {
                auto mediaEventHandle = (AppMediaEventHandle*)(eventHandle.GetRefPtr());
                SendMultimodalEvent(env, mediaEventHandle->jsEvent, eventType, event);
            }
            HILOG_DEBUG("UnitSent: success");
            return;
        }

        JSRegisterHandle::JSRegisterHandle(const napi_env& env)
        {
            this->env_ = env;
        }

        bool JSRegisterHandle::CheckRegistered(int32_t winId, uint32_t type) 
        {
            std::string registerHandle = std::to_string(winId) + "," + std::to_string(type);
            auto iter = g_registerMap.find(registerHandle);
            if (iter == g_registerMap.end()) {
                return false;
            }
            return true;
        }

        bool JSRegisterHandle::CheckUnregistered(int32_t winId, uint32_t type)
        {
            uint32_t num = 0;
            StandEventPtr eventHandle = GetEventHandle(winId, type);
            if (SYSTEM_TYPE_CODE == type) {
                auto systemEventHandle = (AppSystemEventHandle*)(eventHandle.GetRefPtr());
                num = GetEventCallbackNum(systemEventHandle->jsEvent);
            } else if (COMMON_TYPE_CODE == type) {
                auto commonEventHandle = (AppCommonEventHandle*)(eventHandle.GetRefPtr());
                num = GetEventCallbackNum(commonEventHandle->jsEvent);
            } else if (TELEPHONE_TYPE_CODE == type) {
                auto telephoneEventHandle = (AppTelephoneEventHandle*)(eventHandle.GetRefPtr());
                num = GetEventCallbackNum(telephoneEventHandle->jsEvent);
            } else if (MEDIA_TYPE_CODE == type) {
                auto mediaEventHandle = (AppMediaEventHandle*)(eventHandle.GetRefPtr());
                num = GetEventCallbackNum(mediaEventHandle->jsEvent);
            } else if (EVENT_TYPE_CODE == type) {
                auto keyEventHandle = (AppKeyEventHandle*)(eventHandle.GetRefPtr());
                num = GetEventCallbackNum(keyEventHandle->jsEvent);
            } else if (TOUCH_TYPE_CODE == type) {
                auto touchEventHandle = (AppTouchEventHandle*)(eventHandle.GetRefPtr());
                num = GetEventCallbackNum(touchEventHandle->jsEvent);
            } else if (DEVICE_TYPE_CODE == type) {
                auto deviceEventHandle = (AppDeviceEventHandle*)(eventHandle.GetRefPtr());
                num = GetEventCallbackNum(deviceEventHandle->jsEvent);
            }

            if (num > 0) {
                return false;
            }
            return true;
        }

        StandEventPtr JSRegisterHandle::GetEventHandle(int32_t winId, uint32_t type) 
        {
            std::string registerHandle = std::to_string(winId) + "," + std::to_string(type);
            auto iter = g_registerMap.find(registerHandle);
            if (iter == g_registerMap.end()) {
                return nullptr;
            }
            return iter->second.context->pevent;
        }

        int32_t JSRegisterHandle::Register(const StandEventPtr eventHandle, int32_t winId, uint32_t type)
        {
            HILOG_DEBUG("JSRegisterHandle::Register: enter");
            int32_t response = ERROR_CODE;
            std::string u8String = "hello world!";
            auto wsConvert = std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {};
            auto u16String = wsConvert.from_bytes(u8String);
            auto remoteObj = MMIToken::Create(u16String);
            if (remoteObj == nullptr) {
                HILOG_ERROR("Register::Register: remoteObj is nullptr");
                return ERROR_CODE;
            }
            remoteObj->SetName("TestJsHapName");
            remoteObj->SetBundlerName("TestJsBundlerName");
            response = MMIEventHdl.RegisterStandardizedEventHandle(remoteObj, winId, eventHandle);
            if (response != MMI_STANDARD_EVENT_SUCCESS) {
                HILOG_ERROR("Register::Register: failed.response=%{public}d", response);
                return ERROR_CODE;
            }

            auto pContext = std::make_shared<EventContext>();
            pContext->pevent = eventHandle;
            pContext->type = type;
            RegisterHanldeInfo registerInfo;
            registerInfo.remoteObj = remoteObj;
            registerInfo.winId = winId;
            registerInfo.context = pContext;

            std::string registerHandle = std::to_string(winId) + "," + std::to_string(type);
            g_registerMap.insert(std::pair<std::string, RegisterHanldeInfo>(registerHandle, registerInfo));
            HILOG_DEBUG("JSRegisterHandle::Register: registerHandle=%{public}s", registerHandle.c_str());
            HILOG_DEBUG("JSRegisterHandle::Register: registerMap size=%{public}d", static_cast<int32_t>(g_registerMap.size()));
            HILOG_DEBUG("JSRegisterHandle::Register: success");
            return response;
        }

        int32_t JSRegisterHandle::Unregister(int32_t winId, uint32_t type)
        {
            HILOG_DEBUG("JSRegisterHandle::Unregister: enter");
            int32_t response = ERROR_CODE;
            std::string registerHandle = std::to_string(winId) + "," + std::to_string(type);
            auto iter = g_registerMap.find(registerHandle);
            if (iter != g_registerMap.end()) {
                response = MMIEventHdl.UnregisterStandardizedEventHandle(iter->second.remoteObj,
                    iter->second.winId, iter->second.context->pevent);
                if (response != MMI_STANDARD_EVENT_SUCCESS) {
                    HILOG_ERROR("JSRegisterHandle::Unregister: failed. response=%{public}d", response);
                    return response;
                }
                HILOG_DEBUG("JSRegisterHandle::Unregister: registerHandle=%{public}s", registerHandle.c_str());
                g_registerMap.erase(iter);
            }
            HILOG_DEBUG("JSRegisterHandle::Unregister: registerMap size=%{public}d", static_cast<int32_t>(g_registerMap.size()));
            HILOG_DEBUG("JSRegisterHandle::Unregister: success");
            return response;
        }

        int32_t JSRegisterHandle::UnregisterAll()
        {
            HILOG_DEBUG("JSRegisterHandle::UnregisterAll: enter");
            int32_t response = SUCCESS_CODE;
            auto iter = g_registerMap.begin();
            if (iter != g_registerMap.end()) {
                response = MMIEventHdl.UnregisterStandardizedEventHandle(iter->second.remoteObj,
                    iter->second.winId, iter->second.context->pevent);
                if (response != MMI_STANDARD_EVENT_SUCCESS) {
                    HILOG_ERROR("JSRegisterHandle::UnregisterAll: failed. response=%{public}d", response);
                    return response;
                }
                HILOG_DEBUG("JSRegisterHandle::UnregisterAll: registerHandle=%{public}s", iter->first.c_str());
                g_registerMap.erase(iter);
            }
            HILOG_DEBUG("JSRegisterHandle::UnregisterAll: registerMap size=%{public}d", static_cast<int32_t>(g_registerMap.size()));
            HILOG_DEBUG("JSRegisterHandle::UnregisterAll: success");
            return response;
        }
    }
}

