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

#include <algorithm>
#include <inttypes.h>
#include "input_manager.h"
#include "js_register_util.h"
#include "js_register_module.h"
#include "key_event_pre.h"

namespace OHOS {
namespace MMI {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JSRegisterMoudle" };
}

const uint32_t EVENT_NAME_LEN = 64;
const uint32_t ARGC_SYSTEM_NUM = 3;
const uint32_t ARGV_FIRST = 0;
const uint32_t ARGV_SECOND = 1;
const uint32_t ARGV_THIRD = 2;
const uint32_t PRE_KEYS_SIZE = 4;
// static std::map<std::string, KeyEventMonitorInfo*> g_CallbackInfos;
static std::map<std::string, std::vector<KeyEventMonitorInfo*>> g_CallbackInfos;
CallbackMaps callbackMaps = {};

static napi_value GetEventInfo(napi_env env, napi_callback_info info, KeyEventMonitorInfo* event,
    std::shared_ptr<KeyOption> keyOption)
{
    MMI_LOGD("enter");
    size_t argc = ARGC_SYSTEM_NUM;
    napi_value argv[ARGC_SYSTEM_NUM] = { 0 };
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok) {
        MMI_LOGE("napi_get_cb_info failed");
        return nullptr;
    }
    NAPI_ASSERT(env, argc == ARGC_SYSTEM_NUM, "requires 3 parameter");
    napi_valuetype napi_valuetype1 = {};
    if (napi_typeof(env, argv[ARGV_FIRST], &napi_valuetype1) != napi_ok) {
        MMI_LOGE("napi_typeof failed");
        return nullptr;
    }
    NAPI_ASSERT(env, napi_valuetype1 == napi_string, "parameter1 is not napi_string");
    napi_valuetype napi_valuetype2 = {};
    if (napi_typeof(env, argv[ARGV_SECOND], &napi_valuetype2) != napi_ok) {
        MMI_LOGE("napi_typeof failed");
        return nullptr;
    }
    NAPI_ASSERT(env, napi_valuetype2 == napi_object, "parameter2 is not napi_object");
    napi_valuetype eventHandleType = {};
    if (napi_typeof(env, argv[ARGV_THIRD], &eventHandleType) != napi_ok) {
        MMI_LOGE("napi_typeof failed");
        return nullptr;
    }
    NAPI_ASSERT(env, eventHandleType == napi_function, "parameter2 is not napi_function");
    char eventName[EVENT_NAME_LEN] = { 0 };
    size_t typeLen = 0;
    if (napi_get_value_string_utf8(env, argv[ARGV_FIRST], eventName, EVENT_NAME_LEN - 1, &typeLen) != napi_ok) {
        MMI_LOGE("napi_get_value_string_utf8 failed");
        return nullptr;
    }
    event->name = eventName;
    napi_value receiceValue;
    if (napi_get_named_property(env, argv[ARGV_SECOND], "preKeys", &receiceValue) != napi_ok) {
        MMI_LOGE("napi_get_named_property failed");
        return nullptr;
    }
    std::vector<int32_t> preKeys = GetCppArrayInt(receiceValue, env);
    MMI_LOGD("preKeys size:%{public}d", (int32_t)preKeys.size());
    std::vector<int32_t> sortPrekeys = preKeys;
    sort(sortPrekeys.begin(), sortPrekeys.end());
    keyOption->SetPreKeys(preKeys);

    std::string subKeyNames = "";
    for (const auto &item : sortPrekeys){
        subKeyNames += std::to_string(item);
        subKeyNames += ",";
        MMI_LOGD("preKeys = %{public}d", item);
    }

    int32_t finalKey = GetNamedPropertyInt32(env, argv[ARGV_SECOND], "finalKey");
    subKeyNames += std::to_string(finalKey);
    subKeyNames += ",";
    keyOption->SetFinalKey(finalKey);
    MMI_LOGD("finalKey = %{public}d", finalKey);
    bool isFinalKeyDown = GetNamedPropertyBool(env, argv[ARGV_SECOND], "isFinalKeyDown");
    subKeyNames += std::to_string(isFinalKeyDown);
    subKeyNames += ",";
    keyOption->SetFinalKeyDown(isFinalKeyDown);

    MMI_LOGD("isFinalKeyDown: %{public}d, map_key: %{public}s",
        (isFinalKeyDown == true?1:0), subKeyNames.c_str());

    int32_t finalKeyDownDuriation = GetNamedPropertyInt32(env, argv[ARGV_SECOND], "finalKeyDownDuration");
    napi_get_value_int32(env, receiceValue, &finalKeyDownDuriation);
    subKeyNames += std::to_string(finalKeyDownDuriation);
    keyOption->SetFinalKeyDownDuration(finalKeyDownDuriation);
    event->eventType = subKeyNames;
    MMI_LOGD("finalKeyDownDuriation = %{public}d", finalKeyDownDuriation);

    if (napi_create_reference(env, argv[ARGV_THIRD], 1, &event->callback[0]) != napi_ok) {
        MMI_LOGE("napi_create_reference failed");
        return nullptr;
    }
    napi_value result = {};
    napi_create_int32(env, SUCCESS_CODE, &result);
    MMI_LOGD("end");
    return result;
}

static bool MatchCombinationkeys(KeyEventMonitorInfo* monitorInfo, std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent){
    MMI_LOGD("enter");
    auto keyOption = monitorInfo->keyOption;
    std::vector<int32_t> infoPreKeys = keyOption->GetPreKeys();
    std::vector<KeyEvent::KeyItem> items = keyEvent->GetKeyItems();
    int32_t infoFinalKey = keyOption->GetFinalKey();
    int32_t keyEventFinalKey = keyEvent->GetKeyCode();
    MMI_LOGD("infoFinalKey:%{public}d, keyEventFinalKey:%{public}d", infoFinalKey, keyEventFinalKey);
    if (infoFinalKey != keyEventFinalKey || items.size() > 4) {
        MMI_LOGD("%{public}d", __LINE__);
        return false;
    }
    int32_t infoSize = 0;
    auto it = infoPreKeys.begin();
    while(it != infoPreKeys.end()) {
        if (*it >= 0) {
            infoSize++;
        }
        it++;
    }
    int32_t count = 0;
    for (const auto &item : items) {
        if (item.GetKeyCode() == keyEventFinalKey) {
            continue;
        }
        auto iter = find(infoPreKeys.begin(), infoPreKeys.end(), item.GetKeyCode());
        if (iter == infoPreKeys.end()) {
            return false;
        }
        count++;
    }
    MMI_LOGD("kevEventSize:%{public}d, infoSize:%{public}d", count, infoSize);
    const KeyEvent::KeyItem* keyItem = keyEvent->GetKeyItem();
    if (keyItem == nullptr) {
        MMI_LOGE("Skip, null keyItem");
        return false;
    }

    auto upTime = keyEvent->GetActionTime();
    auto downTime = keyItem->GetDownTime();
    auto curDurtionTime = keyOption->GetFinalKeyDownDuration();
    if (curDurtionTime > 0 && (upTime - downTime >= (curDurtionTime * 1000))) {
        MMI_LOGE("Skip, upTime - downTime >= duration");
        return false;
    }
    return count == infoSize;
}

static void SubKeyEventCallback(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
{
    MMI_LOGD("%{public}s in", __func__);
    auto iter = callbackMaps.begin();
    while (iter != callbackMaps.end()) {
        auto &list = iter->second;
        iter++;
        auto infoIter = list.begin();
        MMI_LOGD("list size:%{public}d", static_cast<int32_t>(list.size()));
        while(infoIter != list.end()) {
            auto monitorInfo = *infoIter;
            if (MatchCombinationkeys(monitorInfo, keyEvent)) {
                monitorInfo->keyEvent = keyEvent;
                monitorInfo->status = 1;
                EmitAsyncCallbackWork(monitorInfo);
            }
            infoIter++;
        }
    }
}

bool CheckPara(std::shared_ptr<KeyOption> keyOption)
{
    std::vector<int32_t> preKeys = keyOption->GetPreKeys();
    if (preKeys.size() > PRE_KEYS_SIZE) {
        MMI_LOGE("preKeys size is bigger than 4, can not process");
        return false;
    } 
    std::vector<int32_t> checkRepeat;
    for (const auto &item : preKeys) {
        if (item < 0) {
            MMI_LOGE("preKey:%{public}d is less 0, can not process", item);
            return false;
        }
        if (std::find(checkRepeat.begin(), checkRepeat.end(), item) != checkRepeat.end()){
            MMI_LOGE("preKey is repeat, can not process");
            return false;
        }
        checkRepeat.push_back(item);
    }
    return true;
}

static napi_value SubscribeKeyEventMonitor(napi_env env, napi_callback_info info)
{
    MMI_LOGD("%{public}s enter", __func__);
    napi_value result;
    if (napi_create_int32(env, MMI_STANDARD_EVENT_INVALID_PARAMETER, &result) != napi_ok) {
        MMI_LOGE("napi_create_int32 failed");
        return nullptr;
    }

    KeyEventMonitorInfo *event = new KeyEventMonitorInfo
    {
        .env = env,
        .asyncWork = nullptr,
    };
    auto keyOption = std::shared_ptr<KeyOption>(new KeyOption());
    if (GetEventInfo(env, info, event, keyOption) == nullptr || !CheckPara(keyOption)) {
        delete event;
        event = nullptr;
        MMI_LOGE("GetEventInfo failed");
        return nullptr;
    }

    event->keyOption = keyOption;
    int32_t preSubscribeId = -1;
    if (AddEventCallback(env, callbackMaps, event, preSubscribeId) < 0 ) {
        delete event;
        event = nullptr;
        MMI_LOGE("AddEventCallback failed");
        return nullptr;
    }

    if (preSubscribeId <= 0) {
        MMI_LOGD("eventType: %{public}s, eventName: %{public}s", event->eventType.c_str(),  event->name.c_str());
        int32_t subscribeId = -1;
        subscribeId = InputManager::GetInstance()->SubscribeKeyEvent(keyOption, SubKeyEventCallback);
        if (subscribeId < 0) {
            MMI_LOGD("subscribeId invalid = %{public}d", subscribeId);
            event->status = -1;
            EmitAsyncCallbackWork(event);
            return nullptr;
        }
        MMI_LOGD("subscribeId = %{public}d", subscribeId);
        event->subscribeId = subscribeId;
    } else {
        event->subscribeId = preSubscribeId;
    }
    int32_t response = MMI_STANDARD_EVENT_SUCCESS;
    if (napi_create_int32(env, response, &result) != napi_ok) {
        MMI_LOGE("napi_create_int32 fail");
        return nullptr;
    }
    MMI_LOGD("%{public}s leave", __func__);
    return result;
}

static napi_value UnsubscribeKeyEventMonitor(napi_env env, napi_callback_info info)
{
    MMI_LOGD("%{public}s enter", __func__);
    napi_value result;
    if (napi_create_int32(env, MMI_STANDARD_EVENT_INVALID_PARAMETER, &result) != napi_ok) {
        MMI_LOGE("napi_create_int32 failed");
        return nullptr;
    }

    KeyEventMonitorInfo *event = new KeyEventMonitorInfo
    {
        .env = env,
        .asyncWork = nullptr,
    };
    auto keyOption = std::shared_ptr<KeyOption>(new KeyOption());
    if (GetEventInfo(env, info, event, keyOption) == nullptr) {
        MMI_LOGE("GetEventInfo failed");
        return result;
    }
    int32_t subscribeId = -1;
    if (DelEventCallback(env, callbackMaps, event, subscribeId) < 0) {
        delete event;
        event = nullptr;
        MMI_LOGE("DelEventCallback failed");
        return result;
    }

    int32_t response = MMI_STANDARD_EVENT_INVALID_PARAMETER;
    MMI_LOGD("in for remove subscribeId = %{public}d", subscribeId);
    if (subscribeId >= 0) {
        InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId);
    }
    event->status = 0;
    EmitAsyncCallbackWork(event);
    if (napi_create_int32(env, response, &result) != napi_ok) {
        MMI_LOGE("napi_create_int32 fail");
        return nullptr;
    }
    MMI_LOGD("%{public}s end", __func__);
    return result;
}

EXTERN_C_START
static napi_value MmiInit(napi_env env, napi_value exports)
{
    MMI_LOGD("enter");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("on", SubscribeKeyEventMonitor),
        DECLARE_NAPI_FUNCTION("off", UnsubscribeKeyEventMonitor),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    MMI_LOGD("success");
    return exports;
}
EXTERN_C_END

static napi_module mmiModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = MmiInit,
    .nm_modname = "inputConsumer",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&mmiModule);
}
}
}

