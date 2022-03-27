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

#include <algorithm>
#include <cinttypes>

#include "input_manager.h"
#include "js_register_util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JSRegisterMoudle" };
constexpr size_t EVENT_NAME_LEN = 64;
constexpr size_t PRE_KEYS_SIZE = 4;
} // namespace

static Callbacks callbacks = {};

int32_t GetEventInfo(napi_env env, napi_callback_info info, KeyEventMonitorInfo* event,
    std::shared_ptr<KeyOption> keyOption)
{
    CALL_LOG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    CHKPR(keyOption, ERROR_NULL_POINTER);
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok) {
        MMI_HILOGE("Get param failed");
        napi_throw_error(env, nullptr, "Get param failed");
        return ERROR_CODE;
    }
    if (argc != 2 && argc != 3) {
        MMI_HILOGE("Requires 3 parameter");
        napi_throw_error(env, nullptr, "Requires 3 parameter");
        return ERROR_CODE;
    }
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[0], &valueType) != napi_ok) {
        MMI_HILOGE("Get type of first param failed");
        napi_throw_error(env, nullptr, "Get type of first param failed");
        return ERROR_CODE;
    }
    if (valueType != napi_string) {
        MMI_HILOGE("Parameter1 is not napi_string");
        napi_throw_error(env, nullptr, "Parameter1 is not napi_string");
        return ERROR_CODE;
    }
    if (napi_typeof(env, argv[1], &valueType) != napi_ok) {
        MMI_HILOGE("Get type of second param failed");
        napi_throw_error(env, nullptr, "Get type of second param failed");
        return ERROR_CODE;
    }
    if (valueType != napi_object) {
        MMI_HILOGE("Parameter2 is not napi_object");
        napi_throw_error(env, nullptr, "Parameter2 is not napi_object");
        return ERROR_CODE;
    }
    char eventName[EVENT_NAME_LEN] = { 0 };
    size_t typeLen = 0;
    if (napi_get_value_string_utf8(env, argv[0], eventName, EVENT_NAME_LEN - 1, &typeLen) != napi_ok) {
        MMI_HILOGE("Get value of first param failed");
        napi_throw_error(env, nullptr, "Get value of first param failed");
        return ERROR_CODE;
    }
    event->name = eventName;
    napi_value receiceValue = nullptr;
    if (napi_get_named_property(env, argv[1], "preKeys", &receiceValue) != napi_ok) {
        MMI_HILOGE("Get preKeys failed");
        napi_throw_error(env, nullptr, "Get preKeys failed");
        return ERROR_CODE;
    }
    std::set<int32_t> preKeys;
    if (!GetPreKeys(env, receiceValue, preKeys)) {
        MMI_HILOGE("Get preKeys failed");
        return ERROR_CODE;
    }
    if (preKeys.size() > PRE_KEYS_SIZE) {
        MMI_HILOGE("PreKeys size invalid");
        napi_throw_error(env, nullptr, "PreKeys size invalid");
        return ERROR_CODE;
    }
    MMI_HILOGD("PreKeys size:%{public}d", static_cast<int32_t>(preKeys.size()));
    keyOption->SetPreKeys(preKeys);
    std::string subKeyNames = "";
    for (const auto &item : preKeys) {
        subKeyNames += std::to_string(item);
        subKeyNames += ",";
        MMI_HILOGD("preKeys:%{public}d", item);
    }
    int32_t finalKey = GetNamedPropertyInt32(env, argv[1], "finalKey");
    subKeyNames += std::to_string(finalKey);
    subKeyNames += ",";
    keyOption->SetFinalKey(finalKey);
    MMI_HILOGD("FinalKey:%{public}d", finalKey);
    bool isFinalKeyDown = GetNamedPropertyBool(env, argv[1], "isFinalKeyDown");
    subKeyNames += std::to_string(isFinalKeyDown);
    subKeyNames += ",";
    keyOption->SetFinalKeyDown(isFinalKeyDown);
    MMI_HILOGD("IsFinalKeyDown:%{public}d,map_key:%{public}s",
        (isFinalKeyDown == true?1:0), subKeyNames.c_str());
    int32_t finalKeyDownDuriation = GetNamedPropertyInt32(env, argv[1], "finalKeyDownDuration");
    subKeyNames += std::to_string(finalKeyDownDuriation);
    keyOption->SetFinalKeyDownDuration(finalKeyDownDuriation);
    event->eventType = subKeyNames;
    MMI_HILOGD("FinalKeyDownDuriation:%{public}d", finalKeyDownDuriation);
    if (argc == 3) {
        if (napi_typeof(env, argv[2], &valueType) != napi_ok) {
            MMI_HILOGE("Get type of third param failed");
            napi_throw_error(env, nullptr, "Get type of third param failed");
            return ERROR_CODE;
        }
        if (valueType != napi_function) {
            MMI_HILOGE("Parameter3 is not napi_function");
            napi_throw_error(env, nullptr, "Parameter3 is not napi_function");
            return ERROR_CODE;
        }
        if (napi_create_reference(env, argv[2], 1, &event->callback[0]) != napi_ok) {
            MMI_HILOGE("Event create reference failed");
            napi_throw_error(env, nullptr, "Event create reference failed");
            return ERROR_CODE;
        }
    } else {
        event->callback[0] = nullptr;
    }
    return SUCCESS_CODE;
}

static bool MatchCombinationkeys(KeyEventMonitorInfo* monitorInfo, std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_LOG_ENTER;
    CHKPF(monitorInfo);
    CHKPF(keyEvent);
    auto keyOption = monitorInfo->keyOption;
    CHKPF(keyOption);
    std::vector<KeyEvent::KeyItem> items = keyEvent->GetKeyItems();
    int32_t infoFinalKey = keyOption->GetFinalKey();
    int32_t keyEventFinalKey = keyEvent->GetKeyCode();
    MMI_HILOGD("infoFinalKey:%{public}d,keyEventFinalKey:%{public}d", infoFinalKey, keyEventFinalKey);
    if (infoFinalKey != keyEventFinalKey || items.size() > PRE_KEYS_SIZE) {
        MMI_HILOGE("param invalid");
        return false;
    }
    std::set<int32_t> infoPreKeys = keyOption->GetPreKeys();
    int32_t infoSize = 0;
    auto it = infoPreKeys.begin();
    while (it != infoPreKeys.end()) {
        if (*it >= 0) {
            infoSize++;
        }
        ++it;
    }
    int32_t count = 0;
    for (const auto &item : items) {
        if (item.GetKeyCode() == keyEventFinalKey) {
            continue;
        }
        auto iter = find(infoPreKeys.begin(), infoPreKeys.end(), item.GetKeyCode());
        if (iter == infoPreKeys.end()) {
            MMI_HILOGD("No keyCode in preKeys");
            return false;
        }
        count++;
    }
    MMI_HILOGD("kevEventSize:%{public}d,infoSize:%{public}d", count, infoSize);
    auto keyItem = keyEvent->GetKeyItem();
    CHKPF(keyItem);
    auto upTime = keyEvent->GetActionTime();
    auto downTime = keyItem->GetDownTime();
    auto curDurtionTime = keyOption->GetFinalKeyDownDuration();
    if (curDurtionTime > 0 && (upTime - downTime >= (static_cast<int64_t>(curDurtionTime) * 1000))) {
        MMI_HILOGE("Skip, upTime - downTime >= duration");
        return false;
    }
    return count == infoSize;
}

static void SubKeyEventCallback(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_LOG_ENTER;
    CHKPV(keyEvent);
    auto iter = callbacks.begin();
    while (iter != callbacks.end()) {
        auto &list = iter->second;
        ++iter;
        MMI_HILOGD("list size:%{public}zu", list.size());
        auto infoIter = list.begin();
        while (infoIter != list.end()) {
            auto monitorInfo = *infoIter;
            if (MatchCombinationkeys(monitorInfo, keyEvent)) {
                monitorInfo->keyEvent = keyEvent;
                EmitAsyncCallbackWork(monitorInfo);
            }
            ++infoIter;
        }
    }
}

static napi_value JsOn(napi_env env, napi_callback_info info)
{
    CALL_LOG_ENTER;
    KeyEventMonitorInfo *event = new (std::nothrow) KeyEventMonitorInfo {
        .env = env,
        .asyncWork = nullptr,
    };
    CHKPP(event);
    auto keyOption = std::make_shared<KeyOption>();
    CHKPP(keyOption);
    if (GetEventInfo(env, info, event, keyOption) < 0) {
        delete event;
        event = nullptr;
        MMI_HILOGE("GetEventInfo failed");
        return nullptr;
    }
    event->keyOption = keyOption;
    int32_t preSubscribeId = GetPreSubscribeId(callbacks, event);
    if (preSubscribeId < 0) {
        MMI_HILOGD("eventType:%{public}s,eventName:%{public}s", event->eventType.c_str(),  event->name.c_str());
        int32_t subscribeId = -1;
        subscribeId = InputManager::GetInstance()->SubscribeKeyEvent(keyOption, SubKeyEventCallback);
        if (subscribeId < 0) {
            MMI_HILOGD("subscribeId invalid:%{public}d", subscribeId);
            napi_delete_reference(env, event->callback[0]);
            delete event;
            event = nullptr;
            return nullptr;
        }
        MMI_HILOGD("SubscribeId:%{public}d", subscribeId);
        event->subscribeId = subscribeId;
    } else {
        event->subscribeId = preSubscribeId;
    }
    if (AddEventCallback(env, callbacks, event) < 0) {
        delete event;
        event = nullptr;
        MMI_HILOGE("AddEventCallback failed");
        return nullptr;
    }
    return nullptr;
}

static napi_value JsOff(napi_env env, napi_callback_info info)
{
    CALL_LOG_ENTER;
    KeyEventMonitorInfo *event = new (std::nothrow) KeyEventMonitorInfo {
        .env = env,
        .asyncWork = nullptr,
    };
    CHKPP(event);
    auto keyOption = std::make_shared<KeyOption>();
    CHKPP(keyOption);
    if (GetEventInfo(env, info, event, keyOption) < 0) {
        delete event;
        event = nullptr;
        MMI_HILOGE("GetEventInfo failed");
        return nullptr;
    }
    int32_t subscribeId = -1;
    if (DelEventCallback(env, callbacks, event, subscribeId) < 0) {
        delete event;
        event = nullptr;
        MMI_HILOGE("DelEventCallback failed");
        return nullptr;
    }
    MMI_HILOGD("SubscribeId:%{public}d", subscribeId);
    if (subscribeId >= 0) {
        InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId);
    }
    if (event->callback[0] != nullptr) {
        napi_delete_reference(env, event->callback[0]);
    }
    delete event;
    event = nullptr;
    return nullptr;
}

EXTERN_C_START
static napi_value MmiInit(napi_env env, napi_value exports)
{
    CALL_LOG_ENTER;
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("on", JsOn),
        DECLARE_NAPI_FUNCTION("off", JsOff),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
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
} // namespace MMI
} // namespace OHOS
