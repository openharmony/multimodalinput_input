 /*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "input_consumer.h"
#include <iostream>

#include "define_multimodal.h"
#include "napi_constants.h"
#include "mmi_log.h"
#include "input_manager.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AniInputConsumer"

using namespace OHOS::MMI;

namespace {
constexpr int32_t ANI_SCOPE_SIZE = 16;
constexpr int32_t MILLISECOND_FACTOR = 1000;
constexpr size_t EVENT_NAME_LEN { 64 };
constexpr size_t PRE_KEYS_SIZE { 4 };
constexpr size_t INPUT_PARAMETER_MIDDLE { 2 };
constexpr size_t INPUT_PARAMETER_MAX { 3 };
constexpr int32_t OCCUPIED_BY_SYSTEM = -3;
constexpr int32_t OCCUPIED_BY_OTHER = -4;
const double INT32_MAX_D = static_cast<double>(std::numeric_limits<int32_t>::max());
} // namespace

static Callbacks callbacks = {};
static Callbacks hotkeyCallbacks = {};
std::mutex sCallBacksMutex;
static const std::vector<int32_t> pressKeyCodes = {
    KeyEvent::KEYCODE_ALT_LEFT,
    KeyEvent::KEYCODE_ALT_RIGHT,
    KeyEvent::KEYCODE_SHIFT_LEFT,
    KeyEvent::KEYCODE_SHIFT_RIGHT,
    KeyEvent::KEYCODE_CTRL_LEFT,
    KeyEvent::KEYCODE_CTRL_RIGHT
};
static const std::vector<int32_t> finalKeyCodes = {
    KeyEvent::KEYCODE_ALT_LEFT,
    KeyEvent::KEYCODE_ALT_RIGHT,
    KeyEvent::KEYCODE_SHIFT_LEFT,
    KeyEvent::KEYCODE_SHIFT_RIGHT,
    KeyEvent::KEYCODE_CTRL_LEFT,
    KeyEvent::KEYCODE_CTRL_RIGHT,
    KeyEvent::KEYCODE_META_LEFT,
    KeyEvent::KEYCODE_META_RIGHT
};

static ani_error CreateAniError(ani_env *env, std::string &&errMsg)
{
    static const char *errorClsName = "Lescompat/Error;";
    ani_class cls {};
    if (ANI_OK != env->FindClass(errorClsName, &cls)) {
        MMI_HILOGE("%{public}s: Not found namespace %{public}s.", __func__, errorClsName);
        return nullptr;
    }
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "Lstd/core/String;:V", &ctor)) {
        MMI_HILOGE("%{public}s: Not found <ctor> in %{public}s.", __func__, errorClsName);
        return nullptr;
    }
    ani_string error_msg;
    env->String_NewUTF8(errMsg.c_str(), 17U, &error_msg);
    ani_object errorObject;
    env->Object_New(cls, ctor, &errorObject, error_msg);
    return static_cast<ani_error>(errorObject);
}

static std::optional<bool> GetIsRepeat(ani_env *env, ani_object keyOptionsObj)
{
    ani_ref aniRef;
    if (ANI_OK != env->Object_GetPropertyByName_Ref(keyOptionsObj, "isRepeat", &aniRef)) {
        MMI_HILOGE("%{public}s: Object_GetPropertyByName_Ref isRepeat failed.", __func__);
        return std::nullopt;
    }

    ani_boolean isUndefined;
    if (ANI_OK != env->Reference_IsUndefined(aniRef, &isUndefined)) {
        MMI_HILOGE("%{public}s: Object_GetFieldByName_Ref isRepeat failed.", __func__);
        return std::nullopt;
    }

    if (isUndefined) {
        MMI_HILOGE("%{public}s: Param 'isRepeat' is undefined.", __func__);
        return std::nullopt;
    }

    ani_boolean isRepeat;
    auto ret = env->Object_CallMethodByName_Boolean(static_cast<ani_object>(aniRef), "unboxed", nullptr, &isRepeat);
    if (ret != ANI_OK) {
        MMI_HILOGE("%{public}s: Object_CallMethodByName_Boolean failed.", __func__);
        return std::nullopt;
    }
    return static_cast<bool>(isRepeat);
}

static std::string AniStringToString(ani_env *env, ani_string ani_str)
{
    ani_size strSize;
    env->String_GetUTF8Size(ani_str, &strSize);

    std::vector<char> buffer(strSize + 1);
    char* utf8Buffer = buffer.data();

    ani_size bytes_written = 0;
    env->String_GetUTF8(ani_str, utf8Buffer, strSize + 1, &bytes_written);

    utf8Buffer[bytes_written] = '\0';
    std::string content = std::string(utf8Buffer);
    return content;
}

static bool GetPreKeys(ani_env *env, ani_object keyOptionsObj, std::set<int32_t> &preKeys)
{
    ani_ref ref;
    if (ANI_OK != env->Object_GetPropertyByName_Ref(keyOptionsObj, "preKeys", &ref)) {
        MMI_HILOGE("Object_GetPropertyByName_Ref Failed");
        return false;
    }
    ani_object arrayObj = static_cast<ani_object>(ref);
    ani_double length;
    if (ANI_OK != env->Object_GetPropertyByName_Double(arrayObj, "length", &length)) {
        MMI_HILOGE("Object_GetPropertyByName_Double length Failed");
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref IntArrayRef;
        if (ANI_OK != env->Object_CallMethodByName_Ref(arrayObj, "$_get", "I:Lstd/core/Object;", &IntArrayRef,
            (ani_int)i)) {
            MMI_HILOGE("Object_GetPropertyByName_Ref Failed");
            return false;
        }
        ani_double doubleEntry;
        if (ANI_OK != env->Object_CallMethodByName_Double(static_cast<ani_object>(IntArrayRef), "unboxed", nullptr,
            &doubleEntry)) {
            MMI_HILOGE("Object_CallMethodByName_Double unbox Failed");
            return false;
        }
        if (doubleEntry > INT32_MAX_D || doubleEntry < 0) {
            ani_error error = CreateAniError(env, "preKeys must be between 0 and INT32_MAX");
            env->ThrowError(error);
            MMI_HILOGE("preKey:%{public}f is less 0 or greater than INT32_MAX, can not process", doubleEntry);
            return false;
        }
        if (!preKeys.insert(static_cast<int32_t>(doubleEntry)).second) {
            MMI_HILOGE("Params insert value failed");
            return false;
        }
    }
    return true;
}

static std::shared_ptr<KeyOption> ParsekeyOptions(ani_env *env, ani_object keyOptionsObj, std::string &subKeyNames)
{
    std::shared_ptr<KeyOption> keyOptionPtr = std::make_shared<KeyOption>();

    std::set<int32_t> preKeys;
    if (!GetPreKeys(env, keyOptionsObj, preKeys) || preKeys.size() > PRE_KEYS_SIZE) {
        MMI_HILOGE("PreKeys is invalid");
        return nullptr;
    }
    keyOptionPtr->SetPreKeys(preKeys);
    for (const auto &preKey : preKeys) {
        subKeyNames = subKeyNames + std::to_string(preKey) + ",";
    }

    ani_double finalKey;
    if (ANI_OK != env->Object_GetPropertyByName_Double(keyOptionsObj, "finalKey", &finalKey)) {
        MMI_HILOGE("Object_GetPropertyByName_Double finalKey Failed");
        return nullptr;
    }
    if (finalKey > INT32_MAX_D || finalKey < 0) {
        MMI_HILOGE("finalKey:%{private}f is less 0 or greater than INT32_MAX, can not process", finalKey);
        return nullptr;
    }
    keyOptionPtr->SetFinalKey(static_cast<int32_t>(finalKey));
    subKeyNames = subKeyNames + std::to_string(static_cast<int32_t>(finalKey)) + ",";

    ani_boolean isFinalKeyDown;
    if (ANI_OK != env->Object_GetPropertyByName_Boolean(keyOptionsObj, "isFinalKeyDown", &isFinalKeyDown)) {
        MMI_HILOGE("Object_GetPropertyByName_Boolean isFinalKeyDown Failed");
        return nullptr;
    }
    keyOptionPtr->SetFinalKeyDown(static_cast<bool>(isFinalKeyDown));
    subKeyNames = subKeyNames + std::to_string(isFinalKeyDown) + ",";

    ani_double finalKeyDownDuration;
    if (ANI_OK != env->Object_GetPropertyByName_Double(keyOptionsObj, "finalKeyDownDuration", &finalKeyDownDuration)) {
        MMI_HILOGE("Object_GetPropertyByName_Double finalKeyDownDuration Failed");
        return nullptr;
    }
    if (finalKeyDownDuration > INT32_MAX_D || finalKeyDownDuration < 0) {
        MMI_HILOGE("finalKeyDownDuration:%{public}f is less 0 or greater INT32_MAX", finalKeyDownDuration);
        return nullptr;
    }
    keyOptionPtr->SetFinalKeyDownDuration(static_cast<int32_t>(finalKeyDownDuration));
    subKeyNames = subKeyNames + std::to_string(static_cast<int32_t>(finalKeyDownDuration)) + ",";

    bool isRepeat = true;
    auto isRepeatOpt = GetIsRepeat(env, keyOptionsObj);
    if (isRepeatOpt.has_value()) {
        isRepeat = isRepeatOpt.value();
    }
    keyOptionPtr->SetRepeat(isRepeat);
    subKeyNames += std::to_string(isRepeat);

    return keyOptionPtr;
}

static bool IsMatchKeyAction(bool isFinalKeydown, int32_t keyAction)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("isFinalKeydown:%{public}d, keyAction:%{public}d", isFinalKeydown, keyAction);
    if (isFinalKeydown && keyAction == KeyEvent::KEY_ACTION_DOWN) {
        return true;
    }
    if (!isFinalKeydown && keyAction == KeyEvent::KEY_ACTION_UP) {
        return true;
    }
    MMI_HILOGE("isFinalKeydown not matched with keyAction");
    return false;
}

static bool MatchCombinationKey(std::shared_ptr<KeyEventMonitorInfo> monitorInfo, std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(monitorInfo);
    CHKPF(keyEvent);
    auto keyOption = monitorInfo->keyOption;
    std::vector<KeyEvent::KeyItem> items = keyEvent->GetKeyItems();
    int32_t infoFinalKey = keyOption->GetFinalKey();
    int32_t keyEventFinalKey = keyEvent->GetKeyCode();
    bool isFinalKeydown = keyOption->IsFinalKeyDown();
    MMI_HILOGD("InfoFinalKey:%{public}d,keyEventFinalKey:%{public}d,isFinalKeydown:%{public}d",
        infoFinalKey, keyEventFinalKey, isFinalKeydown);
    if (infoFinalKey != keyEventFinalKey || items.size() > PRE_KEYS_SIZE ||
        !IsMatchKeyAction(isFinalKeydown, keyEvent->GetKeyAction())) {
        MMI_HILOGD("key Param invalid");
        return false;
    }
    std::set<int32_t> infoPreKeys = keyOption->GetPreKeys();
    int32_t infoSize = 0;
    for (auto it = infoPreKeys.begin(); it != infoPreKeys.end(); ++it) {
        if (*it >= 0) {
            infoSize++;
        }
    }
    int32_t count = 0;
    for (const auto &item : items) {
        if (item.GetKeyCode() == keyEventFinalKey) {
            continue;
        }
        auto iter = find(infoPreKeys.begin(), infoPreKeys.end(), item.GetKeyCode());
        if (iter == infoPreKeys.end()) {
            MMI_HILOGW("No keyCode in preKeys");
            return false;
        }
        count++;
    }
    MMI_HILOGD("kevEventSize:%{public}d, infoSize:%{public}d", count, infoSize);
    std::optional<KeyEvent::KeyItem> keyItem = keyEvent->GetKeyItem();
    if (!keyItem) {
        MMI_HILOGE("The keyItem is nullopt");
        return false;
    }
    auto downTime = keyItem->GetDownTime();
    auto upTime = keyEvent->GetActionTime();
    auto curDurationTime = keyOption->GetFinalKeyDownDuration();
    if (curDurationTime > 0 && (upTime - downTime >= (static_cast<int64_t>(curDurationTime) * MILLISECOND_FACTOR))) {
        MMI_HILOGE("Skip, upTime - downTime >= duration");
        return false;
    }
    return count == infoSize;
}

static bool SendEventToMainThread(const std::function<void()> func)
{
    CALL_DEBUG_ENTER;
    if (func == nullptr) {
        MMI_HILOGE("%{public}s: func == nullptr", __func__);
        return false;
    }
    std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
    if (!runner) {
        MMI_HILOGE("%{public}s: runner == nullptr", __func__);
        return false;
    }
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    handler->PostTask(func, "", 0, OHOS::AppExecFwk::EventQueue::Priority::HIGH, {});
    MMI_HILOGD("%{public}s: PostTask success", __func__);
    return true;
}

static ani_boolean IsInstanceOf(ani_env *env, const std::string &cls_name, ani_object obj)
{
    ani_class cls;
    if (ANI_OK != env->FindClass(cls_name.c_str(), &cls)) {
        MMI_HILOGE("%{public}s: FindClass failed", __func__);
        return ANI_FALSE;
    }

    ani_boolean ret;
    env->Object_InstanceOf(obj, cls, &ret);
    return ret;
}

static void EmitAsyncCallbackWork(std::shared_ptr<KeyEventMonitorInfo> reportEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(reportEvent);
    auto task = [reportEvent]() {
        MMI_HILOGD("%{public}s: Begin to call task", __func__);
        ani_size nr_refs = ANI_SCOPE_SIZE;
        if (ANI_OK != reportEvent->env->CreateLocalScope(nr_refs)) {
            MMI_HILOGE("%{public}s: CreateLocalScope failed", __func__);
            return;
        }
        auto fnObj = reinterpret_cast<ani_fn_object>(reportEvent->callback);
        std::vector<ani_ref> args = {reportEvent->keyOptionsObj};
        ani_ref result;
        MMI_HILOGD("%{public}s: Begin to call FunctionalObject_Call", __func__);
        if (fnObj == nullptr || args.size() == 0) {
            MMI_HILOGE("%{public}s: fnObj == nullptr", __func__);
            return;
        }
        if (IsInstanceOf(reportEvent->env, "Lstd/core/Function1;", fnObj) == 0) {
            MMI_HILOGE("%{public}s: fnObj is not instance Of function  ", __func__);
            return;
        }
        const std::string className = "L@ohos/multimodalInput/inputConsumer/inputConsumer/KeyOptions;";
        if (IsInstanceOf(reportEvent->env, className, static_cast<ani_object>(reportEvent->keyOptionsObj)) == 0) {
            MMI_HILOGE("%{public}s: keyOptionsObj is not instance Of KeyOptions class", __func__);
            return;
        }

        if (ANI_OK != reportEvent->env->FunctionalObject_Call(fnObj, 1, args.data(), &result)) {
            MMI_HILOGE("%{public}s: FunctionalObject_Call failed", __func__);
            return;
        }
        MMI_HILOGD("%{public}s: FunctionalObject_Call success", __func__);
        reportEvent->env->DestroyLocalScope();
    };
    if (!SendEventToMainThread(task)) {
        MMI_HILOGE("%{public}s: failed to send event", __func__);
    }
}

static void SubKeyEventCallback(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    std::lock_guard guard(sCallBacksMutex);
    auto iter = callbacks.begin();
    while (iter != callbacks.end()) {
        auto &list = iter->second;
        ++iter;
        MMI_HILOGD("list size:%{public}zu", list.size());
        auto infoIter = list.begin();
        while (infoIter != list.end()) {
            auto monitorInfo = *infoIter;
            if (MatchCombinationKey(monitorInfo, keyEvent)) {
                MMI_HILOGD("MatchCombinationKey success");
                EmitAsyncCallbackWork(monitorInfo);
            }
            ++infoIter;
        }
    }
}

static int32_t GetPreSubscribeId(const std::shared_ptr<KeyEventMonitorInfo> &event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    std::lock_guard guard(sCallBacksMutex);
    auto it = callbacks.find(event->eventType);
    if (it == callbacks.end() || it->second.empty()) {
        MMI_HILOGE("The callbacks is empty");
        return JS_CALLBACK_EVENT_FAILED;
    }
    CHKPR(it->second.front(), ERROR_NULL_POINTER);
    return it->second.front()->subscribeId;
}

static bool CheckCallbackEqual(ani_env *env, ani_ref fnRef, ani_env *iterEnv, ani_ref iterFn)
{
    if (env != iterEnv) {
        MMI_HILOGD("%{public}s: not the same env", __func__);
        return false;
    }
    ani_boolean isEquals = false;
    if (ANI_OK != env->Reference_StrictEquals(fnRef, iterFn, &isEquals)) {
        MMI_HILOGD("%{public}s: check observer equal failed!", __func__);
        return false;
    }
    return isEquals;
}

static int32_t AddEventCallback(std::shared_ptr<KeyEventMonitorInfo> event)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(sCallBacksMutex);
    CHKPR(event, ERROR_NULL_POINTER);
    if (callbacks.find(event->eventType) == callbacks.end()) {
        MMI_HILOGD("No callback in %{public}s", event->eventType.c_str());
        callbacks[event->eventType] = {};
    }

    auto it = callbacks.find(event->eventType);
    for (const auto &iter: it->second) {
        if (CheckCallbackEqual(event->env, event->callback, iter->env, iter->callback)) {
            MMI_HILOGE("Callback already exist");
            return JS_CALLBACK_EVENT_FAILED;
        }
    }
    it->second.push_back(event);
    return JS_CALLBACK_EVENT_SUCCESS;
}

static int32_t SubscribeKey(ani_env *env, std::shared_ptr<KeyEventMonitorInfo> &event)
{
    CALL_DEBUG_ENTER;
    std::string subKeyNames = "";
    auto keyOptionsPtr = ParsekeyOptions(env, static_cast<ani_object>(event->keyOptionsObj), subKeyNames);
    if (keyOptionsPtr == nullptr) {
        MMI_HILOGE("keyOptionsPtr is nullptr");
        return -1;
    }
    event->keyOption = keyOptionsPtr;
    event->eventType = subKeyNames;

    int32_t preSubscribeId = GetPreSubscribeId(event);
    if (preSubscribeId < 0) {
        MMI_HILOGD("EventType:%{private}s, eventName:%{public}s", event->eventType.c_str(), event->name.c_str());
        int32_t subscribeId = -1;
        subscribeId = InputManager::GetInstance()->SubscribeKeyEvent(event->keyOption, SubKeyEventCallback);
        if (subscribeId < 0) {
            MMI_HILOGE("SubscribeId invalid:%{public}d", subscribeId);
            return subscribeId;
        }
        MMI_HILOGD("SubscribeId:%{public}d", subscribeId);
        event->subscribeId = subscribeId;
    } else {
        event->subscribeId = preSubscribeId;
    }

    return AddEventCallback(event);
}

static void On([[maybe_unused]] ani_env *env, ani_string strObj, ani_object keyOptionsObj, ani_object callback)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEventMonitorInfo> event = std::make_shared<KeyEventMonitorInfo>();
    event->env = env;
    if (ANI_OK != env->GlobalReference_Create(callback, &event->callback)) {
        MMI_HILOGE("Create callback failed");
        return;
    }
    if (ANI_OK != env->GlobalReference_Create(keyOptionsObj, &event->keyOptionsObj)) {
        MMI_HILOGE("Create callback failed");
        return;
    }

    std::string keyType = AniStringToString(env, strObj);
    event->name = keyType;

    if (keyType == HOTKEY_SUBSCRIBE_TYPE) {
        MMI_HILOGD("%{public}s: Enter Hotkey.", __func__);
    } else if (keyType == SUBSCRIBE_TYPE) {
        int32_t ret = SubscribeKey(env, event);
        MMI_HILOGD("%{public}s: Call SubscribeKey end ret = %{public}d", __func__, ret);
    } else {
        MMI_HILOGE("Type is not key or hotkey");
        ani_error error = CreateAniError(env, "Type must be key or hotkeyChange");
        env->ThrowError(error);
    }
}

static int32_t DelEventCallbackRef(ani_env *env, std::list<std::shared_ptr<KeyEventMonitorInfo>> &info,
    ani_ref handler, int32_t &subscribeId)
{
    CALL_DEBUG_ENTER;
    for (auto iter = info.begin(); iter != info.end();) {
        if (*iter == nullptr) {
            info.erase(iter++);
            continue;
        }
        if (handler != nullptr) {
            if (!CheckCallbackEqual(env, handler, (*iter)->env, (*iter)->callback)) {
                ++iter;
                continue;
            }
            std::shared_ptr<KeyEventMonitorInfo> monitorInfo = *iter;
            info.erase(iter++);
            if (info.empty()) {
                subscribeId = monitorInfo->subscribeId;
            }
            MMI_HILOGD("Callback has deleted, size:%{public}zu", info.size());
            return JS_CALLBACK_EVENT_SUCCESS;
        }
        std::shared_ptr<KeyEventMonitorInfo> monitorInfo = *iter;
        info.erase(iter++);
        if (info.empty()) {
            subscribeId = monitorInfo->subscribeId;
        }
        MMI_HILOGD("Callback has deleted, size:%{public}zu", info.size());
    }
    MMI_HILOGD("Callback size:%{public}zu", info.size());
    return JS_CALLBACK_EVENT_SUCCESS;
}

static int32_t DelEventCallback(std::shared_ptr<KeyEventMonitorInfo> &event, int32_t &subscribeId)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(sCallBacksMutex);
    CHKPR(event, ERROR_NULL_POINTER);
    if (callbacks.count(event->eventType) <= 0) {
        MMI_HILOGE("Callback doesn't exists, eventType:%{private}s", event->eventType.c_str());
        return JS_CALLBACK_EVENT_FAILED;
    }
    auto &info = callbacks[event->eventType];
    MMI_HILOGD("EventType:%{public}s, keyEventMonitorInfos:%{public}zu", event->eventType.c_str(), info.size());

    return DelEventCallbackRef(event->env, info, event->callback, subscribeId);
}

static void Off([[maybe_unused]] ani_env *env, ani_string strObj, ani_object keyOptionsObj, ani_object callback)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEventMonitorInfo> event = std::make_shared<KeyEventMonitorInfo>();
    event->env = env;
    if (ANI_OK != env->GlobalReference_Create(keyOptionsObj, &event->keyOptionsObj)) {
        MMI_HILOGE("Call GlobalReference_Create failed");
        return;
    }

    ani_boolean isUndefined;
    if (ANI_OK != env->Reference_IsUndefined(callback, &isUndefined)) {
        MMI_HILOGE("Call Reference_IsUndefined failed");
        return;
    }
    if (isUndefined) {
        MMI_HILOGD("%{public}s: callback is undefined", __func__);
        event->callback = nullptr;
    } else {
        if (ANI_OK != env->GlobalReference_Create(callback, &event->callback)) {
            MMI_HILOGE("Create callback failed");
            return;
        }
    }

    std::string keyType = AniStringToString(env, strObj);
    event->name = keyType;
    int32_t subscribeId = -1;
    if (keyType == HOTKEY_SUBSCRIBE_TYPE) {
        MMI_HILOGD("%{public}s: Enter Hotkey.", __func__);
    } else if (keyType == SUBSCRIBE_TYPE) {
        std::string subKeyNames = "";
        auto keyOptionsPtr = ParsekeyOptions(env, static_cast<ani_object>(event->keyOptionsObj), subKeyNames);
        if (keyOptionsPtr == nullptr) {
            MMI_HILOGE("%{public}s: ParsekeyOptions failed", __func__);
            return;
        }
        event->keyOption = keyOptionsPtr;
        event->eventType = subKeyNames;
        if (DelEventCallback(event, subscribeId) < 0) {
            MMI_HILOGE("DelEventCallback failed");
            return;
        }
        MMI_HILOGI("Unsubscribe key event(%{public}d)", subscribeId);
        InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId);
    } else {
        MMI_HILOGE("Type is not key or hotkey");
        ani_error error = CreateAniError(env, "Type must be key or hotkeyChange");
        env->ThrowError(error);
    }
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        MMI_HILOGE("%{public}s: Unsupported ANI_VERSION_1", __func__);
        return ANI_ERROR;
    }

    static const char *name = "L@ohos/multimodalInput/inputConsumer/inputConsumer;";
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(name, &ns)) {
        MMI_HILOGE("%{public}s: Not found %{public}s", __func__, name);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function {"on", nullptr, reinterpret_cast<void *>(On)},
        ani_native_function {"off", nullptr, reinterpret_cast<void *>(Off)},
    };

    if (ANI_OK != env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size())) {
        MMI_HILOGE("%{public}s:Cannot bind native methods to '%{public}s'", __func__, name);
        return ANI_ERROR;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}