/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef JS_REGISTER_MODULE_H
#define JS_REGISTER_MODULE_H

#include <list>

#include "napi/native_node_api.h"

#include "define_multimodal.h"
#include "key_event.h"
#include "key_option.h"

#define SUCCESS_CODE 0
#define ERROR_CODE (-1)
#define UNREGISTERED_CODE (-2)
#define PRE_KEY_MAX_COUNT 4

enum JS_CALLBACK_EVENT {
    JS_CALLBACK_EVENT_FAILED = -1,
    JS_CALLBACK_EVENT_SUCCESS = 1,
    JS_CALLBACK_EVENT_EXIST = 2,
    JS_CALLBACK_EVENT_NOT_EXIST = 3,
};

namespace OHOS {
namespace MMI {
extern std::mutex sCallBacksMutex;
class JsCommon {
public:
    static bool TypeOf(napi_env env, napi_value value, napi_valuetype type);
    static void ThrowError(napi_env env, int32_t code);
};

struct KeyEventMonitorInfo : RefBase {
    napi_env env{ nullptr };
    std::mutex envMutex_;
    napi_async_work asyncWork{ nullptr };
    std::string eventType;
    std::string name;
    napi_ref callback{ nullptr };
    int32_t subscribeId{ 0 };
    std::shared_ptr<KeyOption> keyOption{ nullptr };
    KeyEventMonitorInfo(napi_env env);
    ~KeyEventMonitorInfo();
};
typedef std::map<std::string, std::list<sptr<KeyEventMonitorInfo>>> Callbacks;

class JsInputConsumer final {
    enum JsKeyAction {
        JS_KEY_ACTION_CANCEL,
        JS_KEY_ACTION_DOWN,
        JS_KEY_ACTION_UP,
    };

    struct KeyMonitor {
        int32_t subscriberId_ { -1 };
        KeyMonitorOption keyOption_ {};
        napi_env env_ { nullptr };
        napi_ref callback_ { nullptr };

        bool Parse(napi_env env, napi_callback_info info);
        bool ParseKeyMonitorOption(napi_env env, napi_value keyOption);
        bool ParseUnsubscription(napi_env env, napi_callback_info info);
    };

    struct Work {
        size_t keyMonitorId_ {};
        uv_work_t work_ {};
        std::shared_ptr<KeyEvent> keyEvent_ {};
    };

public:
    JsInputConsumer() = default;
    ~JsInputConsumer() = default;
    DISALLOW_COPY_AND_MOVE(JsInputConsumer);

    void SubscribeKeyMonitor(napi_env env, napi_callback_info info);
    void UnsubscribeKeyMonitor(napi_env env, napi_callback_info info);

    static std::shared_ptr<JsInputConsumer> GetInstance();

private:
    size_t GenerateId();
    void CleanupKeyMonitor(napi_env env, KeyMonitor &tMonitor) const;
    int32_t IsIdentical(napi_env env, const KeyMonitor &sMonitor, const KeyMonitor &tMonitor) const;
    int32_t HasSubscribed(napi_env env, const KeyMonitor &keyMonitor) const;
    bool SubscribeKeyMonitor(napi_env env, KeyMonitor &keyMonitor);
    void UnsubscribeKeyMonitor(napi_env env, const KeyMonitor &keyMonitor);
    void UnsubscribeKeyMonitors(napi_env env);
    void OnSubscribeKeyMonitor(size_t keyMonitorId, std::shared_ptr<KeyEvent> keyEvent);
    void NotifyKeyMonitor(uv_work_t *work, int32_t status);
    void NotifyKeyMonitor(const KeyMonitor &keyMonitor, std::shared_ptr<KeyEvent> keyEvent);
    void NotifyKeyMonitorScoped(const KeyMonitor &keyMonitor, std::shared_ptr<KeyEvent> keyEvent);
    static bool CheckKeyMonitorOption(const KeyMonitorOption &keyOption);
    static napi_value KeyEvent2JsKeyEvent(napi_env env, std::shared_ptr<KeyEvent> keyEvent);
    static napi_value KeyItem2JsKey(napi_env env, const KeyEvent::KeyItem &keyItem);
    static void HandleKeyMonitor(uv_work_t *work, int32_t status);
    static int32_t JsKeyAction2KeyAction(int32_t action);
    static int32_t KeyAction2JsKeyAction(int32_t action);

    std::mutex mutex_;
    size_t baseId_ { 0 };
    std::map<size_t, KeyMonitor> monitors_;
    std::map<uv_work_t*, std::shared_ptr<Work>> pendingWorks_;
    static const std::set<int32_t> allowedKeys_;
};
} // namespace MMI
} // namespace OHOS
#endif // JS_REGISTER_MODULE_H
