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
#include <cstdio>
#include <map>
#include <list>
#include <cstring>
#include <iostream>
#include "multimodal_event_handler.h"
#include "key_event.h"
#include "key_option.h"
#include "libmmi_util.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "utils/log.h"

#define SUCCESS_CODE 0
#define ERROR_CODE (-1)
#define UNREGISTERED_CODE (-2)
#define REFERENCE_CODE 100
#define SLEEPING_SECONDS 1000

#define SYSTEM_TYPE_CODE 0
#define COMMON_TYPE_CODE 1
#define TELEPHONE_TYPE_CODE 2
#define MEDIA_TYPE_CODE 3
#define EVENT_TYPE_CODE 4
#define TOUCH_TYPE_CODE 5
#define DEVICE_TYPE_CODE 6
#define INVALID_TYPE_CODE 255
#define DEFAULT_EVENT_TYPE 10

#define INVALID_APP_HANDLE 255
#define MAX_EVENT_NUM 65535

enum JS_CALLBACK_EVENT {
    JS_CALLBACK_EVENT_FAILED = -1,
    JS_CALLBACK_EVENT_SUCCESS = 1,
    JS_CALLBACK_EVENT_EXIST = 2,
    JS_CALLBACK_EVENT_NOT_EXIST = 3,
};

namespace OHOS {
namespace MMI {
typedef struct {
    napi_env env;
    napi_async_work asyncWork;
    std::string eventType;
    std::string name;
    napi_value handle;
    int32_t status;
    std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent = { nullptr };
    napi_ref callback[1] = { 0 };
    int32_t subscribeId;
    std::shared_ptr<KeyOption> keyOption = { nullptr };
} KeyEventMonitorInfo;

typedef std::map<std::string, std::list<KeyEventMonitorInfo *>> Callbacks;
} // namespace MMI
} // namespace OHOS

#endif // JS_REGISTER_MODULE_H