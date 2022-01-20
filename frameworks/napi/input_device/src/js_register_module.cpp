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
#include <uv.h>
#include "input_device_event.h"

namespace OHOS {
namespace MMI {
constexpr uint32_t ARGV_FIRST = 0;
constexpr uint32_t ARGV_SECOND = 1;
constexpr uint32_t ARGC_NUM_1 = 1;
constexpr uint32_t ARGC_NUM_2 = 2;
constexpr uint32_t INIT_REF_COUNT = 1;
constexpr size_t PARAMETER_NUM = 1;

DeviceType g_deviceType[] = {
    {"keyboard", EVDEV_UDEV_TAG_KEYBOARD},
    {"mouse", EVDEV_UDEV_TAG_MOUSE},
    {"touchpad", EVDEV_UDEV_TAG_TOUCHPAD},
    {"touchscreen", EVDEV_UDEV_TAG_TOUCHSCREEN},
    {"joystick", EVDEV_UDEV_TAG_JOYSTICK},
    {"trackball", EVDEV_UDEV_TAG_TRACKBALL},
};

static napi_value GetDeviceIds(napi_env env, napi_callback_info info)
{
    HILOG_INFO("GetDeviceIds begin");
    size_t argc = ARGC_NUM_1;
    napi_value argv[ARGC_NUM_1];
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok) {
        napi_throw_error(env, nullptr, "GetDeviceIds: call to napi_get_cb_info failed");
    }
    if (argc != ARGC_NUM_1) {
        napi_throw_error(env, nullptr, "GetDeviceIds: requires 1 parameter");
    }

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[ARGV_FIRST], &valueType) != napi_ok) {
        napi_throw_error(env, nullptr, "GetDeviceIds: call to napi_typeof failed");
    }
    if (valueType != napi_function) {
        napi_throw_error(env, nullptr, "GetDeviceIds: The first parameter is not a function");
    }

    struct CallbackInfo {
        napi_env env;
        napi_ref handleRef {nullptr};
        uv_loop_s* loop {nullptr};
        std::vector<int32_t> ids_;
    };
    CallbackInfo* cb = new CallbackInfo;
    cb->env = env;

    uv_loop_s* loop {nullptr};
    if (napi_get_uv_event_loop(env, &loop) != napi_ok) {
        napi_throw_error(env, nullptr, "GetDeviceIds: call to napi_get_uv_event_loop failed");
    }
    cb->loop = loop;

    napi_ref handlerRef {nullptr};
    if (napi_create_reference(env, argv[ARGV_FIRST], INIT_REF_COUNT, &handlerRef) != napi_ok) {
        napi_throw_error(env, nullptr, "GetDeviceIds: call to napi_create_reference failed");
    }
    cb->handleRef = handlerRef;
    uv_work_t* work = new uv_work_t;
    work->data = (void*)cb;

    auto &instance = InputDeviceEvent::GetInstance();
    instance.GetInputDeviceIdsAsync([work](std::vector<int32_t> ids) {
        auto callbackInfo = (CallbackInfo*)work->data;
        callbackInfo->ids_ = ids;
        uv_queue_work(
            callbackInfo->loop,
            work,
            [](uv_work_t *work) {},
            [](uv_work_t *work, int32_t status) {
                HILOG_INFO("uv_queue_work begin");
                struct CallbackInfo* cbInfo = (struct CallbackInfo*)work->data;
                napi_env env = cbInfo->env;
                napi_ref handleRef = cbInfo->handleRef;
                std::vector<int32_t> ids = cbInfo->ids_;
                delete cbInfo;
                delete work;
                cbInfo = nullptr;
                work = nullptr;

                napi_value arr;
                napi_value value;
                if (napi_create_array(env, &arr) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDeviceIds:uv_queue_work call to napi_create_array failed");
                    return;
                }
                for (size_t i = 0; i < ids.size(); i++) {
                    if (napi_create_int64(env, ids[i], &value) != napi_ok) {
                        napi_throw_error(env, nullptr, "GetDeviceIds:uv_queue_work call to napi_create_int64 failed");
                        return;
                    }
                    if (napi_set_element(env, arr, i, value) != napi_ok) {
                        napi_throw_error(env, nullptr, "GetDeviceIds:uv_queue_work call to napi_set_element failed");
                        return;
                    }
                }

                napi_value result;
                napi_value handlerTemp;
                if (napi_get_reference_value(env, handleRef, &handlerTemp) != napi_ok) {
                    napi_throw_error(env, nullptr,
                        "GetDeviceIds:uv_queue_work call to napi_get_reference_value failed");
                    return;
                }
                if (napi_call_function(env, nullptr, handlerTemp, PARAMETER_NUM, &arr, &result) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDeviceIds:uv_queue_work call to napi_call_function failed");
                    return;
                }

                uint32_t refCount {0};
                if (napi_reference_unref(env, handleRef, &refCount) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDeviceIds:uv_queue_work call to napi_reference_unref failed");
                    return;
                }
                HILOG_INFO("uv_queue_work end");
            });
    });
    HILOG_INFO("GetDeviceIds end");
    return nullptr;
}

static napi_value GetDevice(napi_env env, napi_callback_info info)
{
    HILOG_INFO("GetDevice begin");
    size_t argc = ARGC_NUM_2;
    napi_value argv[ARGC_NUM_2];
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok) {
        napi_throw_error(env, nullptr, "GetDevice: call to napi_get_cb_info failed");
    }
    if (argc != ARGC_NUM_2) {
        napi_throw_error(env, nullptr, "GetDevice: requires 2 parameter");
    }

    napi_valuetype valueType {napi_undefined};
    if (napi_typeof(env, argv[ARGV_FIRST], &valueType) != napi_ok) {
        napi_throw_error(env, nullptr, "GetDevice: call to napi_typeof failed");
    }
    if (valueType != napi_number) {
        napi_throw_error(env, nullptr, "GetDevice: The first parameter is not a number");
    }
    if (napi_typeof(env, argv[ARGV_SECOND], &valueType) != napi_ok) {
        napi_throw_error(env, nullptr, "GetDevice: call to napi_typeof failed");
    }
    if (valueType != napi_function) {
        napi_throw_error(env, nullptr, "GetDevice: The second parameter is not a number");
    }

    struct CallbackInfo {
        napi_env env;
        napi_ref handleRef;
        uv_loop_s* loop {nullptr};
        InputDeviceEvent::InputDeviceInfo inputDeviceInfo;
    };
    CallbackInfo* cb = new CallbackInfo;
    cb->env = env;

    uv_loop_s* loop {nullptr};
    if (napi_get_uv_event_loop(env, &loop) != napi_ok) {
        napi_throw_error(env, nullptr, "GetDevice: call to napi_get_uv_event_loop failed");
    }
    cb->loop = loop;

    napi_ref handlerRef {nullptr};
    if (napi_create_reference(env, argv[ARGV_SECOND], INIT_REF_COUNT, &handlerRef) != napi_ok) {
        napi_throw_error(env, nullptr, "GetDevice: call to napi_create_reference failed");
    }
    cb->handleRef = handlerRef;
    uv_work_t* work = new uv_work_t;
    work->data = (void*)cb;

    int32_t id {0};
    if (napi_get_value_int32(env, argv[ARGV_FIRST], &id) != napi_ok) {
        napi_throw_error(env, nullptr, "GetDevice: call to napi_get_value_int32 failed");
    }
    auto &instance = InputDeviceEvent::GetInstance();
    instance.GetInputDeviceAsync(id, [work](std::shared_ptr<InputDeviceEvent::InputDeviceInfo> deviceInfo) {
        auto callbackInfo = (CallbackInfo*)work->data;
        callbackInfo->inputDeviceInfo = *deviceInfo;
        uv_queue_work(
            callbackInfo->loop,
            work,
            [](uv_work_t *work) {},
            [](uv_work_t *work, int32_t status) {
                HILOG_INFO("uv_queue_work begin");
                struct CallbackInfo* cbInfo = (struct CallbackInfo*)work->data;
                napi_env env = cbInfo->env;
                napi_ref handleRef = cbInfo->handleRef;
                auto inputDevice = cbInfo->inputDeviceInfo;
                delete cbInfo;
                delete work;
                cbInfo = nullptr;
                work = nullptr;

                napi_value id_;
                if (napi_create_int64(env, inputDevice.id, &id_) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDevice:uv_queue_work call to napi_create_int64 failed");
                    return;
                }
                napi_value name_;
                if (napi_create_string_utf8(env, (inputDevice.name).c_str(), NAPI_AUTO_LENGTH, &name_) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDevice:uv_queue_work call to napi_create_string_utf8 failed");
                    return;
                }

                napi_value object;
                if (napi_create_object(env, &object) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDevice:uv_queue_work call to napi_create_object failed");
                    return;
                }
                if (napi_set_named_property(env, object, "id", id_) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDevice:uv_queue_work call to napi_set_named_property failed");
                    return;
                }
                if (napi_set_named_property(env, object, "name", name_) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDevice:uv_queue_work call to napi_set_named_property failed");
                    return;
                }

                napi_value typeArr;
                if (napi_create_array(env, &typeArr) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDevice:uv_queue_work call to napi_create_array failed");
                    return;
                }

                int32_t devicTypes = inputDevice.devcieType;
                napi_value value;
                std::vector<std::string> type;
                for (const auto &it : g_deviceType) {
                    if (devicTypes & it.typeBit) {
                        type.push_back(it.deviceTypeName);
                    }
                }
                for (size_t i = 0; i < type.size(); i++) {
                    if (napi_create_string_utf8(env, type[i].c_str(), NAPI_AUTO_LENGTH, &value) != napi_ok) {
                        napi_throw_error(env, nullptr,
                            "GetDevice:uv_queue_work call to napi_create_string_utf8 failed");
                        return;
                    }
                    if (napi_set_element(env, typeArr, i, value) != napi_ok) {
                        napi_throw_error(env, nullptr, "GetDevice:uv_queue_work call to napi_set_element failed");
                    }
                }
                if (napi_set_named_property(env, object, "sources", typeArr) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDevice:uv_queue_work call to napi_set_named_property failed");
                    return;
                }

                napi_value axisRangesArr;
                if (napi_create_array(env, &axisRangesArr) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDevice:uv_queue_work call to napi_create_array failed");
                    return;
                }

                if (napi_set_named_property(env, object, "axisRanges", axisRangesArr) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDevice:uv_queue_work call to napi_set_named_property failed");
                    return;
                }

                napi_value handler;
                if (napi_get_reference_value(env, handleRef, &handler) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDevice:uv_queue_work call to napi_get_reference_value failed");
                    return;
                }

                napi_value result;
                if (napi_call_function(env, nullptr, handler, PARAMETER_NUM, &object, &result) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDevice:uv_queue_work call to napi_call_function failed");
                    return;
                }
                uint32_t refCount {0};
                if (napi_reference_unref(env, handleRef, &refCount) != napi_ok) {
                    napi_throw_error(env, nullptr, "GetDevice:uv_queue_work call to napi_reference_unref failed");
                    return;
                }
                HILOG_INFO("uv_queue_work end");
            });
    });
    HILOG_INFO("GetDevice end");
    return nullptr;
}

EXTERN_C_START
static napi_value MmiInputDeviceInit(napi_env env, napi_value exports)
{
    HILOG_INFO("MmiInputDeviceInit: enter");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getDevice", GetDevice),
        DECLARE_NAPI_FUNCTION("getDeviceIds", GetDeviceIds)
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    HILOG_INFO("MmiInputDeviceInit: success");
    return exports;
}
EXTERN_C_END

static napi_module mmiInputDeviceModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = MmiInputDeviceInit,
    .nm_modname = "inputDevice",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&mmiInputDeviceModule);
}
}
}
