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
            size_t requireArgc = 1;
            size_t argc;
            napi_value argv[requireArgc];
            napi_status status = napi_generic_failure;

            status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
            if (status != napi_ok) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:GetDeviceIds get cb info failed");
                return nullptr;
            }
            if (argc < requireArgc) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:GetDeviceIds argc is not requireArgc");
                return nullptr;
            }

            napi_valuetype valueType = napi_undefined;
            status = napi_typeof(env, argv[0], &valueType);
            if (status != napi_ok) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:GetDeviceIds typeof failed");
                return nullptr;
            }
            if (valueType != napi_function) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:valueType is not napi_function");
                return nullptr;
            }

            struct CallbackInfo {
                napi_env env_;
                napi_ref handleRef_;
                uv_loop_s* loop_ {nullptr};
                std::vector<int32_t> ids_;
            };
            CallbackInfo* cb = new CallbackInfo;
            cb->env_ = env;
            uv_work_t* work = new uv_work_t;
            uv_loop_s* loop {nullptr};

            status = napi_get_uv_event_loop(env, &loop);
            if (status != napi_ok) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:napi_get_uv_event_loop failed");
                return nullptr;
            }
            cb->loop_ = loop;

            napi_ref handlerRef = nullptr;
            status = napi_create_reference(env, argv[0], 1, &handlerRef);
            if (status != napi_ok) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:napi_create_reference failed");
                return nullptr;
            }
            cb->handleRef_ = handlerRef;
            work->data = (void*)cb;

            auto &instance = InputDeviceEvent::GetInstance();
            instance.GetInputDeviceIdsAsync([work](std::vector<int32_t> ids) {
                auto callbackInfo = (CallbackInfo*)work->data;
                callbackInfo->ids_ = ids;
                uv_queue_work(
                    callbackInfo->loop_,
                    work,
                    [](uv_work_t *work) {},
                    [](uv_work_t *work, int32_t status) {
                        HILOG_ERROR("uv_queue_work enter");
                        struct CallbackInfo* cbInfo = (struct CallbackInfo*)work->data;
                        napi_env env = cbInfo->env_;
                        napi_ref handleRef = cbInfo->handleRef_;
                        std::vector<int32_t> ids = cbInfo->ids_;
                        delete cbInfo;
                        delete work;
                        cbInfo = nullptr;
                        work = nullptr;

                        napi_status status_ = napi_generic_failure;
                        napi_value arr;
                        napi_value value;

                        status_ = napi_create_array(env, &arr);
                        if (status_ != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:GetDeviceIds create array failed");
                            return;
                        }
                        for (size_t i = 0; i < ids.size(); i++) {
                            status_ = napi_create_int64(env, ids[i], &value);
                            if (status_ != napi_ok) {
                                napi_throw_type_error(env, nullptr,
                                    "MMI Throw Error:GetDeviceIds create int64 failed");
                                return;
                            }
                            status = napi_set_element(env, arr, i, value);
                            if (status_ != napi_ok) {
                                napi_throw_type_error(env, nullptr,
                                    "MMI Throw Error:GetDeviceIds set element failed");
                                return;
                            }
                        }

                        napi_value result;
                        napi_value handlerTemp = nullptr;
                        status = napi_get_reference_value(env, handleRef, &handlerTemp);
                        if (status != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:napi_get_reference_value failed");
                            return;
                        }
                        status = napi_call_function(env, nullptr, handlerTemp, 1, &arr, &result);
                        if (status != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:napi_call_function failed");
                            return;
                        }

                        uint32_t refCount = 0;
                        status = napi_reference_unref(env, handleRef, &refCount);
                        if (status != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:napi_reference_unref failed");
                            return;
                        }
                    });
            });
            return nullptr;
        }

        static napi_value GetDevice(napi_env env, napi_callback_info info)
        {
            size_t requireArgc = 2;
            size_t argc;
            napi_value argv[2];
            napi_status status = napi_generic_failure;

            status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
            if (status != napi_ok) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:GetDevice get cb info failed");
                return nullptr;
            }
            if (argc < requireArgc) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:GetDevice argc is not requireArgc");
                return nullptr;
            }

            napi_valuetype valueType = napi_undefined;
            status = napi_typeof(env, argv[0], &valueType);
            if (status != napi_ok) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:GetDevice typeof failed");
                return nullptr;
            }
            if (valueType != napi_number) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:valueType is not napi_number");
                return nullptr;
            }

            status = napi_typeof(env, argv[1], &valueType);
            if (status != napi_ok) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:GetDevice typeof failed");
                return nullptr;
            }
            if (valueType != napi_function) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:valueType is not napi_number");
                return nullptr;
            }

            int32_t id = 0;
            status = napi_get_value_int32(env, argv[0], &id);
            if (status != napi_ok) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:GetDevice get value int32 failed");
                return nullptr;
            }

            struct CallbackInfo {
                napi_env env_;
                napi_ref handleRef_;
                uv_loop_s* loop_ {nullptr};
                InputDeviceEvent::InputDeviceInfo inputDeviceInfo_;
            };
            CallbackInfo* cb = new CallbackInfo;
            cb->env_ = env;
            uv_work_t* work = new uv_work_t;
            uv_loop_s* loop {nullptr};

            status = napi_get_uv_event_loop(env, &loop);
            if (status != napi_ok) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:GetDevice napi_get_uv_event_loop failed");
                return nullptr;
            }
            cb->loop_ = loop;

            napi_ref handlerRef = nullptr;
            status = napi_create_reference(env, argv[1], 1, &handlerRef);
            if (status != napi_ok) {
                napi_throw_type_error(env, nullptr, "MMI Throw Error:GetDevice napi_create_reference failed");
                return nullptr;
            }
            cb->handleRef_ = handlerRef;
            work->data = (void*)cb;

            auto &instance = InputDeviceEvent::GetInstance();
            instance.GetInputDeviceAsync(id, [work](std::shared_ptr<InputDeviceEvent::InputDeviceInfo> deviceInfo) {
                auto callbackInfo = (CallbackInfo*)work->data;
                callbackInfo->inputDeviceInfo_ = *deviceInfo;
                uv_queue_work(
                    callbackInfo->loop_,
                    work,
                    [](uv_work_t *work) {},
                    [](uv_work_t *work, int32_t status) {
                        HILOG_ERROR("uv_queue_work enter");
                        struct CallbackInfo* cbInfo = (struct CallbackInfo*)work->data;
                        napi_env env = cbInfo->env_;
                        napi_ref handleRef = cbInfo->handleRef_;
                        auto inputDevice = cbInfo->inputDeviceInfo_;
                        delete cbInfo;
                        delete work;
                        cbInfo = nullptr;
                        work = nullptr;

                        napi_status status_ = napi_generic_failure;
                        napi_value thisVar;

                        napi_value id_;
                        napi_value name_;
                        status_ = napi_create_int64(env, inputDevice.id_, &id_);
                        if (status_ != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:GetDevice napi_create_int64 failed");
                            return;
                        }

                        status_ = napi_create_string_utf8(env,
                            (inputDevice.name_).c_str(), NAPI_AUTO_LENGTH, &name_);
                        if (status_ != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:GetDevice create string utf8 failed");
                            return;
                        }

                        napi_value object = nullptr;
                        status_ = napi_create_object(env, &object);
                        if (status_ != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:GetDevice create object failed");
                            return;
                        }
                        status_ = napi_set_named_property(env, object, "id", id_);
                        if (status_ != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:GetDevice set named property failed");
                            return;
                        }
                        status_ = napi_set_named_property(env, object, "name", name_);
                        if (status_ != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:GetDevice set named property failed");
                            return;
                        }

                        napi_value typeArr;
                        status_ = napi_create_array(env, &typeArr);
                        if (status_ != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:GetDevice create array failed");
                            return;
                        }

                        int32_t devicTypes = inputDevice.devcieType_;
                        napi_value value;
                        std::vector<std::string> type;
                        for (auto it : g_deviceType) {
                            if (devicTypes & it.typeBit) {
                                type.push_back(it.deviceTypeName);
                            }
                        }
                        for (size_t i = 0; i < type.size(); i++) {
                            status_ = napi_create_string_utf8(env, (char*)type[i].c_str(),
                                NAPI_AUTO_LENGTH, &value);
                            if (status_ != napi_ok) {
                                napi_throw_type_error(env, nullptr,
                                    "MMI Throw Error:GetDevice create string utf8 failed");
                                return;
                            }
                            status_ = napi_set_element(env, typeArr, i, value);
                            if (status_ != napi_ok) {
                                napi_throw_type_error(env, nullptr,
                                    "MMI Throw Error:GetDevice set named property failed");
                            }
                        }
                        status_ = napi_set_named_property(env, object, "sources", typeArr);
                        if (status_ != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:GetDevice set named property failed");
                            return;
                        }

                        napi_value axisRangesArr;
                        status_ = napi_create_array(env, &axisRangesArr);
                        if (status_ != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:GetDevice create array failed");
                            return;
                        }

                        status_ = napi_set_named_property(env, object, "axisRanges", axisRangesArr);
                        if (status_ != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:GetDevice set named property failed");
                            return;
                        }

                        napi_value handler = nullptr;
                        napi_value result;
                        status_ = napi_get_reference_value(env, handleRef, &handler);
                        if (status_ != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:GetDevice napi_get_reference_value failed");
                            return;
                        }
                        if (napi_get_undefined(env, &thisVar) != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:GetDevice napi_get_undefined failed");
                            return;
                        }
                        status_ = napi_call_function(env, thisVar, handler, 1, &object, &result);
                        if (status_ != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:GetDevice napi_call_function failed");
                            return;
                        }
                        uint32_t refCount = 0;
                        status = napi_reference_unref(env, handleRef, &refCount);
                        if (status != napi_ok) {
                            napi_throw_type_error(env, nullptr,
                                "MMI Throw Error:GetDevice napi_reference_unref failed");
                            return;
                        }
                    });
            });
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
