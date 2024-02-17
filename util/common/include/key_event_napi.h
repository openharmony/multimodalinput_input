/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef KEY_EVENT_NAPI_H
#define KEY_EVENT_NAPI_H

#include "key_event.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace MMI {
class KeyEventNapi {
public:
    /**
     * @brief Write KeyEvent into a JS object.
     * @param env Indicates the environment that the Node-API call is invoked under.
     * @param in Indicates the KeyEvent object from which data will be read.
     * @param out Indicates the JS object into which data will be written.
     * @return Returns <b>napi_ok</b> if the data is successfully written; returns error status otherwise.
     * @since 10
     */
    static napi_status CreateKeyEvent(napi_env env, const std::shared_ptr<KeyEvent> &in, napi_value &out);

    /**
     * @brief Read KeyEvent from a JS object.
     * @param env Indicates the environment that the Node-API call is invoked under.
     * @param in Indicates the JS object from which data will be read.
     * @param out Indicates the KeyEvent object into which data will be written.
     * @return Returns <b>napi_ok</b> if the data is successfully written; returns error status otherwise.
     * @since 10
     */
    static napi_status GetKeyEvent(napi_env env, napi_value in, std::shared_ptr<KeyEvent> &out);

    /**
     * @brief Write KeyItem into a JS object.
     * @param env Indicates the environment that the Node-API call is invoked under.
     * @param in Indicates the KeyItem object from which data will be read.
     * @param out Indicates the JS object into which data will be written.
     * @return Returns <b>napi_ok</b> if the data is successfully written; returns error status otherwise.
     * @since 10
     */
    static napi_status CreateKeyItem(napi_env env, const std::optional<KeyEvent::KeyItem> in, napi_value &out);

    /**
     * @brief Read KeyItem from a JS object.
     * @param in Indicates the JS object from which data will be read.
     * @param out Indicates the KeyItem object into which data will be written.
     * @return Returns <b>napi_ok</b> if the data is successfully written; returns error status otherwise.
     * @since 10
     */
    static napi_status GetKeyItem(napi_env env, napi_value in, KeyEvent::KeyItem &out);

private:
    static napi_status WriteKeyStatusToJs(napi_env env, const std::vector<int32_t> &pressedKeys, napi_value &out);
    static napi_status WriteFunctionKeyStatusToJs(napi_env env, const std::shared_ptr<KeyEvent> &in, napi_value &out);
    static bool HasKeyCode(const std::vector<int32_t> &pressedKeys, int32_t keyCode);
};
} // namespace MMI
} // namespace OHOS
#endif // KEY_EVENT_NAPI_H
