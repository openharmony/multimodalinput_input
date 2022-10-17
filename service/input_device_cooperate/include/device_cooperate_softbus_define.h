/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DEVICE_COOPERATE_SOFTBUS_DEFINE_H
#define DEVICE_COOPERATE_SOFTBUS_DEFINE_H

#include <string>
#include <unistd.h>

namespace OHOS {
namespace MMI {
constexpr int32_t ENCRYPT_TAG_LEN = 32;
constexpr int32_t MSG_MAX_SIZE = 45 * 1024;
constexpr uint32_t SESSION_NAME_SIZE_MAX = 256;
constexpr uint32_t DEVICE_ID_SIZE_MAX = 65;
constexpr uint32_t INTERCEPT_STRING_LENGTH = 20;
constexpr int32_t SESSION_WAIT_TIMEOUT_SECOND = 5;
constexpr int32_t SESSION_SIDE_SERVER = 0;
constexpr int32_t SESSION_SIDE_CLIENT = 1;

const std::string SESSION_NAME = "ohos.mmi.";
const std::string GROUP_ID = "mmi_softbus_group_id";

#define MMI_SOFTBUS_KEY_CMD_TYPE "mmi_softbus_key_cmd_type"
#define MMI_SOFTBUS_KEY_LOCAL_DEVICE_ID "mmi_softbus_key_local_device_id"
#define MMI_SOFTBUS_KEY_START_DHID "mmi_softbus_key_start_dhid"
#define MMI_SOFTBUS_KEY_POINTER_X "mmi_softbus_key_pointer_x"
#define MMI_SOFTBUS_KEY_POINTER_Y "mmi_softbus_key_pointer_y"
#define MMI_SOFTBUS_KEY_RESULT "mmi_softbus_key_result"
#define MMI_SOFTBUS_KEY_OTHER_DEVICE_ID "mmi_softbus_key_other_device_id"
#define MMI_SOFTBUS_KEY_SESSION_ID "mmi_softbus_key_session_id"

enum {
    REMOTE_COOPERATE_START = 1,
    REMOTE_COOPERATE_START_RES = 2,
    REMOTE_COOPERATE_STOP = 3,
    REMOTE_COOPERATE_STOP_RES = 4,
    REMOTE_COOPERATE_STOP_OTHER_RES = 5
};
}  // namespace MMI
}  // namespace OHOS
#endif  // DEVICE_COOPERATE_SOFTBUS_DEFINE_H
