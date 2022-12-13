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

#ifndef COOPERATION_MESSAGE_H
#define COOPERATION_MESSAGE_H

namespace OHOS {
namespace MMI {
enum class CooperationMessage {
    OPEN_SUCCESS = 100,
    OPEN_FAIL = 101,
    INFO_START = 200,
    INFO_SUCCESS = 201,
    INFO_FAIL = 202,
    CLOSE = 300,
    CLOSE_SUCCESS = 301,
    STOP = 400,
    STOP_SUCCESS = 401,
    STOP_FAIL = 402,
    STATE_ON = 500,
    STATE_OFF = 501,
    INPUT_DEVICE_ID_ERROR = 4400001,
    COOPERATE_FAIL = 4400002,
    COOPERATION_DEVICE_ERROR = 4400003,
};
} // namespace MMI
} // namespace OHOS
#endif // COOPERATION_MESSAGE_H