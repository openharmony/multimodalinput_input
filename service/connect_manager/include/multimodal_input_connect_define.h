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

#ifndef OHOS_MULTIMODAL_INPUT_CONNECT_DEFINE_H
#define OHOS_MULTIMODAL_INPUT_CONNECT_DEFINE_H

#include "parcel.h"

namespace OHOS {
namespace MMI {
#ifndef RET_OK
#define RET_OK (0)
#endif

#ifndef RET_ERR
#define RET_ERR (-1)
#endif

#ifndef MAX_EVENT_SIZE
#define MAX_EVENT_SIZE 100                  // Epoll create maximum event size
#endif

#ifndef MAX_LIST_SIZE
#define MAX_LIST_SIZE 100                   // Instantaneous maximum listening buffer size of socket
#endif

enum {
    ERR_ALREADY_CONNECT_SERVER = 1,
};

// 请求结构体

// 响应结构体
// 返回socket

struct ConnectDefReq {
    int moduleId;
    std::string clientName;
};

struct ConnectDefResp {
    int returnCode;
    int allocedSocketId;
};
} // namespace MMI
} // namespace OHOS

#endif // OHOS_MULTIMODAL_INPUT_CONNECT_DEFINE_H
