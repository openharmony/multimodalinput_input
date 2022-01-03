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
#ifndef OHOS_MMI_INTERFACE_H
#define OHOS_MMI_INTERFACE_H

#include "singleton.h"
#ifdef OHOS_WESTEN_MODEL
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#include "libweston.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif
    void Dump(int fd);
    int GetMultimodeInputinformation(void);
#ifdef OHOS_WESTEN_MODEL
    void StartMmiServer(void);
    int wet_module_init(struct weston_compositor* ec, int* argc, char* argv[]);
#endif
#ifdef __cplusplus
}
#endif
#endif
