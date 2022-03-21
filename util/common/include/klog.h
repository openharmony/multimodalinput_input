/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef KLOG_H
#define KLOG_H

#include <cstring>

namespace OHOS {
namespace MMI {
void kMsgLog(const char *fileName, int line, const char *kLevel, const char *fmt, ...);

#ifndef MMI_FILE_NAME
#define MMI_FILE_NAME   (strrchr((__FILE__), '/') ? strrchr((__FILE__), '/') + 1 : (__FILE__))
#endif
#define KMSG_LOGT(fmt, ...) kMsgLog((MMI_FILE_NAME), (__LINE__), "<7>", fmt"\n", ##__VA_ARGS__)
#define KMSG_LOGD(fmt, ...) kMsgLog((MMI_FILE_NAME), (__LINE__), "<7>", fmt"\n", ##__VA_ARGS__)
#define KMSG_LOGI(fmt, ...) kMsgLog((MMI_FILE_NAME), (__LINE__), "<6>", fmt"\n", ##__VA_ARGS__)
#define KMSG_LOGW(fmt, ...) kMsgLog((MMI_FILE_NAME), (__LINE__), "<4>", fmt"\n", ##__VA_ARGS__)
#define KMSG_LOGE(fmt, ...) kMsgLog((MMI_FILE_NAME), (__LINE__), "<3>", fmt"\n", ##__VA_ARGS__)
#define KMSG_LOGF(fmt, ...) kMsgLog((MMI_FILE_NAME), (__LINE__), "<3>", fmt"\n", ##__VA_ARGS__)
} // namespace MMI
} // namespace OHOS
#endif // KLOG_H