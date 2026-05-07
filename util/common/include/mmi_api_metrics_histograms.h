/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MMI_API_METRICS_HISTOGRAMS_H
#define MMI_API_METRICS_HISTOGRAMS_H
#ifdef OHOS_BUILD_ENABLE_API_METRICS_HISTOGRAM

#include "histogram_plugin_macros.h"

#define MMI_HISTOGRAM_BOOLEAN(name, sample)                 HISTOGRAM_BOOLEAN(name, sample)
#define MMI_HISTOGRAM_ENUMERATION(name, sample, boundary)   HISTOGRAM_ENUMERATION(name, sample, boundary)

namespace OHOS {
namespace MMI {
void HistogramError(const char *name, int32_t errorCode);
} // namespace MMI
} // namespace OHOS

#define MMI_HISTOGRAM_ERROR(name, errorCode)                ::OHOS::MMI::HistogramError(name, (errorCode))

#else // OHOS_BUILD_ENABLE_API_METRICS_HISTOGRAM

#define MMI_HISTOGRAM_BOOLEAN(name, sample)
#define MMI_HISTOGRAM_ENUMERATION(name, sample, boundary)
#define MMI_HISTOGRAM_ERROR(name, errorCode)                ((void)(errorCode))

#endif // OHOS_BUILD_ENABLE_API_METRICS_HISTOGRAM
#endif // MMI_API_METRICS_HISTOGRAMS_H
