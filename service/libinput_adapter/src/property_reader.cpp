/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#include "property_reader.h"

#include "ffrt.h"


#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PropertyReader"

namespace OHOS {
namespace MMI {

PropertyReader::PropertyReader() {}
PropertyReader::~PropertyReader() {}
void PropertyReader::ReadPropertys(std::string path, DTaskCallback callback)
{
    ffrt::submit([this, path, callback] {
        if (!udev_device_property_add('c', path.c_str())) {
            return;
        }
        CHKPV(delegateProxy_);
        delegateProxy_->OnPostAsyncTask(callback);
    });
}

} // namespace MMI
} // namespace OHOS