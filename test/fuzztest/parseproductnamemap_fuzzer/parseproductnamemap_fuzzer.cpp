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
#include "json_parser.h"
#include "product_name_definition_parser.h"
#include "parseproductnamemap_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ParseProductNameMapFuzzTest"

namespace OHOS {
namespace MMI {
void ParseProductNameMap(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string jsonStr = provider.ConsumeRemainingBytesAsString();
    const OHOS::MMI::JsonParser parser(jsonStr.c_str());
    ProductNameDefinitionParser::GetInstance().ParseProductNameMap(parser);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    MMI::ParseProductNameMap(data, size);
    return 0;
}
} // namespace MMI