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


#ifndef PRODUCT_NAME_DEFINITION_H
#define PRODUCT_NAME_DEFINITION_H

#include "product_name_definition_parser.h"

namespace OHOS {
namespace MMI {

const std::string DEVICE_TYPE_FOLD_PC { PRODUCT_NAME_DEFINITION_PARSER.GetProductName("DEVICE_TYPE_FOLD_PC") };
const std::string DEVICE_TYPE_PC_PRO { PRODUCT_NAME_DEFINITION_PARSER.GetProductName("DEVICE_TYPE_PC_PRO") };
const std::string DEVICE_TYPE_TABLET { PRODUCT_NAME_DEFINITION_PARSER.GetProductName("DEVICE_TYPE_TABLET") };
const std::string DEVICE_TYPE_TABLET_P { PRODUCT_NAME_DEFINITION_PARSER.GetProductName("DEVICE_TYPE_TABLET_P") };

} // namespace MMI
} // namespace OHOS
#endif // PRODUCT_NAME_DEFINITION_H