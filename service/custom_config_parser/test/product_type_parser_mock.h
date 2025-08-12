/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef MESSAGE_PARCEL_MOCK_H
#define MESSAGE_PARCEL_MOCK_H

#include <memory>
#include <string>
#include <gmock/gmock.h>

#include "iremote_broker.h"
#include "product_type_parser.h"

namespace OHOS::MMI  {
class ProductTypeParserInterface  {
public:
    ProductTypeParserInterface () = default;
    virtual ~ProductTypeParserInterface () = default;
    virtual std::string ReadJsonFile(const std::string &filePath) = 0;
};

class ProductTypeParserMock : public ProductTypeParserInterface  {
public:
    static ProductTypeParserMock *GetMock()
    {
        return mock.load();
    }

    ProductTypeParserMock();
    ~ProductTypeParserMock() override;
    MOCK_METHOD(std::string, ReadJsonFile, (const std::string &filePath));
private:
    static inline std::atomic<ProductTypeParserMock *> mock = nullptr;

};
} // namespace OHOS::MMI
#endif