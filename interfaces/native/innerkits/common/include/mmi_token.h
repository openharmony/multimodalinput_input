/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef MMI_TOKEN_H
#define MMI_TOKEN_H
#include "immi_token.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class MMIToken : public IMMIToken {
public:
    MMIToken(std::u16string descriptor = nullptr) : IMMIToken(descriptor)
    {
    }
    DISALLOW_COPY_AND_MOVE(MMIToken);
    virtual ~MMIToken() = default;

    virtual int32_t GetObjectRefCount() override
    {
        return 0;
    }
    virtual int32_t SendRequest(uint32_t code, MessageParcel& data,
        MessageParcel& reply, MessageOption& option) override
    {
        return 0;
    }
    virtual bool AddDeathRecipient(const sptr<DeathRecipient>& recipient) override
    {
        return false;
    }
    virtual bool RemoveDeathRecipient(const sptr<DeathRecipient>& recipient) override
    {
        return false;
    }
    virtual int Dump(int fd, const std::vector<std::u16string>& args) override
    {
        return 0;
    }
    virtual const std::string& GetName() const override
    {
        return name_;
    }
    virtual const std::string& GetBundlerName() const override
    {
        return bundlerName_;
    }
    static sptr<MMIToken> Create(const std::u16string& u16)
    {
        return sptr<MMIToken>(new MMIToken(u16));
    }
    void SetBundlerName(const std::string& name)
    {
        bundlerName_ = name;
    }
    void SetName(const std::string& name)
    {
        name_ = name;
    }

private:
    std::string bundlerName_ = "DefaultBundlerName";
    std::string name_ = "DefaultName";
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_TOKEN_H