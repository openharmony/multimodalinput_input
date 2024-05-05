/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

/*
 * This file is used as stub header for key_command_handler.cpp.
 * It should re-define ability related methods for unit test.
 */

#ifndef ABILITY_MANAGER_CLIENT_STUB_H
#define ABILITY_MANAGER_CLIENT_STUB_H

#include <string>
#include <memory>
#include <vector>
#include <map>
#include <errors.h>

#include "iremote_object.h"

namespace OHOS {
namespace AAFwk {

constexpr int32_t DEFAULT_INVAL_VALUE = -1;

class Want {
public:
    Want &SetElementName(const std::string &deviceId, const std::string &bundleName,
        const std::string &abilityName, const std::string &moduleName = "");
    Want &SetAction(const std::string &action);
    Want &SetUri(const std::string &uri);
    Want &SetType(const std::string &type);
    Want &AddEntity(const std::string &entity);
    // Note: We use different SetParam() signature for test
    Want &SetParam(const std::string &key, const std::string &value);

    std::string bundleName_;
    std::string abilityName_;
    std::string action_;
    std::string type_;
    std::string deviceId_;
    std::string uri_;
    std::string moduleName_;
    std::vector<std::string> entities_;
    std::map<std::string, std::string> params_;
};

class AbilityManagerClient {
public:
    AbilityManagerClient()
    {
        callback_ = nullptr;
        err_ = ERR_OK;
    }
    virtual ~AbilityManagerClient() {}
    static std::shared_ptr<AbilityManagerClient> GetInstance();
    ErrCode StartAbility(const Want &want, int32_t requestCode = DEFAULT_INVAL_VALUE,
                         int32_t userId = DEFAULT_INVAL_VALUE);
    ErrCode StartExtensionAbility(const Want &want, sptr<IRemoteObject> callerToken);
    void SetCallback(void (*cb)(const Want &want, ErrCode err));
    void SetErrCode(ErrCode err);

private:
    static std::shared_ptr<AbilityManagerClient> instance_;
    void (*callback_)(const Want &want, ErrCode err);
    ErrCode err_;
};

} // namespace AAFwk

namespace EventFwk {
class CommonEventSupport {
public:
    /**
     * Indicates the action of a common event that the device screen is off and the device is sleeping.
     * This common event can only be published by the system.
     */
    static const std::string COMMON_EVENT_SCREEN_OFF;
    /**
     * Indicates the action of a common event that the device screen is on and the device is interactive.
     * This common event can only be published by the system.
     */
    static const std::string COMMON_EVENT_SCREEN_ON;

	/**
     * Indicates the action of a common event that the screen lock.
     * This is a protected common event that can only be sent by system.
     */
    static const std::string COMMON_EVENT_SCREEN_LOCKED;

    /**
     * Indicates the action of a common event that the screen unlock.
     * This is a protected common event that can only be sent by system.
     */
    static const std::string COMMON_EVENT_SCREEN_UNLOCKED;
public:
    CommonEventSupport();
    virtual ~CommonEventSupport();
};
}  // namespace EventFwk
} // namespace OHOS
#endif // ABILITY_MANAGER_CLIENT_STUB_H
