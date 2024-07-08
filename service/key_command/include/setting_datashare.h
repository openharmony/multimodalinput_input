/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SETTING_DATASHARE_H
#define SETTING_DATASHARE_H

#include "datashare_helper.h"
#include "errors.h"
#include "mutex"
#include "setting_observer.h"

namespace OHOS {
namespace MMI {
class SettingDataShare : public NoCopyable {
public:
    ~SettingDataShare() override;
    static SettingDataShare& GetInstance(int32_t systemAbilityId);
    ErrCode GetStringValue(const std::string& key, std::string& value, const std::string &strUri = std::string());
    ErrCode GetIntValue(const std::string& key, int32_t& value, const std::string &strUri = std::string());
    ErrCode GetLongValue(const std::string& key, int64_t& value, const std::string &strUri = std::string());
    ErrCode GetBoolValue(const std::string& key, bool& value, const std::string &strUri = std::string());
    ErrCode PutStringValue(const std::string& key, const std::string& value,
        bool needNotify = true, const std::string &strUri = std::string());
    ErrCode PutIntValue(const std::string& key, int32_t value,
        bool needNotify = true, const std::string &strUri = std::string());
    ErrCode PutLongValue(const std::string& key, int64_t value,
        bool needNotify = true, const std::string &strUri = std::string());
    ErrCode PutBoolValue(const std::string& key, bool value,
        bool needNotify = true, const std::string &strUri = std::string());
    bool IsValidKey(const std::string& key, const std::string &strUri = std::string());
    sptr<SettingObserver> CreateObserver(const std::string& key, SettingObserver::UpdateFunc& func);
    static void ExecRegisterCb(const sptr<SettingObserver>& observer);
    ErrCode RegisterObserver(const sptr<SettingObserver>& observer, const std::string &strUri = std::string());
    ErrCode UnregisterObserver(const sptr<SettingObserver>& observer, const std::string &strUri = std::string());

private:
    static std::shared_ptr<SettingDataShare> instance_;
    static std::mutex mutex_;
    static sptr<IRemoteObject> remoteObj_;

    static std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(const std::string &strUri);
    static bool ReleaseDataShareHelper(std::shared_ptr<DataShare::DataShareHelper>& helper);
    static Uri AssembleUri(const std::string& key, const std::string &strUri);
};
}
} // namespace OHOS
#endif // SETTING_DATASHARE_H