/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef KEY_MAP_MGR_MOCK_H
#define KEY_MAP_MGR_MOCK_H
#include <gmock/gmock.h>
#include "key_map_manager.h"

namespace OHOS {
namespace MMI {

class KeyMgrInterface {
public:
    virtual char* GetProFileAbsPath(const char* fileName, char* buf, int32_t length) = 0;
    virtual unsigned int libinput_device_get_id_vendor(struct libinput_device *device) = 0;
    virtual unsigned int libinput_device_get_id_product(struct libinput_device *device) = 0;
    virtual unsigned int libinput_device_get_id_version(struct libinput_device *device) = 0;
    virtual const char* libinput_device_get_name(struct libinput_device *device) = 0;
};

class KeyMgrMock : public KeyMgrInterface {
public:
    KeyMgrMock()
    {
        mock = this;
    }
    ~KeyMgrMock()
    {
        mock = nullptr;
    }
    static KeyMgrMock *GetMock()
    {
        return mock;
    }

    MOCK_METHOD(char*, GetProFileAbsPath, (const char* fileName, char* buf, int32_t length), (override));
    MOCK_METHOD(unsigned int, libinput_device_get_id_vendor, (struct libinput_device *device), (override));
    MOCK_METHOD(unsigned int, libinput_device_get_id_product, (struct libinput_device *device), (override));
    MOCK_METHOD(unsigned int, libinput_device_get_id_version, (struct libinput_device *device), (override));
    MOCK_METHOD(const char*, libinput_device_get_name, (struct libinput_device *device), (override));
private:
    static inline KeyMgrMock* mock = nullptr;
};

} // namespace MMI
} // namespace OHOS

#endif /* SOFTBUS_BROADCAST_MGR_MOCK_H */