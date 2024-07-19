/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "message_parcel.h"
#include "permission_helper.h"
#include "pixel_map.h"

namespace OHOS {
namespace MMI {
class DfsMessageParcel {
public:
    virtual ~DfsMessageParcel() = default;
public:
    virtual bool WriteInterfaceToken(std::u16string name) = 0;
    virtual std::u16string ReadInterfaceToken() = 0;
    virtual bool WriteInt32(int32_t value) = 0;
    virtual int32_t ReadInt32() = 0;
    virtual bool ReadInt32(int32_t &value) = 0;
    virtual bool WriteRemoteObject(const Parcelable *object) = 0;
    virtual bool WriteRemoteObject(const sptr<IRemoteObject> &object) = 0;
    virtual sptr<IRemoteObject> ReadRemoteObject() = 0;
    virtual bool ReadBool();
    virtual bool ReadBool(bool &value) = 0;
    virtual bool WriteBool(bool value) = 0;
    virtual bool WriteString(const std::string &value) = 0;
    virtual bool WriteCString(const char *value) = 0;
    virtual bool WriteFileDescriptor(int fd) = 0;
    virtual std::string ReadString() = 0;
    virtual bool ReadString(std::string &value) = 0;
    virtual int ReadFileDescriptor() = 0;
    virtual bool ReadStringVector(std::vector<std::string> *value) = 0;
    virtual bool ReadUint32(uint32_t &value) = 0;
    virtual bool WriteUint64(uint64_t value) = 0;
    virtual bool WriteUint16(uint16_t value) = 0;
    virtual bool WriteUint32(uint32_t value) = 0;
    virtual bool ReadUint64(uint64_t &value) = 0;
    virtual bool VerifySystemApp() = 0;
    virtual bool CheckMouseCursor() = 0;
    virtual bool CheckInputEventFilter() = 0;
    virtual bool CheckInterceptor() = 0;
    virtual bool CheckMonitor() = 0;
    virtual bool CheckDispatchControl() = 0;
    virtual bool CheckInfraredEmmit() = 0;
    virtual bool CheckAuthorize() = 0;
    virtual bool WriteBoolVector(const std::vector<bool> &val) = 0;
    virtual bool WriteInt32Vector(const std::vector<int32_t> &val) = 0;
    virtual int64_t ReadInt64() = 0;
    virtual bool ReadInt64(int64_t &value) = 0;
    virtual float ReadFloat() = 0;
    virtual bool ReadFloat(float &value) = 0;
    virtual double ReadDouble() = 0;
    virtual bool ReadDouble(double &value) = 0;
    virtual Media::PixelMap *Unmarshalling(Parcel &parcel) = 0;
public:
    static inline std::shared_ptr<DfsMessageParcel> messageParcel = nullptr;
};

class MessageParcelMock : public DfsMessageParcel {
public:
    MOCK_METHOD1(WriteInterfaceToken, bool(std::u16string name));
    MOCK_METHOD0(ReadInterfaceToken, std::u16string());
    MOCK_METHOD1(WriteInt32, bool(int32_t value));
    MOCK_METHOD0(ReadInt32, int32_t());
    MOCK_METHOD1(ReadInt32, bool(int32_t &value));
    MOCK_METHOD1(WriteRemoteObject, bool(const Parcelable *object));
    MOCK_METHOD1(WriteRemoteObject, bool(const sptr<IRemoteObject> &object));
    MOCK_METHOD0(ReadRemoteObject, sptr<IRemoteObject>());
    MOCK_METHOD0(ReadBool, bool());
    MOCK_METHOD1(ReadBool, bool(bool &value));
    MOCK_METHOD1(WriteBool, bool(bool value));
    MOCK_METHOD1(WriteString, bool(const std::string &value));
    MOCK_METHOD1(WriteCString, bool(const char *value));
    MOCK_METHOD1(WriteFileDescriptor, bool(int fd));
    MOCK_METHOD0(ReadString, std::string());
    MOCK_METHOD1(ReadString, bool(std::string &value));
    MOCK_METHOD0(ReadFileDescriptor, int());
    MOCK_METHOD1(ReadStringVector, bool(std::vector<std::string> *value));
    MOCK_METHOD1(ReadUint32, bool(uint32_t &value));
    MOCK_METHOD1(WriteUint64, bool(uint64_t value));
    MOCK_METHOD1(WriteUint16, bool(uint16_t value));
    MOCK_METHOD1(WriteUint32, bool(uint32_t value));
    MOCK_METHOD1(ReadUint64, bool(uint64_t &value));
    MOCK_METHOD0(VerifySystemApp, bool());
    MOCK_METHOD0(CheckMouseCursor, bool());
    MOCK_METHOD0(CheckInputEventFilter, bool());
    MOCK_METHOD0(CheckInterceptor, bool());
    MOCK_METHOD0(CheckMonitor, bool());
    MOCK_METHOD0(CheckDispatchControl, bool());
    MOCK_METHOD0(CheckInfraredEmmit, bool());
    MOCK_METHOD0(CheckAuthorize, bool());
    MOCK_METHOD1(WriteBoolVector, bool(const std::vector<bool> &val));
    MOCK_METHOD1(WriteInt32Vector, bool(const std::vector<int32_t> &val));
    MOCK_METHOD0(ReadInt64, int64_t());
    MOCK_METHOD1(ReadInt64, bool(int64_t &value));
    MOCK_METHOD0(ReadFloat, float());
    MOCK_METHOD1(ReadFloat, bool(float &value));
    MOCK_METHOD0(ReadDouble, double());
    MOCK_METHOD1(ReadDouble, bool(double &value));
    MOCK_METHOD1(Unmarshalling, Media::PixelMap *(Parcel &parcel));
};
} // namespace MMI
} // namespace OHOS
#endif