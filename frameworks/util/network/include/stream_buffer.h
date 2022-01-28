/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#ifndef OHOS_STREAM_BUFFER_H
#define OHOS_STREAM_BUFFER_H

#include <cxxabi.h>
#include <stdint.h>
#include <string>
#include "securec.h"
#include "log.h"
#include "config_multimodal.h"
#include "define_multimodal.h"
#include "error_multimodal.h"

namespace OHOS {
namespace MMI {
#define VNAME(name) (#name)
class StreamBuffer {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "StreamBuffer"};
public:
    explicit StreamBuffer();
    StreamBuffer(const StreamBuffer& buf);
    virtual ~StreamBuffer() {}
    virtual StreamBuffer& operator= (const StreamBuffer& other);

    void ResetBuf();

    void Clean();
    bool SetReadIdx(uint32_t idx);

    bool Read(std::string& buf);
    bool Write(const std::string& buf);
    bool Read(StreamBuffer& buf);
    bool Write(const StreamBuffer& buf);
    bool Read(char *buf, size_t size);
    bool Write(const char *buf, size_t size);
    bool IsEmpty();
    /*
     * Method:    Size
     * FullName:  CStreamBuffer::Size
     * Access:    public
     * Returns:   size_t
     * Qualifier: const valid size
     */
    size_t Size() const;

    /*
     * Method:    UnreadSize
     * FullName:  CStreamBuffer::UnreadSize
     * Access:    public
     * Returns:   size_t
     * Qualifier: const unread buf size
     */
    size_t UnreadSize() const;

    template<typename T>
    bool Read(T& data);

    template<typename T>
    bool Write(const T& data);

    bool ChkError() const;
    const char* GetErrorString() const;
    void ResetError();

    /*
    * Method:    Data
    * FullName:  CStreamBuffer::Data
    * Access:    public
    * Returns:   const char*
    * Qualifier: const buf pointer
    */
    const char *Data() const;

    template<typename T>
    const char* GetTypeName();

    template<typename T>
    StreamBuffer& operator >> (T& data);

    template<typename T>
    StreamBuffer& operator << (const T& data);

protected:
    /*
     * Method:    ReadBuf
     * FullName:  CStreamBuffer::ReadBuf
     * Access:    public
     * Returns:   const char*
     * Qualifier: const read position
     */
    const char *ReadBuf() const;

    /*
     * Method:    WriteBuf
     * FullName:  CStreamBuffer::WriteBuf
     * Access:    public
     * Returns:   const char*
     * Qualifier: const write position
     */
    const char *WriteBuf() const;

    bool Clone(const StreamBuffer& buf);

protected:
    enum class ErrorStatus : int8_t {
        ES_OK,
        ES_READ,
        ES_WRITE,
    };
    std::string rwErrStr_;
    ErrorStatus rwError_ = ErrorStatus::ES_OK;

    uint32_t rIdx_ = 0;
    uint32_t wIdx_ = 0;
    char szBuff_[MAX_STREAM_BUF_SIZE] = {};
};

template<typename T>
const char* StreamBuffer::GetTypeName()
{
    int status = 0;
    std::string tname = typeid(T).name();
    auto demName = abi::__cxa_demangle(tname.c_str(), nullptr, nullptr, &status);
    if (status == 0) {
        tname = demName;
        std::free(demName);
    }
    return tname.c_str();
}

template<typename T>
bool StreamBuffer::Write(const T &data)
{
    return Write(reinterpret_cast<char *>(const_cast<T *>(&data)), sizeof(data));
}

template<typename T>
StreamBuffer &StreamBuffer::operator<<(const T &data)
{
    //CK(Write(data), STREAM_BUF_WRITE_FAIL);
    if (!Write(data)) {

    }
    return *this;
}

template<typename T>
bool StreamBuffer::Read(T &data)
{
    return Read(reinterpret_cast<char *>(&data), sizeof(data));
}

template<typename T>
StreamBuffer &StreamBuffer::operator>>(T &data)
{
    //CK(Read(data), STREAM_BUF_READ_FAIL);
    if (!Read(data)) {

    }
    return *this;
}
}
}
#endif
