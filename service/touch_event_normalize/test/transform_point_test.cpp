/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <cctype>
#include <gtest/gtest.h>
#include <thread>

#include "mmi_log.h"
#include "virtual_pen.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TransformPointTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t WAIT_TIME_FOR_INPUT { 1000 };
constexpr int32_t WAIT_TIME_FOR_EVENTS { 10 };
constexpr size_t DEFAULT_BUF_SIZE { 4096 };
} // namespace

#define ARRAY_LENGTH(arr)   (sizeof(arr) / sizeof((arr)[0]))

class Context {
public:
    explicit Context(const std::string& node);
    ~Context();
    bool IsReady() const;
    int GetFd() const;

private:
    std::string node_;
    int fd_ { -1 };
};

Context::Context(const std::string& node)
    : node_(node)
{
    MMI_HILOGD("Open device node: \'%{public}s\'.", node_.c_str());
    fd_ = open(node_.c_str(), O_RDWR);
    if (fd_ < 0) {
        MMI_HILOGE("Failed to open device node: \'%{public}s\'.", node_.c_str());
    }
}

Context::~Context()
{
    if (fd_ >= 0) {
        close(fd_);
    }
}

inline bool Context::IsReady() const
{
    return (fd_ >= 0);
}

inline int Context::GetFd() const
{
    return fd_;
}

class TransformPointTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static std::string GetDeviceNodeName();
    static int Execute(const std::string& command, std::vector<std::string>& results);
    static void GetInputDeviceNodes(std::map<std::string, std::string>& nodes);
    static bool SetupVirtualStylus();
    static bool IsVirtualStylusOn();
    bool SendEvent(const Context& ctx, struct input_event* event);
    bool SendEvents(const Context& ctx, struct input_event* events, size_t nevents);

private:
    static VirtualPen virtualPen_;
    static std::string  devNode_;
};

VirtualPen TransformPointTest::virtualPen_;
std::string TransformPointTest::devNode_;

void TransformPointTest::SetUpTestCase(void)
{
    SetupVirtualStylus();
}

void TransformPointTest::TearDownTestCase(void)
{
    if (!devNode_.empty()) {
        virtualPen_.Close();
        devNode_.clear();
    }
}

std::string TransformPointTest::GetDeviceNodeName()
{
    return devNode_;
}

bool TransformPointTest::SendEvent(const Context& ctx, struct input_event* event)
{
    CALL_INFO_TRACE;
    MMI_HILOGD("Send input event.");
    struct timeval tv;
    if (gettimeofday(&tv, nullptr)) {
        MMI_HILOGE("Failed to get current time.");
        return false;
    }
    event->input_event_sec = tv.tv_sec;
    event->input_event_usec = tv.tv_usec;

    const int fd = ctx.GetFd();
    ssize_t ret = write(fd, event, sizeof(*event));
    return (ret > 0);
}

bool TransformPointTest::SendEvents(const Context& ctx, struct input_event* events, size_t nevents)
{
    CALL_INFO_TRACE;
    if (!ctx.IsReady()) {
        MMI_HILOGE("Device is not ready.");
        return false;
    }
    MMI_HILOGD("%{public}zu input events to send.", nevents);
    struct input_event* sp = events;
    struct input_event* tp = sp + nevents;
    for (; sp < tp; ++sp) {
        if (!SendEvent(ctx, sp)) {
            MMI_HILOGE("Failed to send event.");
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_FOR_EVENTS));
    }
    return (sp >= tp);
}

int TransformPointTest::Execute(const std::string& command, std::vector<std::string>& results)
{
    CALL_INFO_TRACE;
    MMI_HILOGD("Execute command:%{public}s.", command.c_str());
    char buffer[DEFAULT_BUF_SIZE] {};
    FILE* pin = popen(command.c_str(), "r");
    if (!pin) {
        MMI_HILOGE("Failed to popen command.");
        return -1;
    }
    while (!feof(pin)) {
        if (fgets(buffer, sizeof(buffer), pin) != nullptr) {
            results.push_back(buffer);
        }
    }
    MMI_HILOGD("Close phandle.");
    return pclose(pin);
}

void TransformPointTest::GetInputDeviceNodes(std::map<std::string, std::string>& nodes)
{
    CALL_INFO_TRACE;
    std::string command { "cat /proc/bus/input/devices" };
    std::vector<std::string> results;
    Execute(command, results);
    if (results.empty()) {
        MMI_HILOGE("Failed to list devices.");
        return;
    }
    const std::string kname { "Name=\"" };
    const std::string kevent { "event" };
    std::string name;
    for (const auto &item : results) {
        MMI_HILOGD("item:%{public}s.", item.c_str());
        if (item[0] == 'N') {
            std::string::size_type spos = item.find(kname);
            if (spos != std::string::npos) {
                spos += kname.size();
                std::string::size_type tpos = item.find("\"", spos);
                if (tpos != std::string::npos) {
                    name = item.substr(spos, tpos - spos);
                }
            }
        } else if (!name.empty() && (item[0] == 'H')) {
            std::string::size_type spos = item.find(kevent);
            if (spos != std::string::npos) {
                std::map<std::string, std::string>::const_iterator cItr = nodes.find(name);
                if (cItr != nodes.end()) {
                    nodes.erase(cItr);
                }
                std::string::size_type tpos = spos + kevent.size();
                while (std::isalnum(item[tpos])) {
                    ++tpos;
                }
                nodes.emplace(name, item.substr(spos, tpos - spos));
                name.clear();
            }
        }
    }
}

bool TransformPointTest::SetupVirtualStylus()
{
    CALL_INFO_TRACE;
    MMI_HILOGD("Setup virtual stylus.");
    if (!virtualPen_.SetUp()) {
        MMI_HILOGE("Failed to setup virtual stylus.");
        return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_FOR_INPUT));

    std::map<std::string, std::string> nodes;
    GetInputDeviceNodes(nodes);
    MMI_HILOGD("There are %{public}zu device nodes.", nodes.size());

    const std::string dev { "V-Pencil" };
    std::map<std::string, std::string>::const_iterator cItr = nodes.find(dev);
    if (cItr == nodes.cend()) {
        MMI_HILOGE("No virtual stylus is found.");
        return false;
    }
    MMI_HILOGD("Node name : \'%{public}s\'.", cItr->second.c_str());
    std::ostringstream ss;
    ss << "/dev/input/" << cItr->second;
    devNode_ = ss.str();
    return true;
}

bool TransformPointTest::IsVirtualStylusOn()
{
    return !devNode_.empty();
}

static struct input_event inputEvents1[] {
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_X,               7950   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_Y,               6400   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_TILT_X,          10     },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_TILT_Y,          -10    },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_PRESSURE,        30     },
    { .input_event_sec = 0, .input_event_usec = 0, EV_SYN, SYN_REPORT,          0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_X,               8000   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_PRESSURE,        30     },
    { .input_event_sec = 0, .input_event_usec = 0, EV_SYN, SYN_REPORT,          0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_X,               8050   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_Y,               6450   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_PRESSURE,        35     },
    { .input_event_sec = 0, .input_event_usec = 0, EV_SYN, SYN_REPORT,          0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_X,               8100   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_Y,               6500   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_PRESSURE,        1510   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_SYN, SYN_REPORT,          0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_X,               8150   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_PRESSURE,        1520   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_SYN, SYN_REPORT,          0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_X,               8200   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_Y,               6550   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_PRESSURE,        1530   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_SYN, SYN_REPORT,          0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_X,               8200   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_Y,               6550   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_PRESSURE,        0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_SYN, SYN_REPORT,          0      },
};

/**
 * @tc.name:MultimodalEventHandler_InjectKeyEvent_001
 * @tc.desc:Verify inject key Back
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransformPointTest, TabletTransformPointProcesser1, TestSize.Level1)
{
    CALL_INFO_TRACE;
    ASSERT_TRUE(IsVirtualStylusOn());
    Context ctx { GetDeviceNodeName() };
    ASSERT_TRUE(SendEvents(ctx, inputEvents1, ARRAY_LENGTH(inputEvents1)));
}

static struct input_event inputEvents2[] {
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_X,               10752  },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_Y,               22176  },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_TILT_X,          90     },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_TILT_Y,          90     },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_PRESSURE,        0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_SYN, SYN_REPORT,          0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_X,               10753  },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_TILT_X,          -90    },
    { .input_event_sec = 0, .input_event_usec = 0, EV_SYN, SYN_REPORT,          0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_Y,               22177  },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_TILT_Y,          -90    },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_PRESSURE,        50     },
    { .input_event_sec = 0, .input_event_usec = 0, EV_SYN, SYN_REPORT,          0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_TILT_X,          90     },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_PRESSURE,        1510   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_SYN, SYN_REPORT,          0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_X,               40000  },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_TILT_X,          180    },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_PRESSURE,        4096   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_SYN, SYN_REPORT,          0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_X,               50000  },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_TILT_X,          270    },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_PRESSURE,        100000 },
    { .input_event_sec = 0, .input_event_usec = 0, EV_SYN, SYN_REPORT,          0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_X,               60000  },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_Y,               6550   },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_TILT_X,          360    },
    { .input_event_sec = 0, .input_event_usec = 0, EV_ABS, ABS_PRESSURE,        0      },
    { .input_event_sec = 0, .input_event_usec = 0, EV_SYN, SYN_REPORT,          0      },
};

HWTEST_F(TransformPointTest, TabletTransformPointProcesser2, TestSize.Level1)
{
    CALL_INFO_TRACE;
    ASSERT_TRUE(IsVirtualStylusOn());
    Context ctx { GetDeviceNodeName() };
    ASSERT_TRUE(SendEvents(ctx, inputEvents2, ARRAY_LENGTH(inputEvents2)));
}
} // namespace MMI
} // namespace OHOS
