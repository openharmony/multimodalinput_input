/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <cctype>
#include <gtest/gtest.h>
#include <thread>
#include "mmi_log.h"
#include "virtual_stylus.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL { LOG_CORE, MMI_LOG_DOMAIN, "TransformPointTest" };
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
    MMI_HILOGD("open device node: \'%{public}s\'.", node_.c_str());
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
    static struct input_event* CountFrames(struct input_event* events, size_t nevents, size_t nframes);
    bool SendEvent(const Context& ctx, struct input_event* event);
    bool SendEvents(const Context& ctx, struct input_event* events, size_t nevents);
    static int Execute(const std::string& command, std::vector<std::string>& results);
    static void GetInputDeviceNodes(std::map<std::string, std::string>& nodes);
    static bool SetupVirtualStylus();
    static bool IsVirtualStylusOn();

private:
    static VirtualStylus virtualStylus_;
    static std::string  devNode_;
};

VirtualStylus TransformPointTest::virtualStylus_;
std::string TransformPointTest::devNode_;

void TransformPointTest::SetUpTestCase(void)
{
    SetupVirtualStylus();
}

void TransformPointTest::TearDownTestCase(void)
{
    if (!devNode_.empty()) {
        virtualStylus_.Close();
        devNode_.clear();
    }
}

std::string TransformPointTest::GetDeviceNodeName()
{
    return devNode_;
}

struct input_event* TransformPointTest::CountFrames(struct input_event* events, size_t nevents, size_t nframes)
{
    struct input_event* sp = events;
    struct input_event* tp = sp + nevents;
    size_t cnt = 0;

    for (; (sp < tp) && (cnt < nframes); ++sp) {
        if (sp->type == EV_SYN) {
            ++cnt;
        }
    }
    return (cnt >= nframes ? sp : nullptr);
}

bool TransformPointTest::SendEvent(const Context& ctx, struct input_event* event)
{
    MMI_HILOGD("send input event.");
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
    MMI_HILOGD("execute command: %{public}s.", command.c_str());
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
    MMI_HILOGD("close phandle.");
    return pclose(pin);
}

void TransformPointTest::GetInputDeviceNodes(std::map<std::string, std::string>& nodes)
{
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
    for (const auto& item : results) {
        MMI_HILOGD("item : %{public}s.", item.c_str());
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
    MMI_HILOGD("setup virtual stylus.");
    if (!virtualStylus_.SetUp()) {
        MMI_HILOGE("Failed to setup virtual stylus.");
        return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_FOR_INPUT));

    std::map<std::string, std::string> nodes;
    GetInputDeviceNodes(nodes);
    MMI_HILOGD("There are %{public}zu device nodes.", nodes.size());

    const std::string dev { "Virtual Stylus" };
    std::map<std::string, std::string>::const_iterator cItr = nodes.find(dev);
    if (cItr == nodes.cend()) {
        MMI_HILOGE("No virtual stylus is found.");
        return false;
    }
    MMI_HILOGD("node name : \'%{public}s\'.", cItr->second.c_str());
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
    { 0, 0, EV_ABS, ABS_X,               7950   },
    { 0, 0, EV_ABS, ABS_Y,               6400   },
    { 0, 0, EV_ABS, ABS_TILT_X,          10     },
    { 0, 0, EV_ABS, ABS_TILT_Y,          -10    },
    { 0, 0, EV_ABS, ABS_PRESSURE,        30     },
    { 0, 0, EV_SYN, SYN_REPORT,          0      },
    { 0, 0, EV_ABS, ABS_X,               8000   },
    { 0, 0, EV_ABS, ABS_PRESSURE,        30     },
    { 0, 0, EV_SYN, SYN_REPORT,          0      },
    { 0, 0, EV_ABS, ABS_X,               8050   },
    { 0, 0, EV_ABS, ABS_Y,               6450   },
    { 0, 0, EV_ABS, ABS_PRESSURE,        35     },
    { 0, 0, EV_SYN, SYN_REPORT,          0      },
    { 0, 0, EV_ABS, ABS_X,               8100   },
    { 0, 0, EV_ABS, ABS_Y,               6500   },
    { 0, 0, EV_ABS, ABS_PRESSURE,        1510   },
    { 0, 0, EV_SYN, SYN_REPORT,          0      },
    { 0, 0, EV_ABS, ABS_X,               8150   },
    { 0, 0, EV_ABS, ABS_PRESSURE,        1520   },
    { 0, 0, EV_SYN, SYN_REPORT,          0      },
    { 0, 0, EV_ABS, ABS_X,               8200   },
    { 0, 0, EV_ABS, ABS_Y,               6550   },
    { 0, 0, EV_ABS, ABS_PRESSURE,        1530   },
    { 0, 0, EV_SYN, SYN_REPORT,          0      },
    { 0, 0, EV_ABS, ABS_X,               8200   },
    { 0, 0, EV_ABS, ABS_Y,               6550   },
    { 0, 0, EV_ABS, ABS_PRESSURE,        0      },
    { 0, 0, EV_SYN, SYN_REPORT,          0      },
};

/**
 * @tc.name:MultimodalEventHandler_InjectKeyEvent_001
 * @tc.desc:Verify inject key Back
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransformPointTest, TabletTransformPointProcesser1, TestSize.Level1)
{
    ASSERT_TRUE(IsVirtualStylusOn());
    Context ctx { GetDeviceNodeName() };
    ASSERT_TRUE(SendEvents(ctx, inputEvents1, ARRAY_LENGTH(inputEvents1)));
}

static struct input_event inputEvents2[] {
    { 0, 0, EV_ABS, ABS_X,               10752  },
    { 0, 0, EV_ABS, ABS_Y,               22176  },
    { 0, 0, EV_ABS, ABS_TILT_X,          90     },
    { 0, 0, EV_ABS, ABS_TILT_Y,          90     },
    { 0, 0, EV_ABS, ABS_PRESSURE,        0      },
    { 0, 0, EV_SYN, SYN_REPORT,          0      },
    { 0, 0, EV_ABS, ABS_X,               10753  },
    { 0, 0, EV_ABS, ABS_TILT_X,          -90    },
    { 0, 0, EV_SYN, SYN_REPORT,          0      },
    { 0, 0, EV_ABS, ABS_Y,               22177  },
    { 0, 0, EV_ABS, ABS_TILT_Y,          -90    },
    { 0, 0, EV_ABS, ABS_PRESSURE,        50     },
    { 0, 0, EV_SYN, SYN_REPORT,          0      },
    { 0, 0, EV_ABS, ABS_TILT_X,          90     },
    { 0, 0, EV_ABS, ABS_PRESSURE,        1510   },
    { 0, 0, EV_SYN, SYN_REPORT,          0      },
    { 0, 0, EV_ABS, ABS_X,               40000  },
    { 0, 0, EV_ABS, ABS_TILT_X,          180    },
    { 0, 0, EV_ABS, ABS_PRESSURE,        4096   },
    { 0, 0, EV_SYN, SYN_REPORT,          0      },
    { 0, 0, EV_ABS, ABS_X,               50000  },
    { 0, 0, EV_ABS, ABS_TILT_X,          270    },
    { 0, 0, EV_ABS, ABS_PRESSURE,        100000 },
    { 0, 0, EV_SYN, SYN_REPORT,          0      },
    { 0, 0, EV_ABS, ABS_X,               60000  },
    { 0, 0, EV_ABS, ABS_Y,               6550   },
    { 0, 0, EV_ABS, ABS_TILT_X,          360    },
    { 0, 0, EV_ABS, ABS_PRESSURE,        0      },
    { 0, 0, EV_SYN, SYN_REPORT,          0      },
};

HWTEST_F(TransformPointTest, TabletTransformPointProcesser2, TestSize.Level1)
{
    ASSERT_TRUE(IsVirtualStylusOn());
    Context ctx { GetDeviceNodeName() };
    ASSERT_TRUE(SendEvents(ctx, inputEvents2, ARRAY_LENGTH(inputEvents2)));
}
} // namespace MMI
} // namespace OHOS
