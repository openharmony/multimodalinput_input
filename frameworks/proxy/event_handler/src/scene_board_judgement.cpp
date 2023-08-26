#include "input_scene_board_judgement.h"

namespace OHOS {
namespace MMI {
bool MMISceneBoardJudgement::IsSceneBoardEnabled()
{
    static bool isSceneBoardEnabled = false;
    static bool initialized = false;
    if (!initialized) {
        InitWithConfigFile("/etc/sceneboard.config", isSceneBoardEnabled);
        initialized = true;
    }
    return isSceneBoardEnabled;
}

std::ifstream& MMISceneBoardJudgement::SafeGetLine(std::ifstream& configFile, std::string& line)
{
    std::getline(configFile, line);
    if (line.size() && line[line.size() - 1] == '\r') {
        line = line.substr(0, line.size() - 1);
    }
    return configFile;
}

void MMISceneBoardJudgement::InitWithConfigFile(const char* filePath, bool& enabled)
{
    std::ifstream configFile(filePath);
    std::string line;
    if (!(configFile.is_open() && SafeGetLine(configFile, line) && line == "DISABLED")) {
        enabled = true;
    }
    configFile.close();
}
} // namespace MMI
} // namespace OHOS
