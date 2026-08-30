#include "../parse_inject_value.h"
#include <cassert>
#include <cstdio>
#include <stdexcept>
#include <string>

using OHOS::MMI::ParseInjectValue;

static void ExpectOk(const char *s, int32_t want)
{
    int32_t out = 999;
    assert(ParseInjectValue(s, out));
    assert(out == want);
}

static void ExpectFail(const char *s)
{
    int32_t out = 42;
    assert(!ParseInjectValue(s, out));
}

static bool StoiThrows(const std::string &s)
{
    try {
        (void)std::stoi(s);
        return false;
    } catch (const std::out_of_range &) {
        return true;
    } catch (const std::invalid_argument &) {
        return true;
    }
}

int main()
{
    ExpectOk("0", 0);
    ExpectOk("1", 1);
    ExpectOk("-1", -1);
    ExpectOk("2147483647", 2147483647);
    ExpectOk("-2147483648", -2147483648);

    ExpectFail("");
    ExpectFail("12a");
    ExpectFail("a12");
    ExpectFail(" 1");
    ExpectFail("1 ");
    ExpectFail("2147483648");   // INT32_MAX+1, len 10 <= 11
    ExpectFail("-2147483649");  // INT32_MIN-1, len 11
    ExpectFail("99999999999");  // len 11 overflow

    assert(StoiThrows("2147483648"));
    assert(StoiThrows("-2147483649"));
    assert(StoiThrows(std::string(11, '9')));

    int32_t out = 0;
    assert(ParseInjectValue("2147483648", out) == false);
    assert(ParseInjectValue("-2147483649", out) == false);

    std::puts("parse_inject_value_host_test OK");
    return 0;
}
