/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

int main()
{
    std::cout << "=== Mouse API Hidumper Test ===" << std::endl;

    std::cout << "[1] Testing hidumper -s 3101 -a -G ..." << std::endl;
    int ret = system("hidumper -s 3101 -a -G > /data/local/tmp/hidumper_g_test.txt 2>&1");
    std::cout << "  system() returned: " << ret << std::endl;

    std::cout << "[2] Checking sections in output..." << std::endl;
    FILE *f = fopen("/data/local/tmp/hidumper_g_test.txt", "r");
    if (!f) {
        std::cerr << "FAIL: cannot read output file" << std::endl;
        return 1;
    }

    char line[512];
    bool hasRuntimeBindings = false;
    bool hasDisplayGroups = false;
    bool hasPointerState = false;
    bool hasKeyboardState = false;
    bool hasSequenceSnapshots = false;

    while (fgets(line, sizeof(line), f)) {
        std::string s(line);
        if (s.find("RuntimeBindings") != std::string::npos) hasRuntimeBindings = true;
        if (s.find("DisplayGroups") != std::string::npos) hasDisplayGroups = true;
        if (s.find("PointerStateByGroup") != std::string::npos) hasPointerState = true;
        if (s.find("KeyboardStateByGroup") != std::string::npos) hasKeyboardState = true;
        if (s.find("SequenceSnapshots") != std::string::npos) hasSequenceSnapshots = true;
    }
    fclose(f);

    int pass = 0;
    int total = 5;
    auto check = [&](bool ok, const char *name) {
        std::cout << "  " << (ok ? "PASS" : "FAIL") << ": " << name << std::endl;
        if (ok) pass++;
    };
    check(hasRuntimeBindings, "RuntimeBindings section");
    check(hasDisplayGroups, "DisplayGroups section");
    check(hasPointerState, "PointerStateByGroup section");
    check(hasKeyboardState, "KeyboardStateByGroup section");
    check(hasSequenceSnapshots, "SequenceSnapshots section");

    std::cout << "=== " << pass << "/" << total << " PASSED ===" << std::endl;
    return pass == total ? 0 : 1;
}
