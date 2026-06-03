#!/usr/bin/env python3
"""
ohos_callgraph.py — OpenHarmony 全链路函数调用图分析器

从 LLVM bitcode (.o) 提取调用图，自动穿越 dlopen/dlsym 动态加载边界
和 vtable 虚函数间接调用，输出从指定函数出发的完整调用树。

用法:
    python3 ohos_callgraph.py <function_name> [--depth N] [--out-dir <dir>]
    python3 ohos_callgraph.py UpdateMouseTarget --depth 3
    python3 ohos_callgraph.py HandleKeyboardEvent --depth 4 --reverse

原理:
    1. 扫描 out/rk3568/obj/ 下所有 .o (LLVM bitcode) 文件
    2. 用 opt --print-callgraph 提取直接调用
    3. 用 llvm-dis 导出 IR，解析 vtable indirect call 的类型元数据
    4. 匹配 ComponentManager::LoadLibrary<Interface> 模式，穿越 dlopen 边界
    5. 输出调用树 + 标注每条边的类型（direct/vtable/dlopen）

要求:
    - OpenHarmony 已编译成功（需要 .o bitcode 文件）
    - LLVM 工具链可用（opt, llvm-dis, llvm-cxxfilt, llvm-nm）
"""

import argparse
import glob
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# ── 配置 ──────────────────────────────────────────────────────

DEFAULT_OH_ROOT = None  # 自动检测

LLVM_TOOLS = None  # 自动检测

# dlopen 映射表：接口类 -> (so名, CreateInstance所在源文件, 具体实现类)
# 通过 grep "LoadLibrary<" + grep "extern.*C.*CreateInstance" 自动发现
DLOPEN_REGISTRY = {}

# ── 工具函数 ──────────────────────────────────────────────────

def find_oh_root():
    """从当前目录向上查找 OpenHarmony 根目录"""
    p = Path.cwd()
    while p != p.parent:
        if (p / "build" / "ohos.gni").exists():
            return str(p)
        if (p / "out" / "rk3568").exists():
            return str(p)
        p = p.parent
    # 尝试环境变量
    for env in ["OH_ROOT", "OHOS_ROOT"]:
        v = os.environ.get(env)
        if v and os.path.isdir(v):
            return v
    return None


def find_llvm_tools(oh_root):
    """找到 LLVM 工具链路径"""
    candidates = [
        os.path.join(oh_root, "prebuilts/clang/ohos/linux-x86_64/llvm/bin"),
        os.path.join(oh_root, "prebuilts/clang/ohos/linux-aarch64/llvm/bin"),
    ]
    for c in candidates:
        if os.path.isfile(os.path.join(c, "opt")):
            return c
    return None


def run(cmd, timeout=120):
    """执行命令，返回 stdout"""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        out = r.stdout.decode("utf-8", errors="replace")
        err = r.stderr.decode("utf-8", errors="replace")
        return out + err
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def demangle(llvm_bin, mangled):
    """C++ 符号 demangle"""
    r = run([os.path.join(llvm_bin, "llvm-cxxfilt"), mangled])
    return r.strip() if r.strip() else mangled


def demangle_batch(llvm_bin, symbols):
    """批量 demangle"""
    if not symbols:
        return {}
    inp = "\n".join(symbols)
    r = subprocess.run(
        [os.path.join(llvm_bin, "llvm-cxxfilt")],
        input=inp.encode(), capture_output=True, timeout=30
    )
    r.stdout = r.stdout.decode("utf-8", errors="replace")
    results = r.stdout.strip().split("\n")
    mapping = {}
    for mangled, demangled in zip(symbols, results):
        mapping[mangled] = demangled.strip()
    return mapping


# ── 核心分析 ──────────────────────────────────────────────────

def find_bitcode_files(obj_dir, repo_filter=None):
    """扫描 obj 目录找所有 LLVM bitcode .o 文件"""
    pattern = os.path.join(obj_dir, "**", "*.o")
    files = []
    for f in glob.iglob(pattern, recursive=True):
        if "/test/" in f or "/mock/" in f:
            continue
        if repo_filter and repo_filter not in f:
            continue
        files.append(f)
    return files


def extract_callgraph(llvm_bin, obj_file):
    """从单个 .o bitcode 提取调用图"""
    opt = os.path.join(llvm_bin, "opt")
    output = run([opt, "--print-callgraph", obj_file], timeout=60)

    graph = defaultdict(set)
    current_func = None

    for line in output.split("\n"):
        m = re.match(r"Call graph node for function: '([^']+)'", line)
        if m:
            current_func = m.group(1)
            continue

        if current_func:
            m2 = re.match(r"  CS<[^>]*> calls function '([^']+)'", line)
            if m2:
                callee = m2.group(1)
                if callee != current_func:  # 排除递归
                    graph[current_func].add(("direct", callee))

            # 外部节点（间接调用）
            if "calls external node" in line:
                graph[current_func].add(("indirect", None))

        if line.strip() == "":
            current_func = None

    return graph


def extract_vtable_calls(llvm_bin, obj_file):
    """从 LLVM IR 提取虚函数间接调用的接口类型"""
    llvm_dis = os.path.join(llvm_bin, "llvm-dis")
    ll_path = f"/tmp/ohos_cg_{os.path.basename(obj_file)}.ll"
    run([llvm_dis, "-o", ll_path, obj_file], timeout=60)

    vtable_calls = defaultdict(set)  # func -> set of interface class names

    if not os.path.exists(ll_path):
        return vtable_calls

    current_func = None
    with open(ll_path, "r") as f:
        for line in f:
            # 函数定义
            m = re.match(r"define\s.*@([^\s(]+)", line)
            if m:
                current_func = m.group(1).strip('"')
                continue
            if line.startswith("}"):
                current_func = None
                continue
            # type.test 调用 —— 揭示虚函数调用的接口类型
            if current_func and "type.test" in line:
                m2 = re.search(r'metadata\s*!"(_ZTS[^"]+)"', line)
                if m2:
                    mangled_type = m2.group(1)
                    vtable_calls[current_func].add(mangled_type)

    try:
        os.unlink(ll_path)
    except OSError:
        pass

    return vtable_calls


def discover_dlopen_map(src_root):
    """自动发现 dlopen 映射：Interface -> .so -> ConcreteClass"""
    registry = {}

    # 1. 找所有 LoadLibrary<Interface> 调用
    load_calls = run(
        ["grep", "-rn", "LoadLibrary<", src_root,
         "--include=*.cpp", "--include=*.h"],
        timeout=30
    )
    # 2. 找所有 extern "C" CreateInstance
    create_calls = run(
        ["grep", "-rn", "extern.*C.*CreateInstance", src_root,
         "--include=*.cpp"],
        timeout=30
    )
    # 3. 找 .so 名称常量
    so_names = run(
        ["grep", "-rn", 'constexpr.*char.*LIB_.*"', src_root,
         "--include=*.cpp", "--include=*.h"],
        timeout=30
    )

    # 解析 .so 名称
    so_map = {}
    for line in so_names.split("\n"):
        m = re.search(r'constexpr\s+char\s+(\w+)\[\]\s*\{\s*"([^"]+)"', line)
        if m:
            so_map[m.group(1)] = m.group(2)

    # 解析 CreateInstance -> 具体实现类
    create_map = {}  # interface -> (source_file, impl_class)
    for line in create_calls.split("\n"):
        m = re.match(r"([^:]+):.*(\w+)\*\s*CreateInstance", line)
        if m:
            src_file = m.group(1)
            iface = m.group(2)
            # 实现类通常是 new XxxYyy(env) 在同文件里
            create_map[iface] = src_file

    # 解析 LoadLibrary<Interface>(env, LIB_XXX_NAME)
    for line in load_calls.split("\n"):
        m = re.search(r"LoadLibrary<(\w+)>\s*\([^,]+,\s*(\w+)\)", line)
        if m:
            iface = m.group(1)
            lib_const = m.group(2)
            so_name = so_map.get(lib_const, lib_const)
            impl_src = create_map.get(iface, "")
            registry[iface] = {
                "so": so_name,
                "create_src": impl_src,
                "interface": iface,
            }

    return registry


def resolve_vtable_to_impl(mangled_type, dlopen_map, llvm_bin):
    """将 vtable 类型元数据解析为可能的实现类"""
    demangled = demangle(llvm_bin, mangled_type)
    # typeinfo for OHOS::MMI::IInputWindowsManager -> IInputWindowsManager
    m = re.search(r"(\w+)$", demangled)
    if not m:
        return demangled, []

    iface_name = m.group(1)

    # 检查 dlopen 映射
    if iface_name in dlopen_map:
        info = dlopen_map[iface_name]
        return iface_name, [f"[dlopen:{info['so']}] {info.get('create_src', '?')}"]

    return iface_name, [f"[vtable] {iface_name} (in-process)"]


# ── 调用树构建 ────────────────────────────────────────────────

def build_call_tree(target_func, all_graphs, vtable_info, dlopen_map,
                    llvm_bin, max_depth=5, reverse=False):
    """构建从 target_func 出发的调用树"""
    # 合并所有 .o 的调用图
    merged = defaultdict(set)
    for graph in all_graphs:
        for caller, callees in graph.items():
            merged[caller].update(callees)

    # 合并 vtable 信息
    merged_vtable = defaultdict(set)
    for vt in vtable_info:
        for func, types in vt.items():
            merged_vtable[func].update(types)

    # 找到目标函数（支持部分匹配）
    all_funcs = set(merged.keys())
    for graph in all_graphs:
        for callees in graph.values():
            for _, callee in callees:
                if callee:
                    all_funcs.add(callee)

    # demangle 所有函数名
    demangled = demangle_batch(llvm_bin, list(all_funcs))

    matches = []
    for mangled in all_funcs:
        dm = demangled.get(mangled, mangled)
        if target_func in dm or target_func in mangled:
            matches.append((mangled, dm))

    if not matches:
        print(f"未找到包含 '{target_func}' 的函数", file=sys.stderr)
        print(f"提示：搜索范围内共 {len(all_funcs)} 个函数", file=sys.stderr)
        return

    if len(matches) > 1:
        print(f"找到 {len(matches)} 个匹配，使用第一个：", file=sys.stderr)
        for m, d in matches[:5]:
            print(f"  {d}", file=sys.stderr)

    root_mangled, root_demangled = matches[0]
    print(f"\n{'=' * 80}")
    print(f"调用图: {root_demangled}")
    print(f"{'=' * 80}\n")

    if reverse:
        _print_callers(root_mangled, merged, demangled, max_depth)
    else:
        visited = set()
        _print_callees(root_mangled, merged, merged_vtable, demangled,
                       dlopen_map, llvm_bin, max_depth, 0, visited)


def _short_name(demangled):
    """缩短函数名：只保留类名::方法名"""
    # OHOS::MMI::InputWindowsManager::GetCursorPos(int) -> InputWindowsManager::GetCursorPos
    m = re.search(r"(\w+::\w+)\s*\(", demangled)
    if m:
        return m.group(1)
    m = re.search(r"(\w+)\s*\(", demangled)
    if m:
        return m.group(1)
    return demangled


def _print_callees(func, graph, vtable_info, demangled, dlopen_map,
                   llvm_bin, max_depth, depth, visited):
    """递归打印被调用函数树"""
    if depth > max_depth or func in visited:
        return
    visited.add(func)

    indent = "  " * depth
    dm = demangled.get(func, func)
    short = _short_name(dm)

    callees = graph.get(func, set())

    # 过滤掉 hilog/utility 函数
    skip_prefixes = ["HiLog", "std::__h::", "OHOS::MMI::FormatLog",
                     "OHOS::MMI::GetSysClockTime", "OHOS::MMI::InnerFunction",
                     "__cfi_slowpath", "libinput_event_get_type"]

    for call_type, callee in sorted(callees, key=lambda x: x[1] or ""):
        if callee is None:
            continue
        callee_dm = demangled.get(callee, callee)
        if any(callee_dm.startswith(p) for p in skip_prefixes):
            continue

        callee_short = _short_name(callee_dm)
        tag = ""
        if call_type == "indirect":
            tag = " [indirect]"
        print(f"{indent}├── {callee_short}{tag}")
        _print_callees(callee, graph, vtable_info, demangled, dlopen_map,
                       llvm_bin, max_depth, depth + 1, visited)

    # vtable 间接调用
    for vtype in sorted(vtable_info.get(func, set())):
        iface_name, impls = resolve_vtable_to_impl(vtype, dlopen_map, llvm_bin)
        for impl in impls:
            print(f"{indent}├── {iface_name} {impl}")


def _print_callers(func, graph, demangled, max_depth):
    """反向：谁调用了这个函数"""
    # 构建反向图
    reverse = defaultdict(set)
    for caller, callees in graph.items():
        for _, callee in callees:
            if callee:
                reverse[callee].add(caller)

    print("谁调用了这个函数：\n")
    visited = set()
    _print_callers_recursive(func, reverse, demangled, max_depth, 0, visited)


def _print_callers_recursive(func, reverse, demangled, max_depth, depth, visited):
    if depth > max_depth or func in visited:
        return
    visited.add(func)

    indent = "  " * depth
    callers = reverse.get(func, set())
    for caller in sorted(callers):
        dm = demangled.get(caller, caller)
        short = _short_name(dm)
        print(f"{indent}├── {short}")
        _print_callers_recursive(caller, reverse, demangled, max_depth, depth + 1, visited)


# ── 主流程 ────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="OpenHarmony 全链路函数调用图分析器（支持 dlopen 穿越）"
    )
    parser.add_argument("function", help="要分析的函数名（支持部分匹配）")
    parser.add_argument("--depth", type=int, default=3, help="调用树深度（默认 3）")
    parser.add_argument("--reverse", action="store_true", help="反向查询：谁调用了这个函数")
    parser.add_argument("--oh-root", help="OpenHarmony 根目录（默认自动检测）")
    parser.add_argument("--repo", help="只分析指定仓（如 multimodalinput）")
    parser.add_argument("--product", default="rk3568", help="产品名（默认 rk3568）")
    args = parser.parse_args()

    # 检测环境
    oh_root = args.oh_root or find_oh_root()
    if not oh_root:
        print("错误：找不到 OpenHarmony 根目录，请用 --oh-root 指定", file=sys.stderr)
        sys.exit(1)

    llvm_bin = find_llvm_tools(oh_root)
    if not llvm_bin:
        print("错误：找不到 LLVM 工具链", file=sys.stderr)
        sys.exit(1)

    obj_dir = os.path.join(oh_root, "out", args.product, "obj")
    if not os.path.isdir(obj_dir):
        print(f"错误：{obj_dir} 不存在，请先编译", file=sys.stderr)
        sys.exit(1)

    src_root = os.path.join(oh_root, "foundation/multimodalinput/input")

    print(f"OH root: {oh_root}", file=sys.stderr)
    print(f"LLVM: {llvm_bin}", file=sys.stderr)
    print(f"产品: {args.product}", file=sys.stderr)

    # 发现 dlopen 映射
    print("发现 dlopen 映射...", file=sys.stderr)
    dlopen_map = discover_dlopen_map(src_root)
    for iface, info in dlopen_map.items():
        print(f"  {iface} -> {info['so']}", file=sys.stderr)

    # 扫描 bitcode 文件
    repo_filter = args.repo
    if not repo_filter:
        repo_filter = "multimodalinput"
    print(f"扫描 bitcode 文件 (filter={repo_filter})...", file=sys.stderr)
    obj_files = find_bitcode_files(obj_dir, repo_filter)
    print(f"找到 {len(obj_files)} 个 bitcode 文件", file=sys.stderr)

    # 提取调用图
    all_graphs = []
    all_vtable = []
    for i, obj_file in enumerate(obj_files):
        if (i + 1) % 20 == 0:
            print(f"  分析 {i+1}/{len(obj_files)}...", file=sys.stderr)

        graph = extract_callgraph(llvm_bin, obj_file)
        if graph:
            all_graphs.append(graph)

        vtable = extract_vtable_calls(llvm_bin, obj_file)
        if vtable:
            all_vtable.append(vtable)

    print(f"分析完成，共 {sum(len(g) for g in all_graphs)} 个调用节点", file=sys.stderr)

    # 构建调用树
    build_call_tree(
        args.function, all_graphs, all_vtable, dlopen_map,
        llvm_bin, max_depth=args.depth, reverse=args.reverse
    )


if __name__ == "__main__":
    main()
