import os
import argparse
import importlib.util
from typing import List, Tuple


PROJECT_ROOT = "/home/yangting/Documents/BSFuzz"
MSG_CHART_DIR = os.path.join(PROJECT_ROOT, "data", "Message_Chart")
PROMPT_FILE = os.path.join(PROJECT_ROOT, "srcs", "prompt", "1.1State_Construction.py")
MODCONF_FILE = os.path.join(PROJECT_ROOT, "srcs", "llm_model", "ModConf.py")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "result", "state_construction")


def _load_get_field_prompt():
    spec = importlib.util.spec_from_file_location("state_construction_prompt", PROMPT_FILE)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    if not hasattr(module, "get_field_prompt"):
        raise AttributeError("get_field_prompt not found in 1.1State_Construction.py")
    return getattr(module, "get_field_prompt")


def _load_model_config_class():
    spec = importlib.util.spec_from_file_location("modconf", MODCONF_FILE)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    if not hasattr(module, "ModelConfig"):
        raise AttributeError("ModelConfig not found in ModConf.py")
    return getattr(module, "ModelConfig")


def _read_markdown_files(base_dir: str) -> List[Tuple[str, str, str]]:
    collected: List[Tuple[str, str, str]] = []
    for root, _, files in os.walk(base_dir):
        for fname in files:
            if not fname.lower().endswith(".md"):
                continue
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, base_dir)
            rel_stem = os.path.splitext(rel_path)[0]
            name_stem = os.path.splitext(os.path.basename(fname))[0]
            with open(full_path, "r", encoding="utf-8") as rf:
                content = rf.read()
            collected.append((rel_stem, name_stem, content))
    return collected


def _ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description="Extract md to DOT via LLM with selected provider")
    parser.add_argument("--model_provider", type=str, default="google",
                        choices=["openai", "grok", "deepseek", "hw", "nivida", "ali", "google", "Zeta"],
                        help="选择使用的大模型提供商（默认: google）")
    parser.add_argument("--limit", type=int, default=0, help="仅处理前N个文件（0为全部）")
    parser.add_argument("--dry", action="store_true", help="只打印提示词，不调用模型")
    parser.add_argument("--out", type=str, default=OUTPUT_DIR, help="输出目录，保存为 .dot")
    args = parser.parse_args()

    get_field_prompt = _load_get_field_prompt()
    ModelConfig = _load_model_config_class()

    if not args.dry:
        model_conf = ModelConfig(model_provider=args.model_provider)
        llm = model_conf.get_llm()
    else:
        llm = None

    items = _read_markdown_files(MSG_CHART_DIR)
    if args.limit > 0:
        items = items[: args.limit]

    total = len(items)
    if total == 0:
        print("未在 Message_Chart 目录中找到任何 .md 文件")
        return

    print(f"发现 {total} 个 .md 文件，开始处理……")

    for idx, (rel_stem, name_stem, md_text) in enumerate(items, start=1):
        print(f"[{idx}/{total}] 处理: {rel_stem}.md -> FILENAME={name_stem}")
        prompt_text = get_field_prompt(FILENAME=name_stem, MARKDOWN_TEXT=md_text)

        if args.dry:
            print("----- Prompt Preview Start -----")
            print(prompt_text)
            print("----- Prompt Preview End -----")
            continue

        try:
            result = llm.invoke(prompt_text)  # type: ignore[union-attr]
            output_text = getattr(result, "content", None) or str(result)
        except Exception as e:
            print(f"调用模型失败: {e}")
            output_text = f"ERROR: {e}"

        out_path = os.path.join(args.out, f"{rel_stem}.dot")
        _ensure_parent_dir(out_path)
        with open(out_path, "w", encoding="utf-8") as wf:
            wf.write(output_text)
        print(f"已写出: {out_path}")

    print("全部完成。")


if __name__ == "__main__":
    main()


