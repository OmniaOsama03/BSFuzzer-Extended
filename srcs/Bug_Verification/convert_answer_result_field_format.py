import json
import re
from typing import List, Dict, Any


def read_concatenated_json_objects(path: str) -> List[Dict[str, Any]]:
    with open(path, "r") as f:
        content = f.read()

    objects: List[Dict[str, Any]] = []
    buffer: str = ""
    depth: int = 0

    for char in content:
        if char == '{':
            if depth == 0:
                buffer = ''
            depth += 1
            buffer += char
        elif char == '}':
            buffer += char
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(buffer.strip())
                    objects.append(obj)
                except json.JSONDecodeError:
                    # 跳过无法解析的片段
                    pass
                buffer = ''
        elif depth > 0:
            buffer += char

    return objects


def parse_info_str(info_str: str) -> Dict[str, Any]:
    # 目标：从形如
    # "layer_name: BTLE_ADV, field_name: RxAdd, semantic: ...., defined_values: ..." 中解析为字典
    result: Dict[str, Any] = {
        "layer_name": None,
        "field_name": None,
        "semantic": None,
        "defined_values": None,
    }

    # 先分离 defined_values（可能多行且包含逗号）
    m = re.search(r"\bdefined_values:\s*(.*)$", info_str, flags=re.DOTALL)
    if m:
        defined_values = m.group(1).strip()
        # 去掉结尾多余空白
        result["defined_values"] = defined_values
        head = info_str[:m.start()].rstrip(', ').strip()
    else:
        head = info_str.strip()

    # head 中应包含 layer_name, field_name, semantic 三段，以逗号加空格分隔
    # 使用更稳健的正则逐段提取
    ln = re.search(r"\blayer_name:\s*([^,]+)", head)
    fn = re.search(r"\bfield_name:\s*([^,]+)", head)
    se = re.search(r"\bsemantic:\s*(.*)$", head)

    if ln:
        result["layer_name"] = ln.group(1).strip()
    if fn:
        result["field_name"] = fn.group(1).strip()
    if se:
        result["semantic"] = se.group(1).strip()

    return result


def convert_record(obj: Dict[str, Any]) -> Dict[str, Any]:
    new_obj: Dict[str, Any] = {}

    info = obj.get("info_str")
    if isinstance(info, str):
        parsed = parse_info_str(info)
        new_obj["info_str"] = parsed
    elif isinstance(info, dict):
        # 已是目标结构
        new_obj["info_str"] = info
    else:
        new_obj["info_str"] = {
            "layer_name": None,
            "field_name": None,
            "semantic": None,
            "defined_values": None,
        }

    # 其余两段直接透传
    if "ProtocolComplianceCheck" in obj:
        new_obj["ProtocolComplianceCheck"] = obj["ProtocolComplianceCheck"]
    if "ExpectedDeviceBehavior" in obj:
        new_obj["ExpectedDeviceBehavior"] = obj["ExpectedDeviceBehavior"]

    return new_obj


def convert_file(src_path: str, dst_path: str) -> int:
    records = read_concatenated_json_objects(src_path)
    converted: List[Dict[str, Any]] = [convert_record(r) for r in records]

    # 以与源文件一致的“逐对象换行”写法输出，便于后续同样逐对象读取
    with open(dst_path, "w") as f:
        for obj in converted:
            f.write(json.dumps(obj, ensure_ascii=False, indent=2))
            f.write("\n")

    return len(converted)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Convert answer_result1.json records to field format (info_str as object)")
    parser.add_argument("src", help="source concatenated-json file path")
    parser.add_argument("dst", help="destination file path")
    args = parser.parse_args()

    count = convert_file(args.src, args.dst)
    print(f"Converted records: {count}")



