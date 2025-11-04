import json


def read_concatenated_json_objects(path):
    """读取可能由多个顶层 JSON 对象首尾拼接的文件，返回对象列表。"""
    with open(path, 'r') as f:
        content = f.read()

    objects = []
    buffer = ''
    depth = 0

    for ch in content:
        if ch == '{':
            if depth == 0:
                buffer = ''
            depth += 1
            buffer += ch
        elif ch == '}':
            buffer += ch
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(buffer.strip())
                    objects.append(obj)
                except json.JSONDecodeError:
                    pass
                buffer = ''
        elif depth > 0:
            buffer += ch

    return objects

def deduplicate_data(input_file, output_file):
    # 读取（可能是多个顶层 JSON 对象拼接的）文件，并合并为一个 dict
    objects = read_concatenated_json_objects(input_file)
    data = {}
    for obj in objects:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if not isinstance(v, list):
                    continue
                if k not in data:
                    data[k] = []
                data[k].extend(v)
    
    # 存储去重后的数据
    deduplicated_data = {}
    
    # 对每个数据包类型进行处理
    for packet_type, packets in data.items():
        # 使用集合来存储唯一的参数组合
        unique_packets = set()
        deduplicated_packets = []
        
        # 处理每个数据包
        for packet in packets:
            # 将后三个参数组合成元组作为键
            key = tuple(packet[1:])
            if key not in unique_packets:
                unique_packets.add(key)
                deduplicated_packets.append(packet)
        
        # 将去重后的数据包添加到结果中
        deduplicated_data[packet_type] = deduplicated_packets
    
    # 将结果写入新文件
    with open(output_file, 'w') as f:
        json.dump(deduplicated_data, f, indent=4)

if __name__ == "__main__":
    input_file = "/home/yangting/Documents/BSFuzz/data/sem_seed/grok/field_semseed_parse.json"
    output_file = "/home/yangting/Documents/BSFuzz/data/sem_seed/grok/field_semseed_parse_deduplicated1.json"
    deduplicate_data(input_file, output_file)