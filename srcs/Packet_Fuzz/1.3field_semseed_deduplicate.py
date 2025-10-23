import json

def deduplicate_data(input_file, output_file):
    # 读取JSON文件
    with open(input_file, 'r') as f:
        data = json.load(f)
    
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
    input_file = "/home/yangting/Documents/Semantic/data/sem_seed/grok/field_semseed_parse.json"
    output_file = "/home/yangting/Documents/Semantic/data/sem_seed/grok/field_semseed_parse_deduplicated.json"
    deduplicate_data(input_file, output_file)