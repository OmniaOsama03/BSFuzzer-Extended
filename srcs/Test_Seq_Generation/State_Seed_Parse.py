import json

def transform_mutations(input_file, output_file):
    # 读取输入文件
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    result = []
    for test_case in data['test_cases']:
        # 创建新的格式
        new_format = {
            "packet_name": test_case["packet_name"],
            "path": []
        }
        
        # 处理 mutation_steps
        for step in test_case["mutation_steps"]:
            if "Send" in step:
                # 提取包名
                packet = step.split("Send ")[-1].strip(".").strip()
                new_format["path"].append(packet)
        
        # 将 path 转换为逗号分隔的字符串
        new_format["path"] = ",".join(new_format["path"])
        result.append(new_format)
    
    # 写入输出文件
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)

if __name__ == "__main__":
    transform_mutations('/home/yangting/Documents/BSFuzz/data/sem_seed/grok/state_seed_legency.json', '/home/yangting/Documents/BSFuzz/data/sem_seed/grok/state_seed_legency_parsed.json') 