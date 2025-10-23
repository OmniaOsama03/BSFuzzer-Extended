import json
from datetime import datetime

def analyze_time_periods(json_file):
    # 存储时间段信息
    time_periods = []
    current_period = {
        'start_time': None,
        'end_time': None,
        'duration': 0,
        'logs': []
    }
    
    # 读取JSON文件
    with open(json_file, 'r') as f:
        prev_time = None
        
        for line in f:
            try:
                data = json.loads(line)
                current_time = datetime.strptime(data['time'], '%Y-%m-%d %H:%M:%S')
                
                # 如果是第一条记录
                if prev_time is None:
                    current_period['start_time'] = current_time
                    current_period['logs'].append(data['log'])
                else:
                    # 计算时间差（秒）
                    time_diff = (current_time - prev_time).total_seconds()
                    
                    # 如果时间差超过30秒，开始新的时间段
                    if time_diff > 30:
                        current_period['end_time'] = prev_time
                        current_period['duration'] = (current_period['end_time'] - current_period['start_time']).total_seconds()
                        time_periods.append(current_period)
                        
                        # 创建新的时间段
                        current_period = {
                            'start_time': current_time,
                            'end_time': None,
                            'duration': 0,
                            'logs': [data['log']]
                        }
                    else:
                        current_period['logs'].append(data['log'])
                
                prev_time = current_time
                
            except json.JSONDecodeError:
                print(f"警告：跳过无效的JSON行")
                continue
    
    # 处理最后一个时间段
    if current_period['start_time']:
        current_period['end_time'] = prev_time
        current_period['duration'] = (current_period['end_time'] - current_period['start_time']).total_seconds()
        time_periods.append(current_period)
    
    return time_periods

def print_time_periods(periods):
    print("\n时间段分析结果：")
    print("-" * 50)
    total_duration = 0
    
    for i, period in enumerate(periods, 1):
        start = period['start_time'].strftime('%H:%M:%S')
        end = period['end_time'].strftime('%H:%M:%S')
        duration = period['duration']
        total_duration += duration
        
        print(f"\n第{i}个时间段:")
        print(f"开始时间: {start}")
        print(f"结束时间: {end}")
        print(f"持续时间: {duration:.0f}秒")
        print(f"包含的日志编号: {period['logs']}")
    
    print("\n" + "-" * 50)
    print(f"总时间段数: {len(periods)}")
    print(f"总持续时间: {total_duration:.0f}秒 (约{total_duration/60:.1f}分钟)")

if __name__ == "__main__":
    json_file = "Semantic/result/log_file/Esp32/semfuzz_output.json"
    time_periods = analyze_time_periods(json_file)
    print_time_periods(time_periods) 