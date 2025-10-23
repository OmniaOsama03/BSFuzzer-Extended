import json

def process_packets(file_path, target_packet_name):
    with open(file_path, 'r') as f:
        data = json.load(f)
    data = data['packets']

    
    results = []
    results_str =[]
    for entry in data:

        if ('packet_name_1' in entry and entry['packet_name_1'] == target_packet_name) or \
           ('packet_name_2' in entry and entry['packet_name_2'] == target_packet_name):
            
            
          
            if entry.get('cross_packet_dependency', False):
                
                other_packet = entry['packet_name_2'] if entry['packet_name_1'] == target_packet_name else entry['packet_name_1']
                
                results.append({
                    'Interdependent packet': other_packet,
                    'explanation': entry['explanation']
                })
    if results == []:
        print(f"No dependency found for {target_packet_name}")
        return []
   
    for result in results:
        

        key = list(result['explanation'].keys())
        value = list(result['explanation'].values())
        for i in range(len(value)):
            if "no direct" in value[i] or "No direct" in value[i]:
                pass
            else:
                single_result = "Interdependent packet:"+result['Interdependent packet']+",  "+"Interdependent field: "+key[i] + ":" + value[i]
                results_str.append(single_result)
    

    return results_str

def process_packets_identity(file_path, target_packet_name):
    with open(file_path, 'r') as f:
        data = json.load(f)
    data = data['packets']

    
    results = []
    results_str =[]
    for entry in data:

        if ('packet_name_1' in entry and entry['packet_name_1'] == target_packet_name) or \
           ('packet_name_2' in entry and entry['packet_name_2'] == target_packet_name):
            
            
          
            if entry.get('cross_packet_dependency', False):
                
                other_packet = entry['packet_name_2'] if entry['packet_name_1'] == target_packet_name else entry['packet_name_1']
                
                results.append({
                    'Interdependent packet': other_packet,
                    'explanation': entry['explanation']
                })
    
    interdependent_packet = []
    for result in results:
        interdependent_packet.append(result['Interdependent packet'])
    
    return ",".join(interdependent_packet)
    
    


def main():
    file_path = 'Semantic/data/sem_seed/deepseek-r1_pkt_dependency.json'
    target_packet = 'smp_pairing_failed_pkt'
    results = process_packets_identity(file_path, target_packet)
    # 获取results[0]['explanation']中的value
    print(results)

if __name__ == "__main__":
    main()