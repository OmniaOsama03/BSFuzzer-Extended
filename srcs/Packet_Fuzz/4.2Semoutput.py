import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../libs/")

from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *

import json
# from BSFuzz.srcs.prompt.SemFieldRspPrompt import get_prompt

from BSFuzz.srcs.prompt.Packet_Description import PacketDescriptionGenerator
from BSFuzz.srcs.prompt.SemFieldRspPrompt import get_prompt
import re

def analyze_mutation_result(self,packet_name, field_name, mutated_value, response_desc):
    packet_desc_gen = PacketDescriptionGenerator(self.semfuzz_xml_path)
    field_desc = packet_desc_gen.get_field_description(packet_name, field_name)
    self.prompt = get_prompt(FIELD_DESC=field_desc, MUTATED_VALUE=mutated_value, RESPONSE_PACKET_DESC=response_desc)
    result = self.llm.invoke(prompt=self.prompt)
    return result.content

def read_logs(log_path):
        logs = []
        try:
            with open(log_path, 'r') as f:
                # 每行都是一个独立的JSON对象
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        logs.append(log_entry)
                    except json.JSONDecodeError as e:
                        print(f"解析JSON行时出错: {e}")
                        continue
            
            print(f"成功读取 {len(logs)} 条日志记录")
            return logs
        except Exception as e:
            print(f"读取文件时出错: {e}")
            return False

def get_semoutput(log_path):
    logs = read_logs(log_path)
    for log in logs:
        base_path = log["base_path"]
        outputs = log["outputs"]
        mutation = log["mutation"]
        fuzz_result = log["fuzz_result"]
        if mutation is not None:
            #seed mutation
            print(log)

        else:
            #state mutation
            pass
        break
        
if __name__ == "__main__":
    logs = get_semoutput("/home/yangting/Documents/Semantic/result/log_file/Esp32/semfuzz_output.json")
    
     
