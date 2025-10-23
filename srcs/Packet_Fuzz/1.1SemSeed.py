import os
import sys
import json

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")

from BSFuzz.srcs.Send_Packet.Bluetooth_SUL import Bluetooth_SUL
from BSFuzz.libs.driver.NRF52_dongle import NRF52Dongle

from BSFuzz.srcs.Log_Config.logger_config import *
from BSFuzz.srcs.Config_File.Cypress import config

import re
from time import sleep
from BSFuzz.srcs.llm_model.ModConf import ModelConfig
from BSFuzz.srcs.prompt.Packet_Description import PacketDescriptionGenerator
from BSFuzz.srcs.prompt.SemSeedPrompt import get_prompt


Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_legency_pkts",6:"test_sc_pkts"}

# sul config
advertiser_address = config.device["advertiser_address"]
iat = config.device["iat"]
rat = config.device["rat"]
role = config.device["role"]
rx_len = config.device["rx_len"]
tx_len = config.device["tx_len"]
test_layer = Layers[config.device["packet_layer"]]
config_file = config.device["config_file"]
logger_handle = config_file.split('/')[-1].split('.')[0]

logger = configure_logger( logger_handle, config.device["log_path"],logging.DEBUG)


return_handle_layer = [Layers[i] for i in config.device["return_handle_layer"]]
send_handle_layer = [Layers[i] for i in config.device["send_handle_layer"]]
port_name = config.device["port_name"]
logs_pcap = config.device["logs_pcap"]
pcap_filename = config.device["pcap_filename"]
key_path = config.device["key_path"]

ble_sul = Bluetooth_SUL(NRF52Dongle(port_name=port_name,logs_pcap=logs_pcap,pcap_filename=pcap_filename), advertiser_address,iat,rat, role,rx_len,tx_len ,logger_handle, key_path,test_layer, config_file, return_handle_layer=return_handle_layer,send_handle_layer=send_handle_layer)
alphabet=["scan_req","connect_req"]
# alphabet= ['ll_channel_map_req_pkt', 'll_terminate_ind_pkt', 'll_enc_req_pkt', 'll_enc_rsp_pkt', 'll_start_enc_req_pkt', 'll_start_enc_rsp_pkt', 'll_unknown_rsp_pkt', 'll_feature_req_pkt', 'll_feature_rsp_pkt', 'll_pause_enc_req_pkt', 'll_pause_enc_rsp_pkt', 'll_version_ind_pkt', 'll_reject_ind_pkt', 'll_slave_feature_req_pkt', 'll_connection_param_req_pkt', 'll_connection_param_rsp_pkt', 'll_reject_ind_ext_pkt', 'll_ping_req_pkt', 'll_ping_rsp_pkt', 'll_length_req_pkt', 'll_length_rsp_pkt']

# alphabet.extend(['master_identification_pkt','pairing_request_pkt', 'identity_information_pkt', 'pairing_response_pkt', 'pairing_confirm_pkt', 'pairing_random_pkt', 'pairing_failed_pkt', 'encryption_information_pkt',  'identity_address_information_pkt', 'signing_information_pkt', 'security_request_pkt', 'pairing_public_key_pkt', 'pairing_dhkey_check_pkt', 'pairing_keypress_notification_pkt'])
# print(prompt.format(packet_name="pairing request", field="io_cap"))
# alphabet.extend(['ll_connection_update_ind_pkt'])
# alphabet.extend(['pairing_response_pkt'])
# 加载 JSON 配置文件
with open("/home/yangting/Documents/Semantic/config/semseed_config.json", "r") as file:
    config = json.load(file)
    model_config = ModelConfig(config.get("llm", {}).get("model_provider"))

    model = config.get("llm", {}).get("model")
# 
    model_config.update_config({"model":config.get("llm", {}).get("model"),"temperature":config.get("llm", {}).get("temperature"),})
    print(model_config.get_config())
    llm = model_config.get_llm()
    xml_path = config.get("semext_merge", {}).get("xml_file_path")
    embedding_model = config.get("llm", {}).get("embedding_model")

    semseed_file_path_var = config.get("semseed", {}).get("field_seed_file_path")
    #将semseed_file_path中的${model_provider}替换为model_provider
    semseed_file_path = semseed_file_path_var.replace("${model_provider}",config.get("llm", {}).get("model_provider") )
    faiss_index_path = config.get("semext_merge", {}).get("faiss_index_path")
    packet_desc_gen = PacketDescriptionGenerator(xml_path)



def get_answer(packt_name, field):
    # 获取数据包描述
    # 使用配置文件中的 xml_path
    packet_description = packet_desc_gen.get_field_description(packt_name, field)  # 使用新的方法
    
    # 获取 SemSeed 提示并格式化
    print("Field Description:")
    print(packet_description)

    query_prompt = get_prompt(packet_description)
    
    # 直接使用 LLM 获取回答
    try:
        answer = llm.invoke(query_prompt)
        print("\nLLM Response:")
        # 检查 answer 是否为字符串或具有 content 属性的对象
        if isinstance(answer, str):
            print(answer)
            return answer
        else:
            print(answer.content)
            return answer.content
    except Exception as e:
        print(f"LLM 调用出错: {str(e)}")
        # 返回一个默认的回答，避免程序崩溃
    answer = llm.invoke(query_prompt)
    print("\nLLM Response:")
    print(answer.content)
    return answer.content

def answer_to_json(pkt_list):
    # 初始化 JSON 数据结构
    json_data = {
        "packets": []
    }
    
    if os.path.exists(semseed_file_path):
        with open(semseed_file_path, 'r') as f:
            try:
                json_data = json.load(f)
            except json.JSONDecodeError:
                print("Invalid JSON file, creating new one")
                json_data = {"packets": []}

    for pkt in pkt_list:
        packet_name = pkt["packet name"]
        field = pkt["field"]
        packet_exists = False
        
        for packet in json_data["packets"]:
            if packet["name"] == packet_name:
                field_exists = any(f["name"] == field for f in packet["fields"])
                if not field_exists:
                
                    print(f"\nProcessing {packet_name}.{field}")
                    answer = get_answer(packet_name, field)
                    print(answer)
                    try:
                        # 解析回答中的 JSON 字符串
                        answer_match = re.search(r'\[(.*)\]', answer, re.DOTALL)

                        if answer_match:
                            mutations = json.loads(answer_match.group())
                            field_data = {
                                "name": field,
                                "mutations": mutations
                            }
                            packet["fields"].append(field_data)
                            print(f"Successfully processed {packet_name}.{field}")
                        else:
                            print(f"No valid JSON found in answer for {packet_name}.{field}")
                    except Exception as e:
                        print(f"Error processing {packet_name}.{field}: {str(e)}")
                packet_exists = True
                break
        
        if not packet_exists:
            try:
                print(f"\nProcessing new packet {packet_name}.{field}")
                answer = get_answer(packet_name, field)

                
                answer_match = re.search(r'\[(.*)\]', answer, re.DOTALL)
                if answer_match:
                    mutations = json.loads(answer_match.group())
                    json_data["packets"].append({
                        "name": packet_name,
                        "fields": [{
                            "name": field,
                            "mutations": mutations
                        }]
                    })
                    print(f"Successfully added new packet {packet_name}.{field}")
                else:
                    print(f"No valid JSON found in answer for {packet_name}.{field}")
            except Exception as e:
                print(f"Error processing {packet_name}.{field}: {str(e)}")
        
        # 保存到文件
        print(f"Saving to {semseed_file_path}")
        with open(semseed_file_path, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        sleep(2)
    
    return json_data

def find_in_json(packet_name, field_name, json_data):
    """检查数据包和字段是否已存在于 JSON 数据中"""
    for packet in json_data.get("packets", []):
        if packet["name"] == packet_name:
            for field in packet.get("fields", []):
                if field["name"] == field_name:
                    return True
    return False

if __name__ == "__main__":
    pkt_list = packet_desc_gen.extract_packet_fields()
    print(pkt_list)

    answer_to_json(pkt_list)



