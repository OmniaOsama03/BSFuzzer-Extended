import os
import sys
import json
import traceback
import xml.etree.ElementTree as ET

import logging


sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS

from BSFuzz.srcs.Send_Packet.Bluetooth_SUL1 import Bluetooth_SUL
from BSFuzz.libs.driver.NRF52_dongle import NRF52Dongle

from BSFuzz.srcs.Log_Config.logger_config import *
from BSFuzz.srcs.Config_File.Cypress import config

import re
from time import sleep
from BSFuzz.srcs.llm_model.ModConf import ModelConfig
from BSFuzz.srcs.prompt.SemStateMutation import get_prompt
from BSFuzz.srcs.prompt.IndexPacketStatePrompt import get_question
from BSFuzz.srcs.Pdf_Sem.PdfDb import load_documents
from BSFuzz.srcs.Packet_Fuzz.process_dependency_identity import process_packets_identity


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
alphabet=[]
alphabet.extend(['ll_connection_update_ind_pkt', 'll_channel_map_req_pkt', 'll_terminate_ind_pkt', 'll_enc_req_pkt', 'll_enc_rsp_pkt', 'll_start_enc_req_pkt', 'll_start_enc_rsp_pkt', 'll_unknown_rsp_pkt', 'll_feature_req_pkt', 'll_feature_rsp_pkt', 'll_pause_enc_req_pkt', 'll_pause_enc_rsp_pkt', 'll_version_ind_pkt', 'll_reject_ind_pkt', 'll_slave_feature_req_pkt', 'll_connection_param_req_pkt', 'll_connection_param_rsp_pkt', 'll_reject_ind_ext_pkt', 'll_ping_req_pkt', 'll_ping_rsp_pkt', 'll_length_req_pkt', 'll_length_rsp_pkt'])
smp_alphabet = ['master_identification_pkt','pairing_request_pkt', 'identity_information_pkt', 'pairing_confirm_pkt', 'pairing_random_pkt', 'pairing_failed_pkt', 'encryption_information_pkt',  'identity_address_information_pkt', 'signing_information_pkt', 'security_request_pkt', 'pairing_public_key_pkt', 'pairing_dhkey_check_pkt', 'pairing_keypress_notification_pkt']
smp_alphabet_new = []
for pkt in smp_alphabet:
    if "smp_" in pkt:
        smp_alphabet_new.append(pkt)
    else:
        smp_alphabet_new.append("smp_" + pkt)
alphabet.extend(smp_alphabet_new)
# 加载 JSON 配置文件
with open("/home/yangting/Documents/Semantic/config/semseed_config.json", "r") as file:
    config = json.load(file)
    model_config = ModelConfig(config.get("llm", {}).get("model_provider"))
    model = config.get("llm", {}).get("model")
    model_config.update_config({"model":config.get("llm", {}).get("model"),"temperature":config.get("llm", {}).get("temperature"),})
    llm = model_config.get_llm()
    jg_model_name = config.get("llm", {}).get("jg_model")
    jg_model = ModelConfig("ali")
    jg_model.update_config({"model":config.get("llm", {}).get("jg_model"),"temperature":0,})
    jg_llm = jg_model.get_llm()



    xml_path = config.get("semext_merge", {}).get("xml_file_path")
   
    # state_seed_path = config.get("semseed_openai", {}).get("cross_field_seed_file_path")
    faiss_index_path = config.get("semext_merge", {}).get("faiss_index_path")
    documents = load_documents(config.get("semext_merge", {}).get("txt_path"))
    pkt_dependency_path_var = config.get("semseed", {}).get("pkt_dependency_path")
    # 在/home/yangting/Documents/Semantic/data/sem_seed/deepseek-r1/jg_model_name_pkt_dependency.json' 将pkt_dependency.json 替换
    pkt_dependency_path = pkt_dependency_path_var.replace("pkt_dependency.json",jg_model_name + "_pkt_dependency.json")


    state_seed_path_var = config.get("semseed", {}).get("state_seed_file_path")
    state_seed_path = state_seed_path_var.replace("${model_provider}",config.get("llm", {}).get("model_provider")).replace("state_seed.json","state_seed_sc.json")

if not state_seed_path:
    raise ValueError("state_seed_path not found in config file")




def parse_test_cases(xml_content):
    """解析XML格式的测试用例并转换为JSON格式"""
    test_cases = []
    
    # 首先提取packet name
    packet_name_match = re.search(r'<Packet name="([^"]+)">', xml_content)
    packet_name = packet_name_match.group(1) if packet_name_match else "Unknown"
    
    # 使用正则表达式匹配每个TestCase块
    test_case_pattern = r'<TestCase ScenarioType="([^"]+)">\s*<Analysis>\s*(.*?)\s*</Analysis>\s*<MutationSteps>\s*(.*?)\s*</MutationSteps>\s*<Validation>\s*(.*?)\s*</Validation>\s*</TestCase>'
    matches = re.finditer(test_case_pattern, xml_content, re.DOTALL)
    
    for match in matches:
        scenario_type = match.group(1)
        analysis = match.group(2).strip()
        mutation_steps = [step.strip() for step in match.group(3).split('\n') if step.strip()]
        validation = [v.strip() for v in match.group(4).split('\n') if v.strip()]
        
        test_case = {
            "packet_name": packet_name,
            "scenario_type": scenario_type,
            "analysis": analysis,
            "mutation_steps": mutation_steps,
            "validation": validation
        }
        test_cases.append(test_case)
    
    return test_cases

def save_test_cases_to_json(test_cases, output_file):
    """将测试用例保存到JSON文件"""
    # 如果文件存在且不为空，则读取并追加
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        with open(output_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if "test_cases" in data:
                data["test_cases"].extend(test_cases)
            else:
                data["test_cases"] = test_cases
    else:
        # 如果文件不存在或为空，创建新的数据结构
        data = {"test_cases": test_cases}
    
    # 保存到文件
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def get_answer(packet_name):
    """获取数据包的答案"""
    dependency_info = process_packets_identity(pkt_dependency_path, packet_name)
   
    question = get_prompt(packet_name,dependency_info)
    print(question)
    answer = llm.invoke(question)
    # print(answer.content)

    # 解析测试用例并保存到JSON
    test_cases = parse_test_cases(answer.content)
    output_file = os.path.join(os.path.dirname(state_seed_path), "state_seed_sc.json")
    save_test_cases_to_json(test_cases, output_file)

        
        

if __name__ == "__main__":
    # 取消注释以运行测试
    # test_json_functions()

    for i in alphabet:
        get_answer(i)
    
   
    




