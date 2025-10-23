import os
import sys
import json
import traceback

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")

from BSFuzz.srcs.Send_Packet.Bluetooth_SUL1 import Bluetooth_SUL
from BSFuzz.libs.driver.NRF52_dongle import NRF52Dongle

from BSFuzz.srcs.Log_Config.logger_config import *
from BSFuzz.srcs.Config_File.Cypress import config

import re
from BSFuzz.srcs.llm_model.ModConf import ModelConfig
from BSFuzz.srcs.prompt.SemCrossFieldMutation import get_prompt

from BSFuzz.srcs.Pdf_Sem.PdfDb import load_documents
from BSFuzz.srcs.prompt.Packet_Description import PacketDescriptionGenerator
from BSFuzz.srcs.prompt.IndexPacketPrompt import get_question
from BSFuzz.srcs.Packet_Fuzz.process_dependency_identity import process_packets


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
base_path = "LL Feature Request → LL Length Request → LL Version Ind → Pairing Request → Pairing Confirm → Pairing Random → LL Encryption Request → LL Start Encryption Response → LL Pause Encryptin Request"


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


# print(prompt.format(packet_name="pairing request", field="io_cap"))
# alphabet.extend(['ll_connection_update_ind_pkt'])
# alphabet.remove(['pairing_request_pkt'])
# 加载 JSON 配置文件
with open("/home/yangting/Documents/Semantic/config/semseed_config.json", "r") as file:
    config = json.load(file)
    model_config = ModelConfig(config.get("llm", {}).get("model_provider"))
    model = config.get("llm", {}).get("model")
    model_config.update_config({"model":config.get("llm", {}).get("model"),"temperature":config.get("llm", {}).get("temperature"),})
    llm = model_config.get_llm()

    jg_model = ModelConfig("ali")
    jg_model_name = config.get("llm", {}).get("jg_model")
    jg_model.update_config({"model":jg_model_name,"temperature":0})
    jg_llm = jg_model.get_llm()
    print(jg_llm.model_name)



    xml_path = config.get("semext_merge", {}).get("xml_file_path")
   
    semseed_file_path_var = config.get("semseed", {}).get("cross_field_seed_file_path")

    semseed_file_path = semseed_file_path_var.replace("${model_provider}",config.get("llm", {}).get("model_provider") )
    faiss_index_path = config.get("semext_merge", {}).get("faiss_index_path")
    documents = load_documents(config.get("semext_merge", {}).get("txt_path"))
    packet_description_generator = PacketDescriptionGenerator(xml_path=xml_path)
    pkt_dependency_path_var = config.get("semseed", {}).get("pkt_dependency_path")

    pkt_dependency_path = pkt_dependency_path_var.replace("pkt_dependency.json",jg_model_name + "_pkt_dependency.json")


if not semseed_file_path:
    raise ValueError("semseed_file_path not found in config file")



def find_dependent_packet(pkt_name_list):
    # 如果pkt_dependency_path 不存在，则创建。如果存在则读取
    pkt_dependency = None
    if not os.path.exists(pkt_dependency_path):
        with open(pkt_dependency_path, "w") as f:
            json.dump({"packets": []}, f, indent=4)
        print(f"Created new JSON file at {pkt_dependency_path}")
    else:
        with open(pkt_dependency_path, "r") as f:
            pkt_dependency = json.load(f)
    
    # 如果JSON格式不是期望的格式，重新初始化
    if not pkt_dependency or "packets" not in pkt_dependency:
        pkt_dependency = {"packets": []}
    
    # 存储已处理的数据包对，避免重复处理
    processed_pairs = set()
    for item in pkt_dependency["packets"]:
        if "packet_name_1" in item and "packet_name_2" in item:
            pair_key = f"{item['packet_name_1']}:{item['packet_name_2']}"
            processed_pairs.add(pair_key)
    
    # 遍历pkt_name_list中的每个数据包对
    for packet_name, packet_name_2 in pkt_name_list:
        # 处理数据包名称，移除下划线和pkt后缀以符合文档搜索要求
        clean_packet_name_1 = packet_name.replace("_", " ").replace(" pkt", "")
        clean_packet_name_2 = packet_name_2.replace("_", " ").replace(" pkt", "")
    
        name_1 = type(ble_sul.get_packet(packet_name.replace("smp_","")).lastlayer()).__name__
        name_2 = type(ble_sul.get_packet(packet_name_2.replace("smp_","")).lastlayer()).__name__

        fields_1 = packet_description_generator.get_packet_fields(name_1)
        fields_2 = packet_description_generator.get_packet_fields(name_2)
        if fields_1 == "":
            fields_1 = "The packet has no fields, please ignore it."
        if fields_2 == "":
            fields_2 = "The packet has no fields, please ignore it."


         
        # 检查这对数据包是否已经处理过
        pair_key = f"{packet_name}:{packet_name_2}"
        if pair_key in processed_pairs:
            print(f"跳过已处理过的数据包对: {packet_name} 和 {packet_name_2}")
            continue
        
        print(f"处理数据包对: {packet_name} 和 {packet_name_2}")
        
        # 使用LLM判断两个数据包之间是否存在依赖关系
        prompt = get_question(packet_name=clean_packet_name_1, packet_name_2=clean_packet_name_2,packet_name_fields=fields_1,packet_name_2_fields=fields_2)
        print(prompt)
        try:
            answer = jg_llm.invoke(prompt)
            
            # 使用括号计数算法提取完整的JSON对象
            print(answer.content)
            json_data = None
            
            # 清理回答，移除可能的代码块标记
            clean_answer = re.sub(r'```(?:json)?\s*|\s*```', '', answer.content)
            
            # 查找第一个开放大括号
            open_brace_pos = clean_answer.find('{')
            if open_brace_pos != -1:
                # 使用计数器跟踪括号嵌套来找到匹配的闭合括号
                brace_count = 1
                pos = open_brace_pos + 1
                while pos < len(clean_answer) and brace_count > 0:
                    if clean_answer[pos] == '{':
                        brace_count += 1
                    elif clean_answer[pos] == '}':
                        brace_count -= 1
                    pos += 1
                
                if brace_count == 0:  # 找到匹配的闭合括号
                    json_str = clean_answer[open_brace_pos:pos]
                    print("提取的完整JSON字符串:")
                    print(json_str)
                    
                    try:
                        json_data = json.loads(json_str)
                        print("成功解析JSON数据")
                    except json.JSONDecodeError as e:
                        print(f"JSON解析错误: {e}")
                        json_data = None
            else:
                print("在回答中未找到JSON对象的开始符号 '{'")
                
            print("json_data")
            print(json_data)
            # 2. 如果完整JSON提取失败，尝试单独提取各个字段
            if not json_data:
                # is_relevant_match = re.search(r'"cross_packet_dependency"\s*:\s*(true|false)', answer, re.IGNORECASE)
                # explanation_match = re.search(r'"explanation"\s*:\s*"(.*?)"(?:,|\s*\})', answer, re.DOTALL)
                is_relevant_match = re.search(r'"cross_packet_dependency"\s*:\s*(true|false)', answer, re.IGNORECASE)
                is_relevant = is_relevant_match.group(1).lower() == "true" if is_relevant_match else False
                
                # 提取explanation字段 - 使用与上面相同的括号计数算法
                explanation = "No explanation provided"
                explanation_start = answer.find('"explanation"')
                if explanation_start != -1:
                    # 找到冒号之后的位置
                    colon_pos = answer.find(':', explanation_start)
                    if colon_pos != -1:
                        # 找到第一个 { 的位置
                        open_brace = answer.find('{', colon_pos)
                        if open_brace != -1:
                            # 使用计数器跟踪括号嵌套来找到匹配的闭合括号
                            brace_count = 1
                            pos = open_brace + 1
                            while pos < len(answer) and brace_count > 0:
                                if answer[pos] == '{':
                                    brace_count += 1
                                elif answer[pos] == '}':
                                    brace_count -= 1
                                pos += 1
                            
                            if brace_count == 0:  # 找到匹配的闭合括号
                                explanation_text = answer[open_brace:pos]
                                try:
                                    explanation = json.loads(explanation_text)
                                    print("成功解析explanation JSON对象")
                                except json.JSONDecodeError as e:
                                    print(f"解析explanation JSON时出错: {e}")
                                    # 如果JSON解析失败，保留原始文本
                                    explanation = explanation_text
            else:
                # 使用解析的JSON数据
                is_relevant = json_data.get("cross_packet_dependency", False)
                explanation = json_data.get("explanation", "No explanation provided")
            
            # 创建新的数据包依赖记录
            new_dependency = {
                "packet_name_1": packet_name,
                "packet_name_2": packet_name_2,
                "cross_packet_dependency": is_relevant,
                "explanation": explanation
            }
            
            # 添加到结果列表中
            pkt_dependency["packets"].append(new_dependency)
            processed_pairs.add(pair_key)
            
            # 及时保存结果，防止长时间运行时中断丢失数据
            with open(pkt_dependency_path, "w") as f:
                json.dump(pkt_dependency, f, indent=4)
            
            print(f"添加了 {packet_name} 和 {packet_name_2} 之间的依赖关系")
        except Exception as e:
            print(f"处理数据包 {packet_name} 和 {packet_name_2} 时出错: {e}")
            traceback.print_exc()
    
    # 最终保存结果
    with open(pkt_dependency_path, "w") as f:
        json.dump(pkt_dependency, f, indent=4)
    
    return pkt_dependency



def pkt_list(alphabet):
    pkt_list = []
    for index, pkt_name in enumerate(alphabet[:-1]):
        for i in alphabet[index+1:]:
            pkt_list.append((pkt_name,i))
    return pkt_list


def get_answer(packet_name):
    # 读取pkt_dependency_path 文件
    packet_dependency = process_packets(pkt_dependency_path, packet_name)
    if packet_dependency == []:
        return []
    for packet_dependency_item in packet_dependency:
        question = get_prompt(packet_name = packet_name,dependency_info=packet_dependency_item, base_path=base_path)
        print(question)

        answer = llm.invoke(question)
        print(answer.content)
        break

    

if __name__ == "__main__":
    # 生成数据包对列表
    pkt_name_list = pkt_list(alphabet)

    find_dependent_packet(pkt_name_list)
    # get_answer("ll_feature_rsp_pkt")

    



