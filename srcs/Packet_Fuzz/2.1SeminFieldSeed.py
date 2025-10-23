import os
import sys
import json

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")


from BSFuzz.srcs.Send_Packet.Bluetooth_SUL import Bluetooth_SUL
from BSFuzz.libs.driver.NRF52_dongle import NRF52Dongle

from BSFuzz.srcs.Log_Config.logger_config import *
from BSFuzz.srcs.Config_File.Cypress import config

import re
from BSFuzz.srcs.llm_model.ModConf import ModelConfig
from BSFuzz.srcs.prompt.SemFieldMutation import get_prompt
from BSFuzz.srcs.prompt.IndexPacketPrompt import get_question
from BSFuzz.srcs.Pdf_Sem.PdfDb import load_documents
from BSFuzz.srcs.prompt.Packet_Description import PacketDescriptionGenerator



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
# alphabet= ['ll_connection_update_ind_pkt', 'll_channel_map_req_pkt', 'll_terminate_ind_pkt', 'll_enc_req_pkt', 'll_enc_rsp_pkt', 'll_start_enc_req_pkt', 'll_start_enc_rsp_pkt', 'll_unknown_rsp_pkt', 'll_feature_req_pkt', 'll_feature_rsp_pkt', 'll_pause_enc_req_pkt', 'll_pause_enc_rsp_pkt', 'll_version_ind_pkt', 'll_reject_ind_pkt', 'll_slave_feature_req_pkt', 'll_connection_param_req_pkt', 'll_connection_param_rsp_pkt', 'll_reject_ind_ext_pkt', 'll_ping_req_pkt', 'll_ping_rsp_pkt', 'll_length_req_pkt', 'll_length_rsp_pkt']
alphabet.extend(['master_identification_pkt','pairing_request_pkt', 'identity_information_pkt', 'pairing_confirm_pkt', 'pairing_random_pkt', 'pairing_failed_pkt', 'encryption_information_pkt',  'identity_address_information_pkt', 'signing_information_pkt', 'security_request_pkt', 'pairing_public_key_pkt', 'pairing_dhkey_check_pkt', 'pairing_keypress_notification_pkt'])
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

    jg_model = ModelConfig("openai")
    jg_model.update_config({"model":config.get("llm", {}).get("jg_model"),"temperature":0,})
    jg_llm = jg_model.get_llm()



    xml_path = config.get("semext_merge", {}).get("xml_file_path")
   
    semseed_file_path_var = config.get("semseed", {}).get("inner_field_seed_file_path")

    semseed_file_path = semseed_file_path_var.replace("${model_provider}",config.get("llm", {}).get("model_provider") )
    faiss_index_path = config.get("semext_merge", {}).get("faiss_index_path")
    documents = load_documents(config.get("semext_merge", {}).get("txt_path"))
    packet_description_generator = PacketDescriptionGenerator(xml_path=xml_path)


if not semseed_file_path:
    raise ValueError("semseed_file_path not found in config file")

# def search_context(faiss_index_path,packet_name, k=141):
def search_context(packet_name):
    packet_name = packet_name.replace("_"," ")
    packet_name = packet_name.replace("SM","smp")
    confidence= []    
   

    for i in documents:
        prompt = get_question(packet_name=packet_name,context=i.page_content)
        # 让llm 帮忙判断是否是相关文档
        answer = jg_llm.invoke(prompt)
    
        # 匹配JSON格式的响应
        answer_match = re.search(r'\{[\s\n]*"is_relevant":\s*(true|false),\s*"confidence":\s*([0-9.]+)[\s\n]*\}', answer.content, re.DOTALL | re.IGNORECASE)
      
        if answer_match:
            try:
                is_relevant = answer_match.group(1) == "true"
                confidence_value = float(answer_match.group(2))

                
                if is_relevant and confidence_value >= 0.85:  # 可以根据需要调整置信度阈值
                    confidence.append(i.page_content)
            except (ValueError, IndexError) as e:
                print(f"parse error: {e}")
                continue
    return confidence



def pkt_list(alphabet,index_name):
    pkt_list = []
    # i= 0
    for packet_name in alphabet:
        packet = ble_sul.get_packet(packet_name)
        # print(f"packet_name:{packet_name}")
        # 如果index_name中包含SMP，则使用SM_Hdr层，否则使用BTLE_CTRL层
        if "SMP" in index_name:
            hdr_layer = packet.getlayer("SM_Hdr")
        elif "LL" in index_name:
            hdr_layer = packet.getlayer("BTLE_CTRL")
        elif "L2CAP" in index_name:
            hdr_layer = packet.getlayer("L2CAP_Hdr")
        elif "ATT" in index_name:
            hdr_layer = packet.getlayer("ATT_Hdr")
        else:
            print(f"Error: {packet_name} not found")
            hdr_layer = None

        # if i == 0:
        #     # 收集所有相关字段
        #     related_fields = []
        #     for field in hdr_layer.default_fields:
        #         related_fields.append(field)
        #     if related_fields:
        #         pkt_list.append({"packet name": type(hdr_layer).__name__, "field": ",".join(related_fields)})
        #     i = 1
    
        if hdr_layer:
            # 收集所有相关字段
            related_fields = []
            for field in hdr_layer.payload.default_fields:
                related_fields.append(field)
            if related_fields:
                # pkt_list.append({"packet name": type(hdr_layer.payload).__name__, "field": ",".join(related_fields)})
                pkt_list.append({"packet name": packet_name,"field": ",".join(related_fields)})
    return pkt_list


def get_answer(packet_name):

    # print(packet_description)
    # new txt file for context
    # context_file = f"/home/yangting/Documents/Semantic/data/{packet_name}_context.txt"
    # if os.path.exists(context_file):
    #     # 如果存在，则读取
    #     print(f"context file {context_file} exists")
    #     with open(context_file, "r") as f:
    #         context = f.readlines()
    # else:
    #     print(f"context file {context_file} not exists")
    #     context = search_context(packet_name)  # 使用配置文件中的 xml_path
    #     # 将context 写入临时txt文件
    #     with open(context_file, "w") as f:
    #         f.write("\n".join(context))
    
    packet_description = packet_description_generator.get_all_packet_description(ble_sul.get_packet(packet_name))  # 使用新的方法
    question = get_prompt(target=packet_name,background= packet_description)  # 使用新的方法
    # print(question)
   

    # 直接使用 LLM 获取回答
    answer = llm.invoke(question)

    print(answer.content)
    print(f"the {packet_name} mutation")
    answer_to_json(packet_name,answer.content)
    

   

# write answer to json file
def answer_to_json(packet_name, answer):
    json_data = {
        "packets": []
    }
    
    # 加载现有的 JSON 数据
    if os.path.exists(semseed_file_path):
        try:
            with open(semseed_file_path, 'r') as f:
                json_data = json.load(f)
                print(f"Successfully loaded existing data from {semseed_file_path}")
        except json.JSONDecodeError as e:
            print(f"Error reading existing file {semseed_file_path}: {e}")
            print("Creating new JSON data structure")
            json_data = {"packets": []}
    
    # 查找现有数据包
    existing_packet = None
    for packet in json_data["packets"]:
        if packet["name"] == packet_name:
            existing_packet = packet
            break

    # 从回答中提取 JSON
    answer_match = re.search(r'```json\s*(.*?)\s*```', answer, re.DOTALL)
    if answer_match:
        json_str = answer_match.group(1).strip()
        
        # 清理 JSON 字符串
        json_str = re.sub(r'//.*?$', '', json_str, flags=re.MULTILINE)  # 移除单行注释
        json_str = re.sub(r'/\*.*?\*/', '', json_str, flags=re.DOTALL)  # 移除多行注释
        json_str = re.sub(r'([{,])\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'\1"\2":', json_str)  # 确保键名有双引号
        json_str = re.sub(r',(\s*[}\]])', r'\1', json_str)  # 移除尾随逗号
        
        try:
            # 解析 JSON
            mutations = json.loads(json_str)
            
            # 确保 mutations 包含预期的字段
            if "Inner_Packet_Field_Dependent_Mutations" not in mutations:
                mutations["Inner_Packet_Field_Dependent_Mutations"] = []
         
            
            if existing_packet:
                # 如果数据包已存在，合并变异
                print(f"Packet {packet_name} already exists, merging mutations")
                
                # 确保 mutations 字段存在
                if "mutations" not in existing_packet:
                    existing_packet["mutations"] = {
                        "Inner_Packet_Field_Dependent_Mutations": [],
                       
                    }
                
                # 如果 mutations 是字符串，尝试解析它
                if isinstance(existing_packet["mutations"], str):
                    try:
                        existing_packet["mutations"] = json.loads(existing_packet["mutations"])
                    except json.JSONDecodeError:
                        # 如果解析失败，创建新的结构
                        existing_packet["mutations"] = {
                            "Inner_Packet_Field_Dependent_Mutations": [],
                           
                        }
                
                # 确保 mutations 包含预期的字段
                if "Inner_Packet_Field_Dependent_Mutations" not in existing_packet["mutations"]:
                    existing_packet["mutations"]["Inner_Packet_Field_Dependent_Mutations"] = []
              
                
                # 合并内部数据包字段依赖变异
                existing_packet["mutations"]["Inner_Packet_Field_Dependent_Mutations"].extend(
                    mutations["Inner_Packet_Field_Dependent_Mutations"]
                )
                
                # 合并数据包序列字段依赖变异
 
            else:
                # 如果数据包不存在，创建新条目
                print(f"Creating new packet entry for {packet_name}")
                json_data["packets"].append({
                    "name": packet_name,
                    "mutations": mutations  # 直接使用解析后的 mutations
                })
            
            # 保存更新后的 JSON 数据
            try:
                with open(semseed_file_path, 'w') as f:
                    json.dump(json_data, f, indent=4)
                print(f"Successfully saved {packet_name} to {semseed_file_path}")
            except Exception as e:
                print(f"Error saving to {semseed_file_path}: {e}")
                
        except json.JSONDecodeError as je:
            print(f"JSON parsing error: {je}")
            print(f"Cleaned JSON string:\n{json_str}")
            print(f"Error position: line {je.lineno}, column {je.colno}")
            
            # 显示错误位置
            lines = json_str.split('\n')
            for i in range(max(0, je.lineno-3), min(len(lines), je.lineno+2)):
                print(f"{i+1}: {lines[i]}")
                if i+1 == je.lineno:
                    print(" " * (je.colno+3) + "^-- Error here")
    else:
        print(f"No JSON content found in answer for {packet_name}")
    
    return json_data

def find_in_json(packet_name, semseed_file_path):
    """检查数据包和字段是否已存在于 JSON 数据中"""
    try:
        # 检查文件是否存在且不为空
        if os.path.exists(semseed_file_path) and os.path.getsize(semseed_file_path) > 0:
            with open(semseed_file_path, 'r') as f:
                try:
                    json_data = json.load(f)
                    for packet in json_data.get("packets", []):
                        if packet["name"] == packet_name:
                            return True
                except json.JSONDecodeError as e:
                    print(f"Error parsing JSON in {semseed_file_path}: {e}")
                    # 文件存在但JSON无效，返回False
                    return False
        else:
            # 文件不存在或为空
            print(f"File {semseed_file_path} does not exist or is empty")
            return False
    except Exception as e:
        print(f"Error checking JSON file: {e}")
        return False
    
    return False

def main():
    # 判断semseed_file_path 是否存在,不存在则创建
    if not os.path.exists(semseed_file_path):
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(semseed_file_path), exist_ok=True)
            # 创建文件并写入初始JSON结构
            with open(semseed_file_path, "w") as f:
                json.dump({"packets": []}, f, indent=4)
            print(f"Created new JSON file at {semseed_file_path}")
        except Exception as e:
            print(f"Error creating JSON file: {e}")
            return
    elif os.path.getsize(semseed_file_path) == 0:
        # 文件存在但为空，写入初始JSON结构
        try:
            with open(semseed_file_path, "w") as f:
                json.dump({"packets": []}, f, indent=4)
            print(f"Initialized empty JSON file at {semseed_file_path}")
        except Exception as e:
            print(f"Error initializing JSON file: {e}")
            return
    
    # 获取数据包列表
    pkt = pkt_list(alphabet, "SMP")
    
    for i in range(len(pkt)):  # 使用索引而不是直接迭代
        current_packet = pkt[i]
        packet_name = current_packet["packet name"]
        
        if find_in_json(packet_name, semseed_file_path):
            # 判断是否是最后一个数据包
            if i == len(pkt) - 1:
                get_answer(packet_name)
            else:
                # 判断下一个是否存在
                next_packet = pkt[i + 1]
                if find_in_json(next_packet["packet name"], semseed_file_path):
                    continue
                else:
                    get_answer(packet_name)
        else:
            get_answer(packet_name)

if __name__ == "__main__":
    main()
    



