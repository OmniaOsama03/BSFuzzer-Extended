import os
import sys
import json

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
from BSFuzz.srcs.prompt.SemFieldMutation import get_prompt
from BSFuzz.srcs.prompt.IndexPacketPrompt import get_question
from BSFuzz.srcs.Pdf_Sem.PdfDb import load_documents
from BSFuzz.srcs.prompt.Packet_Description import PacketDescriptionGenerator
from langchain_community.retrievers import BM25Retriever
from langchain.retrievers import EnsembleRetriever


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
# alphabet.extend(['master_identification_pkt','pairing_request_pkt', 'identity_information_pkt', 'pairing_confirm_pkt', 'pairing_random_pkt', 'pairing_failed_pkt', 'encryption_information_pkt',  'identity_address_information_pkt', 'signing_information_pkt', 'security_request_pkt', 'pairing_public_key_pkt', 'pairing_dhkey_check_pkt', 'pairing_keypress_notification_pkt'])
# print(prompt.format(packet_name="pairing request", field="io_cap"))
# alphabet.extend(['ll_connection_update_ind_pkt'])
alphabet.extend(['pairing_request_pkt'])
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
   
    semseed_file_path = config.get("semseed", {}).get("cross_field_seed_file_path")
    faiss_index_path = config.get("semext_merge", {}).get("faiss_index_path")
    documents = load_documents(config.get("semext_merge", {}).get("txt_path"))


if not semseed_file_path:
    raise ValueError("semseed_file_path not found in config file")

# def search_context(faiss_index_path,packet_name, k=141):
def search_context(packet_name):
    packet_name = packet_name.replace("_"," ")
    packet_name = packet_name.replace("SM","smp")
# # 加载向量索引
#     vectorstore = FAISS.load_local(faiss_index_path, OpenAIEmbeddings(), allow_dangerous_deserialization=True)
#     vector_retriever = vectorstore.as_retriever(search_kwargs={"k": k})

#     # BM25 关键词检索
#     bm25_retriever = BM25Retriever.from_documents(documents)
#     bm25_retriever.k = k  # 设置返回文档数

#     # 组合检索

#     hybrid_retriever = EnsembleRetriever(retrievers=[vector_retriever, bm25_retriever], weights=[0.5, 0.5])

#     # 进行检索

#     results = hybrid_retriever.invoke(packet_name)
    confidence= []    
    results = documents

    for i in results:
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
                pkt_list.append({"packet name": type(hdr_layer.payload).__name__, "field": ",".join(related_fields)})
    return pkt_list


def get_answer(packet_name):
    # 获取数据包描述
    packet_desc_gen = PacketDescriptionGenerator(xml_path)  # 使用配置文件中的 xml_path
    packet_description = packet_desc_gen.get_packet_description(packet_name)  # 使用新的方法
    # print(packet_description)
    context = search_context(packet_name)  # 使用配置文件中的 xml_path
    print(len(context))
    # packet_description = get_prompt(target=packt_name,background="\n".join(context))  # 使用新的方法
    
    # print(packet_description)

    # query_prompt = get_prompt(packet_description)
    
    # # 直接使用 LLM 获取回答
    # answer = llm.invoke(packet_description)
    # # print("\nLLM Response:")
    # print(answer.content)
    # return answer.content


def answer_to_json(pkt_list):
    json_data = {
        "packets": []
    }
    
    if os.path.exists(semseed_file_path):
        try:
            with open(semseed_file_path, 'r') as f:
                json_data = json.load(f)
                print(f"Successfully loaded existing data from {semseed_file_path}")
        except json.JSONDecodeError as e:
            print(f"Error reading existing file {semseed_file_path}: {e}")
            print("Creating new JSON data structure")
            json_data = {"packets": []}
    
    for pkt in pkt_list:
        packet_name = pkt["packet name"]
        if not find_in_json(packet_name, json_data):
            try:
                answer = get_answer(packet_name)
                
                # 从回答中提取 JSON 数据
                answer_match = re.search(r'```json\s*(.*?)\s*```', answer, re.DOTALL)
                if answer_match:
                    answer_str = answer_match.group(1)
                else:
                    answer_str = answer

                json_data["packets"].append({
                    "name": packet_name,
                    "mutations": answer_str
                })
                
                # Save after each successful packet processing
                try:
                    with open(semseed_file_path, 'w') as f:
                        json.dump(json_data, f, indent=4)
                    print(f"Successfully saved {packet_name} to {semseed_file_path}")
                except Exception as e:
                    print(f"Error saving to {semseed_file_path}: {e}")
                    
            except Exception as e:
                print(f"Error processing packet {packet_name}: {e}")
            
      
    
    return json_data

def find_in_json(packet_name,  json_data):
    """检查数据包和字段是否已存在于 JSON 数据中"""
    for packet in json_data.get("packets", []):
        if packet["name"] == packet_name:
            return True
    return False

if __name__ == "__main__":
    pkt_list = pkt_list(alphabet,"SMP")
    # print(pkt_list)
    # get_answer(pkt_list[0]["packet name"],)
    

    answer_to_json(pkt_list)



