import os
import sys
import json

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")

from BSFuzz.srcs.Send_Packet.Bluetooth_SUL import Bluetooth_SUL
from BSFuzz.libs.driver.NRF52_dongle import NRF52Dongle

from BSFuzz.srcs.Log_Config.logger_config import *
from BSFuzz.srcs.Config_File.Esp32 import config

import re
from time import sleep
from BSFuzz.srcs.llm_model.ModConf import ModelConfig
from BSFuzz.srcs.prompt.Packet_Description import PacketDescriptionGenerator
from BSFuzz.srcs.prompt.SemSeedPrompt import get_prompt
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.chains import RetrievalQA
from langchain.agents import initialize_agent, Tool, AgentType
from langchain.prompts import PromptTemplate



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
alphabet=['pairing_response_pkt']
# alphabet= ['ll_channel_map_req_pkt', 'll_terminate_ind_pkt', 'll_enc_req_pkt', 'll_enc_rsp_pkt', 'll_start_enc_req_pkt', 'll_start_enc_rsp_pkt', 'll_unknown_rsp_pkt', 'll_feature_req_pkt', 'll_feature_rsp_pkt', 'll_pause_enc_req_pkt', 'll_pause_enc_rsp_pkt', 'll_version_ind_pkt', 'll_reject_ind_pkt', 'll_slave_feature_req_pkt', 'll_connection_param_req_pkt', 'll_connection_param_rsp_pkt', 'll_reject_ind_ext_pkt', 'll_ping_req_pkt', 'll_ping_rsp_pkt', 'll_length_req_pkt', 'll_length_rsp_pkt']

# alphabet.extend(['master_identification_pkt','pairing_request_pkt', 'identity_information_pkt', 'pairing_response_pkt', 'pairing_confirm_pkt', 'pairing_random_pkt', 'pairing_failed_pkt', 'encryption_information_pkt',  'identity_address_information_pkt', 'signing_information_pkt', 'security_request_pkt', 'pairing_public_key_pkt', 'pairing_dhkey_check_pkt', 'pairing_keypress_notification_pkt'])
# print(prompt.format(packet_name="pairing request", field="io_cap"))
# alphabet.extend(['ll_connection_update_ind_pkt'])
# alphabet.extend(['pairing_response_pkt'])
# 加载 JSON 配置文件
with open("/home/yangting/Documents/BSFuzz/config/semseed_config.json", "r") as file:
    config = json.load(file)
    model_config = ModelConfig(config.get("llm", {}).get("model_provider"))

    model = config.get("llm", {}).get("model")
# 
    model_config.update_config({"model":config.get("llm", {}).get("model"),"temperature":config.get("llm", {}).get("temperature"),})
    base_llm = model_config.get_llm()
    xml_path = config.get("semext_merge", {}).get("xml_file_path")
    embedding_model = config.get("llm", {}).get("embedding_model")

    semseed_file_path_var = config.get("semseed", {}).get("field_seed_file_path")
    #将semseed_file_path中的${model_provider}替换为model_provider
    semseed_file_path = semseed_file_path_var.replace("${model_provider}",config.get("llm", {}).get("model_provider") )
    smp_faiss_index_path = config.get("semext_smp", {}).get("faiss_index_path")
    l2cap_faiss_index_path = config.get("semext_l2cap", {}).get("faiss_index_path")
    att_faiss_index_path = config.get("semext_att", {}).get("faiss_index_path")
    ll_faiss_index_path = config.get("semext_ll", {}).get("faiss_index_path")
    packet_desc_gen = PacketDescriptionGenerator(xml_path)


def load_vector_store(faiss_index_path):
    embeddings = OpenAIEmbeddings()
    return FAISS.load_local(
        faiss_index_path,
        embeddings,
        allow_dangerous_deserialization=True
    )

# Step 4: Create a retrieval tool for the agent
def create_smp_retrieval_tool(vector_store, k_value=10):
    prompt_template = """
    You are a Bluetooth SMP (Security Manager Protocol) expert analyzing the Bluetooth Core Specification.
    Use the provided context from the specification to answer questions about SMP protocol.
    Refer to the SMP protocol specification to generate seed for the field. Use chain-of-thought reasoning to break down your analysis.
    
    Context: {context}
    Question: {question}
    
    """
    prompt = PromptTemplate(
        template=prompt_template,
        input_variables=["context", "question"]
    )
    
    qa_chain = RetrievalQA.from_chain_type(
        llm=base_llm,
        chain_type="stuff",
        retriever=vector_store.as_retriever(search_kwargs={"k": k_value}),
        chain_type_kwargs={"prompt": prompt}
    )
    
    return Tool(
        name="SMP_Spec_Retriever",
        func=qa_chain.invoke,
        description="Retrieves and analyzes information specific to Bluetooth SMP protocol from the specification."
    )

def create_l2cap_retrieval_tool(vector_store, k_value=10):
    prompt_template = """
    You are a Bluetooth L2CAP (Logical Link Control and Adaptation Protocol) expert analyzing the Bluetooth Core Specification.
    Use the provided context from the specification to answer questions about L2CAP protocol.
    Focus on channel management, segmentation and reassembly, and multiplexing capabilities.
    Refer to the L2CAP protocol specification to generate seed for the field. Use chain-of-thought reasoning to break down your analysis.
    
    Context: {context}
    Question: {question}
    
    """
    prompt = PromptTemplate(
        template=prompt_template,
        input_variables=["context", "question"]
    )
    
    qa_chain = RetrievalQA.from_chain_type(
        llm=base_llm,
        chain_type="stuff",
        retriever=vector_store.as_retriever(search_kwargs={"k": k_value}),
        chain_type_kwargs={"prompt": prompt}
    )
    
    return Tool(
        name="L2CAP_Spec_Retriever",
        func=qa_chain.invoke,
        description="Retrieves and analyzes information specific to Bluetooth L2CAP protocol from the specification."
    )

def create_att_retrieval_tool(vector_store, k_value=10):
    prompt_template = """
    You are a Bluetooth ATT (Attribute Protocol) expert analyzing the Bluetooth Core Specification.
    Use the provided context from the specification to answer questions about ATT protocol.
    Refer to the ATT protocol specification to generate seed for the field. Use chain-of-thought reasoning to break down your analysis.
    
    Context: {context}
    Question: {question}

    """
    prompt = PromptTemplate(
        template=prompt_template,
        input_variables=["context", "question"]
    )
    
    qa_chain = RetrievalQA.from_chain_type(
        llm=base_llm,
        chain_type="stuff",
        retriever=vector_store.as_retriever(search_kwargs={"k": k_value}),
        chain_type_kwargs={"prompt": prompt}
    )
    
    return Tool(
        name="ATT_Spec_Retriever",
        func=qa_chain.invoke,
        description="Retrieves and analyzes information specific to Bluetooth ATT protocol from the specification."
    )

def create_ll_retrieval_tool(vector_store, k_value=10):
    prompt_template = """
    You are a Bluetooth LL (Link Layer) expert analyzing the Bluetooth Core Specification.
    Use the provided context from the specification to answer questions about Link Layer protocol.
    Refer to the Link Layer protocol specification to generate seed for the field.
    Use chain-of-thought reasoning to break down your analysis.
    
    Context: {context}
    Question: {question}
    
    """
    prompt = PromptTemplate(
        template=prompt_template,
        input_variables=["context", "question"]
    )
    
    qa_chain = RetrievalQA.from_chain_type(
        llm=base_llm,
        chain_type="stuff",
        retriever=vector_store.as_retriever(search_kwargs={"k": k_value}),
        chain_type_kwargs={"prompt": prompt}
    )
    
    return Tool(
        name="LL_Spec_Retriever",
        func=qa_chain.invoke,
        description="Retrieves and analyzes information specific to Bluetooth Link Layer protocol from the specification."
    )

# Step 5: Initialize the agent
def create_agent(base_llm,k_value=10):
    tools = []
    
    smp_vector_store = load_vector_store(smp_faiss_index_path)
    l2cap_vector_store = load_vector_store(l2cap_faiss_index_path)
    att_vector_store = load_vector_store(att_faiss_index_path)
    ll_vector_store = load_vector_store(ll_faiss_index_path)
    

    smp_tool = create_smp_retrieval_tool(smp_vector_store, k_value)
    l2cap_tool = create_l2cap_retrieval_tool(l2cap_vector_store, k_value)
    att_tool = create_att_retrieval_tool(att_vector_store, k_value)
    ll_tool = create_ll_retrieval_tool(ll_vector_store, k_value)
    
    tools.append(smp_tool)
    tools.append(l2cap_tool)
    tools.append(att_tool)
    tools.append(ll_tool)
    
    # Initialize the agent with ReAct framework
    agent = initialize_agent(
        tools=tools,
        llm=base_llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION, 
        verbose=True,
        handle_parsing_errors=False
    )
    return agent

def get_answer(packt_name, field):
    # 获取数据包描述
    # 使用配置文件中的 xml_path
    agent = create_agent(base_llm, k_value=15)
    packet_description = packet_desc_gen.get_field_description(packt_name, field)  # 使用新的方法
    
    # 获取 SemSeed 提示并格式化
    print("Field Description:")
    print(packet_description)

    query_prompt = get_prompt(packet_description)
    
    # 直接使用 LLM 获取回答
    try:
        result = agent.invoke({"input": query_prompt})
        print("\nLLM Response:")
        # 检查 answer 是否为字符串或具有 content 属性的对象
        if isinstance(result, str):
            print(result)
            return result
        elif hasattr(result, "output"):
            print(result.output)
            return result.output
        else:
            print(result.content)
            return result.content
    except Exception as e:
        print(f"LLM 调用出错: {str(e)}")
        # 尝试从异常中提取JSON
        err_text = str(e)
        json_extracted = None
        
        # 先清理可能的代码块标记
        err_text_clean = re.sub(r'```(?:json)?\s*|\s*```', '', err_text)
        
        # 尝试提取完整的JSON对象
        open_brace_pos = err_text_clean.find('{')
        if open_brace_pos != -1:
            brace_count = 1
            pos = open_brace_pos + 1
            while pos < len(err_text_clean) and brace_count > 0:
                if err_text_clean[pos] == '{':
                    brace_count += 1
                elif err_text_clean[pos] == '}':
                    brace_count -= 1
                pos += 1
            
            if brace_count == 0:
                json_str = err_text_clean[open_brace_pos:pos]
                try:
                    json_extracted = json.loads(json_str)
                    return json.dumps(json_extracted, indent=2)
                except json.JSONDecodeError:
                    pass
        
        # 如果提取失败，创建默认的Unknown JSON
        test_case = {}
        test_case[field] = "Unknown"
        test_case["TestType"] = "Unknown"
        unknown_json = {
            "MutationType": "Field Mutation",
            "TestCases": [test_case]
        }
        return json.dumps(unknown_json, indent=2)

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
                        answer_clean = re.sub(r'```(?:json)?\s*|\s*```', '', answer)
                        json_data_parsed = json.loads(answer_clean)
                        
                        if isinstance(json_data_parsed, dict) and "TestCases" in json_data_parsed:
                            mutations = json_data_parsed["TestCases"]
                            field_data = {
                                "name": field,
                                "mutations": mutations
                            }
                            packet["fields"].append(field_data)
                            print(f"Successfully processed {packet_name}.{field}")
                        else:
                            print(f"No valid JSON found in answer for {packet_name}.{field}")
                            # 创建默认的 Unknown 记录
                            test_case = {}
                            test_case[field] = "Unknown"
                            test_case["TestType"] = "Unknown"
                            field_data = {
                                "name": field,
                                "mutations": [test_case]
                            }
                            packet["fields"].append(field_data)
                            print(f"Added default Unknown record for {packet_name}.{field}")
                    except Exception as e:
                        print(f"Error processing {packet_name}.{field}: {str(e)}")
                        # 创建默认的 Unknown 记录
                        test_case = {}
                        test_case[field] = "Unknown"
                        test_case["TestType"] = "Unknown"
                        field_data = {
                            "name": field,
                            "mutations": [test_case]
                        }
                        packet["fields"].append(field_data)
                        print(f"Added default Unknown record for {packet_name}.{field}")
                packet_exists = True
                break
        
        if not packet_exists:
            try:
                print(f"\nProcessing new packet {packet_name}.{field}")
                answer = get_answer(packet_name, field)
                
                answer_clean = re.sub(r'```(?:json)?\s*|\s*```', '', answer)
                json_data_parsed = json.loads(answer_clean)
                
                if isinstance(json_data_parsed, dict) and "TestCases" in json_data_parsed:
                    mutations = json_data_parsed["TestCases"]
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
                    # 创建默认的 Unknown 记录
                    test_case = {}
                    test_case[field] = "Unknown"
                    test_case["TestType"] = "Unknown"
                    json_data["packets"].append({
                        "name": packet_name,
                        "fields": [{
                            "name": field,
                            "mutations": [test_case]
                        }]
                    })
                    print(f"Added default Unknown record for {packet_name}.{field}")
            except Exception as e:
                print(f"Error processing {packet_name}.{field}: {str(e)}")
                # 创建默认的 Unknown 记录
                test_case = {}
                test_case[field] = "Unknown"
                test_case["TestType"] = "Unknown"
                json_data["packets"].append({
                    "name": packet_name,
                    "fields": [{
                        "name": field,
                        "mutations": [test_case]
                    }]
                })
                print(f"Added default Unknown record for {packet_name}.{field}")
        
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



