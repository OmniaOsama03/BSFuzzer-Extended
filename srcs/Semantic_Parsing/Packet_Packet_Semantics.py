import os
import sys
import json
import traceback

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../libs")

from BSFuzz.srcs.Send_Packet.Bluetooth_SUL import Bluetooth_SUL
from BSFuzz.libs.driver.NRF52_dongle import NRF52Dongle

from BSFuzz.srcs.Log_Config.logger_config import *
from BSFuzz.srcs.Config_File.Esp32 import config

import re
from BSFuzz.srcs.llm_model.ModConf import ModelConfig
from BSFuzz.srcs.prompt.Packet_Description import PacketDescriptionGenerator
from BSFuzz.srcs.prompt.IndexPacketPrompt import get_question
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
alphabet=[]

# alphabet.extend(['ll_connection_update_ind_pkt', 'll_channel_map_req_pkt', 'll_terminate_ind_pkt', 'll_enc_req_pkt', 'll_enc_rsp_pkt', 'll_start_enc_req_pkt', 'll_start_enc_rsp_pkt', 'll_unknown_rsp_pkt', 'll_feature_req_pkt', 'll_feature_rsp_pkt', 'll_pause_enc_req_pkt', 'll_pause_enc_rsp_pkt', 'll_version_ind_pkt', 'll_reject_ind_pkt', 'll_slave_feature_req_pkt', 'll_connection_param_req_pkt', 'll_connection_param_rsp_pkt', 'll_reject_ind_ext_pkt', 'll_ping_req_pkt', 'll_ping_rsp_pkt', 'll_length_req_pkt', 'll_length_rsp_pkt'])
# smp_alphabet = ['master_identification_pkt','pairing_request_pkt', 'identity_information_pkt', 'pairing_confirm_pkt', 'pairing_random_pkt', 'pairing_failed_pkt', 'encryption_information_pkt',  'identity_address_information_pkt', 'signing_information_pkt', 'security_request_pkt', 'pairing_public_key_pkt', 'pairing_dhkey_check_pkt', 'pairing_keypress_notification_pkt']
# smp_alphabet_new = []
alphabet.extend(['ll_enc_req_pkt'])
smp_alphabet = ['master_identification_pkt','pairing_request_pkt']
smp_alphabet_new = []


for pkt in smp_alphabet:
    if "smp_" in pkt:
        smp_alphabet_new.append(pkt)
    else:
        smp_alphabet_new.append("smp_" + pkt)
alphabet.extend(smp_alphabet_new)



with open("/home/yangting/Documents/BSFuzz/config/semext_packet_config.json", "r") as file:
    config = json.load(file)
    model_config = ModelConfig(config.get("llm", {}).get("model_provider"))
    model = config.get("llm", {}).get("model")
    model_config.update_config({"model":config.get("llm", {}).get("model"),"temperature":config.get("llm", {}).get("temperature"),})
    base_llm = model_config.get_llm()

    xml_path = config.get("semext_merge", {}).get("xml_file_path")
   
    semseed_file_path_var = config.get("semseed", {}).get("cross_field_seed_file_path")

    semseed_file_path = semseed_file_path_var.replace("${model_provider}",config.get("llm", {}).get("model_provider") )
    smp_faiss_index_path = config.get("semext_smp", {}).get("faiss_index_path")
    l2cap_faiss_index_path = config.get("semext_l2cap", {}).get("faiss_index_path")
    att_faiss_index_path = config.get("semext_att", {}).get("faiss_index_path")
    ll_faiss_index_path = config.get("semext_ll", {}).get("faiss_index_path")
    # documents = load_documents(config.get("semext_merge", {}).get("txt_path"))
    packet_description_generator = PacketDescriptionGenerator(xml_path=xml_path)
    pkt_dependency_path_var = config.get("semseed", {}).get("pkt_dependency_path")

    pkt_dependency_path = pkt_dependency_path_var.replace("pkt_dependency.json",config.get("llm", {}).get("model_provider") + "_pkt_dependency.json")


if not semseed_file_path:
    raise ValueError("semseed_file_path not found in config file")

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
    Focus on packet's semantic information, and judge whether there is a dependency relationship.
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
        name="SMP_Spec_Retriever",
        func=qa_chain.invoke,
        description="Retrieves and analyzes information specific to Bluetooth SMP protocol from the specification."
    )

def create_l2cap_retrieval_tool(vector_store, k_value=10):
    prompt_template = """
    You are a Bluetooth L2CAP (Logical Link Control and Adaptation Protocol) expert analyzing the Bluetooth Core Specification.
    Use the provided context from the specification to answer questions about L2CAP protocol.
    Focus on packet's semantic information, and judge whether there is a dependency relationship.
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
        name="L2CAP_Spec_Retriever",
        func=qa_chain.invoke,
        description="Retrieves and analyzes information specific to Bluetooth L2CAP protocol from the specification."
    )

def create_att_retrieval_tool(vector_store, k_value=10):
    prompt_template = """
    You are a Bluetooth ATT (Attribute Protocol) expert analyzing the Bluetooth Core Specification.
    Use the provided context from the specification to answer questions about ATT protocol.
    Focus on packet's semantic information, and judge whether there is a dependency relationship.
    If asked about protocol violations or errors, identify the issue, explain its implications,
    and suggest mitigations. Use chain-of-thought reasoning to break down your analysis.
    
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
    Focus on packet's semantic information, and judge whether there is a dependency relationship.
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
def create_agent(llm,k_value=10):
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

def get_answer(query_prompt):
    agent = create_agent(base_llm, k_value=15)
    result = agent.invoke({"input": query_prompt})
    return result["output"]


def find_dependent_packet(pkt_name_list):

    pkt_dependency = None
    if not os.path.exists(pkt_dependency_path):
        with open(pkt_dependency_path, "w") as f:
            json.dump({"packets": []}, f, indent=4)
        print(f"Created new JSON file at {pkt_dependency_path}")
    else:
        with open(pkt_dependency_path, "r") as f:
            pkt_dependency = json.load(f)
    

    if not pkt_dependency or "packets" not in pkt_dependency:
        pkt_dependency = {"packets": []}
    
 
    processed_pairs = set()
    for item in pkt_dependency["packets"]:
        if "packet_name_1" in item and "packet_name_2" in item:
            pair_key = f"{item['packet_name_1']}:{item['packet_name_2']}"
            processed_pairs.add(pair_key)
    

    for packet_name, packet_name_2 in pkt_name_list:
   
        clean_packet_name_1 = packet_name.replace("_", " ").replace(" pkt", "")
        clean_packet_name_2 = packet_name_2.replace("_", " ").replace(" pkt", "")
        print("--------------------------------")
        print(packet_name)
        print(packet_name_2)
       
    
        name_1 = type(ble_sul.get_packet(packet_name.replace("smp_","")).lastlayer()).__name__
        name_2 = type(ble_sul.get_packet(packet_name_2.replace("smp_","")).lastlayer()).__name__

        fields_1 = packet_description_generator.get_packet_fields(name_1)
        fields_2 = packet_description_generator.get_packet_fields(name_2)
        if fields_1 == "":
            fields_1 = "The packet has no fields, please focus on packet's semantic information, and judge whether there is a dependency relationship."
        if fields_2 == "":
            fields_2 = "The packet has no fields, please focus on packet's semantic information, and judge whether there is a dependency relationship."


         
        # 检查这对数据包是否已经处理过
        pair_key = f"{packet_name}:{packet_name_2}"
        if pair_key in processed_pairs:
            print(f"skipping processed packet pair: {packet_name} and {packet_name_2}")
            continue
        
        print(f"processing packet pair: {packet_name} and {packet_name_2}")
        
        # 使用LLM判断两个数据包之间是否存在依赖关系
        prompt = get_question(packet_name=clean_packet_name_1, packet_name_2=clean_packet_name_2,packet_name_fields=fields_1,packet_name_2_fields=fields_2)
        # print(prompt)
        
        # 初始化默认值
        answer = None
        is_relevant = False
        explanation = "Unknown"
        
        try:
            answer = get_answer(query_prompt=prompt)
            
 
            print(answer)
            json_data = None
            
  
            clean_answer = re.sub(r'```(?:json)?\s*|\s*```', '', answer)
            
   
            open_brace_pos = clean_answer.find('{')
            if open_brace_pos != -1:
        
                brace_count = 1
                pos = open_brace_pos + 1
                while pos < len(clean_answer) and brace_count > 0:
                    if clean_answer[pos] == '{':
                        brace_count += 1
                    elif clean_answer[pos] == '}':
                        brace_count -= 1
                    pos += 1
                
                if brace_count == 0: 
                    json_str = clean_answer[open_brace_pos:pos]
                    print("extracted complete JSON string:")
                    print(json_str)
                    
                    try:
                        json_data = json.loads(json_str)
                        print("successfully parsed JSON data")
                    except json.JSONDecodeError as e:
                        print(f"error parsing JSON: {e}")
                        json_data = None
            else:
                print("no JSON object start symbol '{' found in answer")
                
            print("json_data")
            print(json_data)
          
            if not json_data:

                is_relevant_match = re.search(r'"cross_packet_dependency"\s*:\s*(true|false)', answer, re.IGNORECASE)
                is_relevant = is_relevant_match.group(1).lower() == "true" if is_relevant_match else False
                
            
                explanation = "No explanation provided"
                explanation_start = answer.find('"explanation"')
                if explanation_start != -1:
             
                    colon_pos = answer.find(':', explanation_start)
                    if colon_pos != -1:
                  
                        open_brace = answer.find('{', colon_pos)
                        if open_brace != -1:
                     
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
                                    print("successfully parsed explanation JSON object")
                                except json.JSONDecodeError as e:
                                    print(f"error parsing explanation JSON: {e}")
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
            
            print(f"Add {packet_name} and {packet_name_2} dependency relationship")
        except Exception as e:
            print(f"error processing {packet_name} and {packet_name_2}: {e}")
            traceback.print_exc()
            
            # 尝试从异常信息中提取JSON
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
                        is_relevant = json_extracted.get("cross_packet_dependency", False)
                        explanation = json_extracted.get("explanation", "Unknown")
                    except json.JSONDecodeError:
                        pass
            
            # 如果没有成功提取JSON，使用Unknown值
            if json_extracted is None:
                is_relevant = False
                explanation = "Unknown"
            
            # 创建默认的依赖记录
            new_dependency = {
                "packet_name_1": packet_name,
                "packet_name_2": packet_name_2,
                "cross_packet_dependency": is_relevant,
                "explanation": explanation
            }
            
            # 添加到结果列表中
            pkt_dependency["packets"].append(new_dependency)
            processed_pairs.add(pair_key)
            
            # 及时保存结果
            with open(pkt_dependency_path, "w") as f:
                json.dump(pkt_dependency, f, indent=4)
            
            print(f"add {packet_name} and {packet_name_2} dependency relationship (using default value)")
    
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




if __name__ == "__main__":
    # 生成数据包对列表
    pkt_name_list = pkt_list(alphabet)

    find_dependent_packet(pkt_name_list)


    



