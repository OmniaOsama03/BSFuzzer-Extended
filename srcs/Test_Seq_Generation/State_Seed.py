import os
import sys
import json
import logging


sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
from BSFuzz.srcs.Log_Config.logger_config import *
from BSFuzz.srcs.Config_File.Esp32 import config

import re
from BSFuzz.srcs.llm_model.ModConf import ModelConfig
from BSFuzz.srcs.prompt.SemStateMutation import get_prompt
# from BSFuzz.srcs.prompt.IndexPacketStatePrompt import get_question
# from BSFuzz.srcs.Pdf_Sem.PdfDb import load_documents
from BSFuzz.srcs.Test_Seq_Generation.process_dependency_identity import process_packets_identity
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.agents import initialize_agent, AgentType
from langchain.agents import Tool
from langchain.prompts import PromptTemplate
from langchain.chains import RetrievalQA


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




# ble_sul = Bluetooth_SUL(NRF52Dongle(port_name=port_name,logs_pcap=logs_pcap,pcap_filename=pcap_filename), advertiser_address,iat,rat, role,rx_len,tx_len ,logger_handle, key_path,test_layer, config_file, return_handle_layer=return_handle_layer,send_handle_layer=send_handle_layer)
alphabet=[]
# alphabet.extend(['ll_connection_update_ind_pkt', 'll_channel_map_req_pkt', 'll_terminate_ind_pkt', 'll_enc_req_pkt', 'll_enc_rsp_pkt', 'll_start_enc_req_pkt', 'll_start_enc_rsp_pkt', 'll_unknown_rsp_pkt', 'll_feature_req_pkt', 'll_feature_rsp_pkt', 'll_pause_enc_req_pkt', 'll_pause_enc_rsp_pkt', 'll_version_ind_pkt', 'll_reject_ind_pkt', 'll_slave_feature_req_pkt', 'll_connection_param_req_pkt', 'll_connection_param_rsp_pkt', 'll_reject_ind_ext_pkt', 'll_ping_req_pkt', 'll_ping_rsp_pkt', 'll_length_req_pkt', 'll_length_rsp_pkt'])
# smp_alphabet = ['master_identification_pkt','pairing_request_pkt', 'identity_information_pkt', 'pairing_confirm_pkt', 'pairing_random_pkt', 'pairing_failed_pkt', 'encryption_information_pkt',  'identity_address_information_pkt', 'signing_information_pkt', 'security_request_pkt', 'pairing_public_key_pkt', 'pairing_dhkey_check_pkt', 'pairing_keypress_notification_pkt']
alphabet.extend(['ll_connection_update_ind_pkt'])
smp_alphabet = ['master_identification_pkt']

smp_alphabet_new = []
for pkt in smp_alphabet:
    if "smp_" in pkt:
        smp_alphabet_new.append(pkt)
    else:
        smp_alphabet_new.append("smp_" + pkt)
alphabet.extend(smp_alphabet_new)
# 加载 JSON 配置文件
with open("/home/yangting/Documents/BSFuzz/config/semseed_config.json", "r") as file:
    config = json.load(file)
    model_config = ModelConfig(config.get("llm", {}).get("model_provider"))
    model = config.get("llm", {}).get("model")
    model_config.update_config({"model":config.get("llm", {}).get("model"),"temperature":config.get("llm", {}).get("temperature"),})
    base_llm = model_config.get_llm()
    jg_model_name = config.get("llm", {}).get("jg_model")
    jg_model = ModelConfig("ali")
    jg_model.update_config({"model":config.get("llm", {}).get("jg_model"),"temperature":0,})
    jg_llm = jg_model.get_llm()
    xml_path = config.get("semext_merge", {}).get("xml_file_path")
   
    # state_seed_path = config.get("semseed_openai", {}).get("cross_field_seed_file_path")
    smp_faiss_index_path = config.get("semext_smp", {}).get("faiss_index_path")
    l2cap_faiss_index_path = config.get("semext_l2cap", {}).get("faiss_index_path")
    att_faiss_index_path = config.get("semext_att", {}).get("faiss_index_path")
    ll_faiss_index_path = config.get("semext_ll", {}).get("faiss_index_path")
    # documents = load_documents(config.get("semext_merge", {}).get("txt_path"))
    pkt_dependency_path_var = config.get("semseed", {}).get("pkt_dependency_path")
    # 在/home/yangting/Documents/Semantic/data/sem_seed/deepseek-r1/jg_model_name_pkt_dependency.json' 将pkt_dependency.json 替换
    pkt_dependency_path = pkt_dependency_path_var.replace("pkt_dependency.json",jg_model_name + "_pkt_dependency.json")


    state_seed_path_var = config.get("semseed", {}).get("state_seed_file_path")
    state_seed_path = state_seed_path_var.replace("${model_provider}",config.get("llm", {}).get("model_provider")).replace("state_seed.json","state_seed_sc.json")

if not state_seed_path:
    raise ValueError("state_seed_path not found in config file")

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
    Refer to the SMP protocol specification to generate state seed for the field. Use chain-of-thought reasoning to break down your analysis.
    
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
    Refer to the L2CAP protocol specification to generate state seed for the field. Use chain-of-thought reasoning to break down your analysis.
    
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
    Refer to the ATT protocol specification to generate state seed for the field. Use chain-of-thought reasoning to break down your analysis.
    
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
    Refer to the Link Layer protocol specification to generate stateseed for the field.
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
    agent = create_agent(base_llm)
    question = get_prompt(packet_name,dependency_info)
    print(question)
    
    # 使用 invoke 方法调用 agent
    try:
        result = agent.invoke({"input": question})
        # 从返回结果中提取 output
        if isinstance(result, str):
            answer = result
        elif hasattr(result, "output"):
            answer = result.output
        elif isinstance(result, dict):
            answer = result.get("output", "")
        else:
            answer = str(result)
    except Exception as e:
        print(f"LLM 调用出错: {str(e)}")
        # 尝试从异常中提取XML
        err_text = str(e)
        answer = None
        
        # 先清理可能的代码块标记
        err_text_clean = re.sub(r'```(?:xml)?\s*|\s*```', '', err_text)
        
        # 尝试提取完整的XML对象（查找 <Packet> 标签）
        packet_start = err_text_clean.find('<Packet')
        if packet_start != -1:
            # 找到对应的 </Packet> 结束标签
            packet_end = err_text_clean.find('</Packet>', packet_start)
            if packet_end != -1:
                answer = err_text_clean[packet_start:packet_end + len('</Packet>')]
        
        # 如果提取失败，创建默认的 Unknown XML
        if answer is None:
            answer = f'<Packet name="{packet_name}"><TestCase ScenarioType="Unknown"><Analysis>Unknown</Analysis><MutationSteps>Unknown</MutationSteps><Validation>Unknown</Validation></TestCase></Packet>'
    
    print(answer)

    # 解析测试用例并保存到JSON
    try:
        test_cases = parse_test_cases(answer)
        output_file = os.path.join(os.path.dirname(state_seed_path), "state_seed_sc.json")
        print(output_file)
        save_test_cases_to_json(test_cases, output_file)
    except Exception as e:
        print(f"解析测试用例出错: {str(e)}")
        # 创建默认的 Unknown 测试用例
        test_cases = [{
            "packet_name": packet_name,
            "scenario_type": "Unknown",
            "analysis": "Unknown",
            "mutation_steps": ["Unknown"],
            "validation": ["Unknown"]
        }]
        output_file = os.path.join(os.path.dirname(state_seed_path), "state_seed_sc.json")
        save_test_cases_to_json(test_cases, output_file)

        
        

if __name__ == "__main__":
    # 取消注释以运行测试
    # test_json_functions()

    for i in alphabet:
        get_answer(i)
    
   
    




