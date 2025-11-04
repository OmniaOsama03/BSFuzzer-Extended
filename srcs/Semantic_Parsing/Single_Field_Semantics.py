import os
import sys
import json

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.chains import RetrievalQA
from BSFuzz.srcs.prompt import SemExtPrompt
from BSFuzz.srcs.Send_Packet.Bluetooth_SUL import Bluetooth_SUL
from BSFuzz.libs.driver.NRF52_dongle import NRF52Dongle
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
from BSFuzz.srcs.Log_Config.logger_config import *
from BSFuzz.srcs.Config_File.Esp32 import config
import re
from time import sleep
from BSFuzz.srcs.llm_model.ModConf import ModelConfig
from langchain.agents import initialize_agent, Tool, AgentType
from langchain.prompts import PromptTemplate
from langchain.tools import Tool


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

# alphabet.extend(['master_identification_pkt','pairing_request_pkt', 'identity_information_pkt', 'pairing_response_pkt', 'pairing_confirm_pkt', 'pairing_random_pkt', 'pairing_failed_pkt', 'encryption_information_pkt',  'identity_address_information_pkt', 'signing_information_pkt', 'security_request_pkt', 'pairing_public_key_pkt', 'pairing_dhkey_check_pkt', 'pairing_keypress_notification_pkt'])
# print(prompt.format(packet_name="pairing request", field="io_cap"))
# alphabet.extend(['ll_connection_update_ind_pkt'])
alphabet.extend(['pairing_response_pkt'])
# 加载 JSON 配置文件
with open("/home/yangting/Documents/BSFuzz/config/semext_config.json", "r") as file:
    config = json.load(file)
    model_config = ModelConfig(config.get("llm", {}).get("model_provider"))
    model = config.get("llm", {}).get("model")
    model_config.update_config({"model":config.get("llm", {}).get("model"),"temperature":config.get("llm", {}).get("temperature"),})
    base_llm = model_config.get_llm()
    pdf_path = config.get("semext_smp", {}).get("pdf_path")
    faiss_index_path = config.get("semext_smp", {}).get("faiss_index_path")
    index_name = pdf_path.split('/')[-1]
    xml_path = config.get("semext_smp", {}).get("xml_file_path")
    embedding_model = config.get("llm", {}).get("embedding_model")
    smp_faiss_index_path = config.get("semext_smp", {}).get("faiss_index_path")
    l2cap_faiss_index_path = config.get("semext_l2cap", {}).get("faiss_index_path")
    att_faiss_index_path = config.get("semext_att", {}).get("faiss_index_path")
    ll_faiss_index_path = config.get("semext_ll", {}).get("faiss_index_path")
    
# def count_tokens(text, model):
#     """计算单个文本的 token 数"""
#     encoding = tiktoken.encoding_for_model(model)
#     return len(encoding.encode(text))

def query(question):
    embeddings = OpenAIEmbeddings(model=embedding_model)
    vector_db = FAISS.load_local(faiss_index_path, embeddings, allow_dangerous_deserialization=True)
    retriever = vector_db.as_retriever()  # 只检索 3 个文档
    qa_chain = RetrievalQA.from_chain_type(llm=base_llm, retriever=retriever)

    # ✅ 计算 Token
    # input_tokens = count_tokens(question,model)  # 计算用户输入 Token
    docs = retriever.invoke(question)  # 获取检索到的知识
    # knowledge_tokens = sum(count_tokens(doc.page_content,model) for doc in docs)  # 计算知识库 Token

    # total_tokens = input_tokens + knowledge_tokens  # 预计总 Token
    # print(f"📝 输入 Token: {input_tokens}, 📚 知识库 Token: {knowledge_tokens}, 🔢 预计总 Token: {total_tokens}")

    answer_dict = qa_chain.invoke({"query": question})
      # 执行查询
    return answer_dict["result"]

def pkt_list(alphabet):
    pkt_list = []
    i= 0
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

        fields = hdr_layer.default_fields
        if i == 0 :
            for field in fields:
                pkt_list.append({"packet name":type(hdr_layer).__name__,"field":field})
                # print(f"packet_name:{type(sm_hdr_layer).__name__},field:{field}")
            i = 1
    
        if hdr_layer:
            fields = hdr_layer.payload.default_fields
            for field in fields:
                pkt_list.append({"packet name":type(hdr_layer.payload).__name__,"field":field})
                # print(f"packet_name:{type(sm_hdr_layer.payload).__name__},field:{field}")
    return pkt_list


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
    Focus on security features, pairing procedures, and authentication mechanisms.
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
        name="SMP_Spec_Retriever",
        func=qa_chain.invoke,
        description="Retrieves and analyzes information specific to Bluetooth SMP protocol from the specification."
    )

def create_l2cap_retrieval_tool(vector_store, k_value=10):
    prompt_template = """
    You are a Bluetooth L2CAP (Logical Link Control and Adaptation Protocol) expert analyzing the Bluetooth Core Specification.
    Use the provided context from the specification to answer questions about L2CAP protocol.
    Focus on channel management, segmentation and reassembly, and multiplexing capabilities.
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
        name="L2CAP_Spec_Retriever",
        func=qa_chain.invoke,
        description="Retrieves and analyzes information specific to Bluetooth L2CAP protocol from the specification."
    )

def create_att_retrieval_tool(vector_store, k_value=10):
    prompt_template = """
    You are a Bluetooth ATT (Attribute Protocol) expert analyzing the Bluetooth Core Specification.
    Use the provided context from the specification to answer questions about ATT protocol.
    Focus on attribute operations, data formats, and error handling procedures.
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
    Focus on connection establishment, packet formats, and state machines.
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

def get_answer(packet_name, field):
    agent = create_agent(base_llm, k_value=15)
    query_prompt = SemExtPrompt.get_prompt(packet_name=packet_name, field=field)
    result = agent.invoke({"input": query_prompt})
    return result["output"]

def _clean_and_extract_answer(raw_text):
    if not isinstance(raw_text, str):
        raw_text = str(raw_text)
    # 去除 Markdown 反引号与代码围栏残留
    cleaned = raw_text.replace('`', '')
    # 去除常见的提示/链接行
    cleaned_lines = []
    for line in cleaned.splitlines():
        striped = line.strip()
        if striped.lower().startswith('for troubleshooting'):
            continue
        if striped.startswith('http://') or striped.startswith('https://'):
            continue
        cleaned_lines.append(line)
    cleaned = "\n".join(cleaned_lines)
    # 修复常见格式错误
    cleaned = cleaned.replace('defined_values>ned_values>', 'defined_values>')
    # 选取最后一个 <answer>...</answer>（很多 ReAct 会多次打印）
    matches = re.findall(r"<answer>[\s\S]*?</answer>", cleaned)
    if matches:
        return matches[-1]
    return None


def answer_to_xml(pkt_list):
    append_flag = 0
    # Check if XML file exists
    if os.path.exists(xml_path):
        if os.path.getsize(xml_path) == 0:
            # Create a new XML tree if the file exists but is empty
            root = ET.Element('layer', name='smp')
            tree = ET.ElementTree(root)
        else:
            # Load existing XML
            tree = ET.parse(xml_path)
            root = tree.getroot()
    else:
        # Create a new XML structure if the file doesn't exist
        root = ET.Element('layer', name='smp')
        tree = ET.ElementTree(root)

    for pkt in pkt_list:
        # Check if packet and field already exist in the XML
        if find_in_xml(pkt["packet name"], pkt["field"], root):          
            print(f"Info: {pkt['packet name']} {pkt['field']} already exists")
            continue
        try:
            answer = get_answer(pkt["packet name"], pkt["field"])
            raw_text = answer
        except Exception as e:
            err_text = str(e)
            match = re.search(r"<answer>[\s\S]*?</answer>", err_text)
            if match:
                raw_text = match.group(0)
            else:
                raw_text = "<answer><field_bit_length>Unknown</field_bit_length><semantic>Unknown</semantic><defined_values>Unknown</defined_values></answer>"

        cleaned_answer = _clean_and_extract_answer(raw_text)
        if cleaned_answer is None:
            # 若未能从文本中抽取到 <answer>，但原始文本已经是占位 XML，则直接使用
            if "<answer>" in (raw_text or ""):
                cleaned_answer = raw_text
            else:
                print(f"Error: {pkt['packet name']} {pkt['field']}")
                cleaned_answer = "<answer><field_bit_length>Unknown</field_bit_length><semantic>Unknown</semantic><defined_values>Unknown</defined_values></answer>"
        print(cleaned_answer)
        # except:
        #     print(f"Error: {pkt['packet name']} {pkt['field']} not found")
        #     logger.error(f"Error: {pkt['packet name']} {pkt['field']} not found")
        #     answer = "<answer><field_bit_length>Unknown</field_bit_length><semantic>Unknown</semantic><defined_values>Unknown</defined_values></answer>"

        try:
            answer_xml = ET.fromstring(cleaned_answer)
        except:
            # 若 XML 不合规，尝试用正则提取三段并重组有效 XML 后继续
            bit_len = re.search(r"<field_bit_length>\s*([\s\S]*?)\s*</field_bit_length>", cleaned_answer or "")
            semantic_txt = re.search(r"<semantic>\s*([\s\S]*?)\s*</semantic>", cleaned_answer or "")
            defined_vals = re.search(r"<defined_values>\s*([\s\S]*?)\s*</defined_values>", cleaned_answer or "")
            bl = (bit_len.group(1).strip() if bit_len else "Unknown")
            se = (semantic_txt.group(1).strip() if semantic_txt else "Unknown")
            dv = (defined_vals.group(1).strip() if defined_vals else "Unknown")
            rebuilt = f"<answer><field_bit_length>{bl}</field_bit_length><semantic>{se}</semantic><defined_values>{dv}</defined_values></answer>"
            try:
                answer_xml = ET.fromstring(rebuilt)
            except:
                # 打印出错的包名和字段名，兜底为 Unknown
                print(f"Error: {pkt['packet name']} {pkt['field']}")
                answer = "<answer><field_bit_length>Unknown</field_bit_length><semantic>Unknown</semantic><defined_values>Unknown</defined_values></answer>"
                answer_xml = ET.fromstring(answer)
        new_packet = ET.Element('packet', name= pkt["packet name"])
        new_field = ET.SubElement(new_packet, 'field', name=pkt["field"])
        field_bit_length = ET.SubElement(new_field, 'field_bit_length')
        field_bit_length.text = answer_xml.find("field_bit_length").text
        semantic = ET.SubElement(new_field, 'semantic')
        semantic.text = answer_xml.find("semantic").text
        defined_values = ET.SubElement(new_field, 'defined_values')
        defined_values.text = answer_xml.find("defined_values").text
        # fuzz_seed = ET.SubElement(new_field, 'fuzz_seed')
        # fuzz_seed.text = answer_xml.find("fuzz_seed").text
        root.append(new_packet)
        append_flag = 1
        sleep(3)
    if append_flag == 0:
        return
    # Convert to pretty-printed XML format
    xml_str = ET.tostring(root, encoding='utf-8')
    parsed_str = minidom.parseString(xml_str)

    # Format XML without extra blank lines
    pretty_xml_as_string = parsed_str.toprettyxml(indent="  ")
    # Write back to file
    with open(xml_path, 'w', encoding='utf-8') as f:
        f.write(pretty_xml_as_string)

def find_in_xml(packet_name, field_name, root):
    """Check if a packet with the given name and field already exists in XML"""
    for packet in root.findall("packet"):
        if packet.get("name") == packet_name:
            for field in packet.findall("field"):
                if field.get("name") == field_name:
                    return True
    return False
if __name__ == "__main__":
    pkt_list1 = pkt_list(alphabet)
    answer_to_xml(pkt_list1)





