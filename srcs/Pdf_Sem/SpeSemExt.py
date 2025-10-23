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
from BSFuzz.srcs.Config_File.Cypress import config
import re
from time import sleep
from BSFuzz.srcs.llm_model.ModConf import ModelConfig


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
with open("/home/yangting/Documents/Semantic/config/semext_config.json", "r") as file:
    config = json.load(file)
    model_config = ModelConfig(config.get("llm", {}).get("model_provider"))
    model = config.get("llm", {}).get("model")
    model_config.update_config({"model":config.get("llm", {}).get("model"),"temperature":config.get("llm", {}).get("temperature"),})
    llm = model_config.get_llm()
    pdf_path = config.get("semext_mesh", {}).get("pdf_path")
    faiss_index_path = config.get("semext_mesh", {}).get("faiss_index_path")
    index_name = pdf_path.split('/')[-1]
    xml_path = config.get("semext_mesh", {}).get("xml_file_path")
    embedding_model = config.get("llm", {}).get("embedding_model")
    
# def count_tokens(text, model):
#     """计算单个文本的 token 数"""
#     encoding = tiktoken.encoding_for_model(model)
#     return len(encoding.encode(text))

def query(question):
    embeddings = OpenAIEmbeddings(model=embedding_model)
    vector_db = FAISS.load_local(faiss_index_path, embeddings, allow_dangerous_deserialization=True)
    retriever = vector_db.as_retriever()  # 只检索 3 个文档
    qa_chain = RetrievalQA.from_chain_type(llm=llm, retriever=retriever)

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


def get_answer(packt_name,field):
    prompt = SemExtPrompt.get_prompt()
    query_prompt=prompt.format(packet_name=packt_name, field=field)
    answer = query(query_prompt)
    return answer

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
            answer = get_answer(pkt["packet name"],pkt["field"])
            print(answer)
        except:
            print(f"Error: {pkt['packet name']} {pkt['field']} not found")
            logger.error(f"Error: {pkt['packet name']} {pkt['field']} not found")
            answer = "<answer><field_bit_length>Unknown</field_bit_length><semantic>Unknown</semantic><defined_values>Unknown</defined_values></answer>"

        match = re.search(r"<answer>[\s\S]*?</answer>", answer)
        if match:
            answer = match.group(0)
        else:
            print(f"Error: {pkt['packet name']} {pkt['field']}")
            answer = "<answer><field_bit_length>Unknown</field_bit_length><semantic>Unknown</semantic><defined_values>Unknown</defined_values></answer>"
        try:
            answer_xml = ET.fromstring(answer) 
        except:
            # 打印出错的包名和字段名
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
    pkt_list = pkt_list(alphabet)
    answer_to_xml(pkt_list)





    # pkt_list = pkt_list(alphabet)
    # i = 0

    # for pkt in pkt_list:
    #     if i <3:
    #         prompt = SemExtPrompt.get_prompt()
    #         query_prompt=prompt.format(packet_name=pkt["packet name"], field=pkt["field"])
    #         answer = query(faiss_index_path,query_prompt)
    #         print(answer)
    #         i = i+1

    # xml_string = """<answer>
    #     <semantic>Indicates the presence of Out Of Band (OOB) authentication data, influencing the pairing method and security level by signifying whether OOB data is available from a remote device or not.</semantic>
    #     <defined_values>0x00 (no OOB data), 0x01 (OOB data available from a remote device), 0x02-0xFF (Reserved for future use)</defined_values>
    #     <fuzz_seed>0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x1F, 0x3F, 0x7F, 0xFF, 0x0B, 0x10, 0x20, 0x80, 0xFE</fuzz_seed>
    # </answer>"""

    # # ✅ 解析 XML
    # answer = ET.fromstring(xml_string)

    # # ✅ 提取各个字段
    # semantic = answer.find("semantic").text
    # defined_values = answer.find("defined_values").text
    # fuzz_seed = answer.find("fuzz_seed").text

    # # ✅ 打印结果
    # print("Semantic:", semantic)
    # print("Defined Values:", defined_values)
    # print("Fuzz Seed:", fuzz_seed)





# prompt = SemExtPrompt.get_prompt()
# query_prompt=prompt.format(packet_name="pairing request", field="authtication")
# answer = query(faiss_index_path,query_prompt)
# print(answer)
# print(memory.load_memory_variables({}))
# question = "packet name:pairing request,field:authtication"
# answer = llm_qa.run(question)
# print(answer)



