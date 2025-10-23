import os
import sys
import json
import traceback
import xml.etree.ElementTree as ET
from xml.dom import minidom

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
# from BSFuzz.srcs.prompt.Packet_Description import PacketDescriptionGenerator
# from langchain_community.retrievers import BM25Retriever
# from langchain.retrievers import EnsembleRetriever


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
   
    semseed_file_path = config.get("semseed_openai", {}).get("cross_field_seed_file_path")
    faiss_index_path = config.get("semext_merge", {}).get("faiss_index_path")
    documents = load_documents(config.get("semext_merge", {}).get("txt_path"))
    state_seed_file_path = config.get("semseed_openai", {}).get("state_seed_file_path")

if not semseed_file_path:
    raise ValueError("semseed_file_path not found in config file")

# def search_context(faiss_index_path,packet_name, k=141):
def search_context(packet_name):
    packet_name = packet_name.replace("_"," ")
    packet_name = packet_name.replace("SM","smp")
    confidence= []    

   # 从documents中看是包含"MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT","SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL"
    for i in documents:
        if "must" in i.page_content.lower() or "must not" in i.page_content.lower() or "required" in i.page_content.lower() or "shall" in i.page_content.lower() or "shall not" in i.page_content.lower() or "should" in i.page_content.lower() or "should not" in i.page_content.lower() or "recommended" in i.page_content.lower() or "not recommended" in i.page_content.lower() or "may" in i.page_content.lower() or "optional" in i.page_content.lower():
            # 用llm判断是否和packet_name状态转换相关
            print("enter the context")
            question = get_question(packet_name=packet_name,context=i.page_content)
            answer = jg_llm.invoke(question)
            # 匹配JSON格式的响应
            answer_match = re.search(r'\{[\s\n]*"is_relevant":\s*(true|false),\s*"confidence":\s*([0-9.]+)[\s\n]*\}', answer.content, re.DOTALL | re.IGNORECASE)
        
            if answer_match:
                try:
                    is_relevant = answer_match.group(1) == "true"
                    confidence_value = float(answer_match.group(2))
                    
                    print(f"confidence_value: {confidence_value}")
                    print(f"is_relevant: {is_relevant}")
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

    # print(packet_description)
    # new txt file for context
    context_file = f"/home/yangting/Documents/Semantic/data/{packet_name}_state_context.txt"
    if os.path.exists(context_file):
        # 如果存在，则读取
        print(f"context file {context_file} exists")
        with open(context_file, "r") as f:
            context = f.readlines()
    else:
        print(f"context file {context_file} not exists")
        context = search_context(packet_name)  # 使用配置文件中的 xml_path
        # 将context 写入临时txt文件
        print("len of context: ",len(context))
        with open(context_file, "w") as f:
            f.write("\n".join(context))
    for i in context:
        
        packet_description = get_prompt(target=packet_name,background_info=i) 

        # 直接使用 LLM 获取回答
        answer = llm.invoke(packet_description)

      


        answer_to_xml(packet_name,answer.content)
        
    # remove txt
    os.remove(context_file)
   

# write answer to xml file
def answer_to_xml(packet_name, answer):
    """将回答写入XML文件，如果数据包已存在则补充，使用改进的XML处理"""
    global state_seed_file_path
    
    # 提取XML测试用例
    test_cases = extract_test_cases(answer)
    
    if not test_cases:
        print(f"警告：未能从{packet_name}的回答中提取测试用例")
        return False
    
    # 检查XML文件是否存在
    if os.path.exists(state_seed_file_path) and os.path.getsize(state_seed_file_path) > 0:
        try:
            # 尝试解析现有的XML文件
            tree = ET.parse(state_seed_file_path)
            root = tree.getroot()
            
            # 查找是否已存在该数据包
            existing_packet = None
            for packet in root.findall(".//Packet"):
                if packet.get("name") == packet_name:
                    existing_packet = packet
                    break
            
            if existing_packet is not None:
                # 数据包已存在，追加测试用例
                print(f"找到现有数据包 {packet_name}，正在追加测试用例")
                
                # 添加测试用例
                for test_case in test_cases:
                    add_test_case_to_element(existing_packet, test_case)
                
                # 使用格式化后的XML写入文件
                xml_str = prettify_xml(root)
                with open(state_seed_file_path, 'w', encoding='utf-8') as f:
                    f.write('<?xml version="1.0" encoding="utf-8"?>\n')
                    f.write(xml_str)
                
                print(f"成功将测试用例追加到 {packet_name}")
                return True
            
            # 如果数据包不存在，创建新的数据包元素
            packet_element = ET.SubElement(root, "Packet")
            packet_element.set("name", packet_name)
            
            # 添加测试用例
            for test_case in test_cases:
                add_test_case_to_element(packet_element, test_case)
            
            # 使用格式化后的XML写入文件
            xml_str = prettify_xml(root)
            with open(state_seed_file_path, 'w', encoding='utf-8') as f:
                f.write('<?xml version="1.0" encoding="utf-8"?>\n')
                f.write(xml_str)
            
            return True
            
        except Exception as e:
            print(f"解析现有XML文件时出错: {e}")
            print("创建新的XML结构")
            root = ET.Element("TestCases")
            packet_element = ET.SubElement(root, "Packet")
            packet_element.set("name", packet_name)
    else:
        # 创建一个新的XML结构
        root = ET.Element("TestCases")
        packet_element = ET.SubElement(root, "Packet")
        packet_element.set("name", packet_name)
    
    # 添加测试用例到新创建的数据包
    for test_case in test_cases:
        add_test_case_to_element(packet_element, test_case)
    
    # 确保目录存在（如果文件路径包含目录）
    dir_name = os.path.dirname(state_seed_file_path)
    if dir_name:  # 只有当目录名不为空时才创建目录
        os.makedirs(dir_name, exist_ok=True)
    
    # 使用格式化后的XML写入文件
    xml_str = prettify_xml(root)
    with open(state_seed_file_path, 'w', encoding='utf-8') as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n')
        f.write(xml_str)
    
    print(f"成功创建了包含 {packet_name} 测试用例的新XML文件")
    return True

def add_test_case_to_element(parent_element, test_case):
    """将测试用例添加到父元素中"""
    # 创建测试用例元素
    case_element = ET.SubElement(parent_element, "TestCase")
    
    # 添加场景类型
    scenario_type = test_case.get("Scenario Type", "")
    if scenario_type:
        scenario_element = ET.SubElement(case_element, "ScenarioType")
        scenario_element.text = scenario_type
    
    # 添加分析
    analysis = test_case.get("Analysis", "")
    if analysis:
        analysis_element = ET.SubElement(case_element, "Analysis")
        analysis_element.text = analysis
    
    # 添加变异步骤
    mutation_steps = test_case.get("Mutation Steps", "")
    if mutation_steps:
        steps_element = ET.SubElement(case_element, "MutationSteps")
        steps_element.text = mutation_steps
    
    # 添加验证
    validation = test_case.get("Validation", "")
    if validation:
        validation_element = ET.SubElement(case_element, "Validation")
        validation_element.text = validation
    
    return case_element

def prettify_xml(elem):
    """生成美观的XML格式，将多行文本合并为单行"""
    # 将元素转换为字符串
    rough_string = ET.tostring(elem, 'utf-8')
    
    # 使用minidom解析字符串
    parsed = minidom.parseString(rough_string)
    
    # 根元素标签
    root_tag = elem.tag
    
    # 自定义格式化函数
    def format_element(element, indent_level=0):
        indent = "  " * indent_level
        result = []
        
        # 开始标签
        attrs = ""
        for i in range(element.attributes.length):
            attr = element.attributes.item(i)
            attrs += f' {attr.name}="{attr.value}"'
        
        # 检查是否有子元素
        has_element_children = any(child.nodeType == child.ELEMENT_NODE for child in element.childNodes)
        
        # 获取文本内容
        text_content = ""
        for child in element.childNodes:
            if child.nodeType == child.TEXT_NODE:
                text = child.data.strip()
                if text:
                    text_content += text
        
        # 处理内容
        if has_element_children:
            # 有子元素，递归处理
            result.append(f"{indent}<{element.tagName}{attrs}>")
            for child in element.childNodes:
                if child.nodeType == child.ELEMENT_NODE:
                    result.extend(format_element(child, indent_level + 1))
            result.append(f"{indent}</{element.tagName}>")
        elif text_content:
            # 只有文本内容，合并为单行
            # 将多行文本中的换行替换为空格
            text_content = re.sub(r'\s*\n\s*', ' ', text_content)
            # 将连续的空格替换为单个空格
            text_content = re.sub(r'\s+', ' ', text_content)
            
            # 如果文本很短，使用内联格式
            if len(text_content) < 80:
                result.append(f"{indent}<{element.tagName}{attrs}>{text_content}</{element.tagName}>")
            else:
                # 如果文本较长，使用缩进格式但保持单行
                result.append(f"{indent}<{element.tagName}{attrs}>")
                result.append(f"{indent}  {text_content}")
                result.append(f"{indent}</{element.tagName}>")
        else:
            # 空元素
            result.append(f"{indent}<{element.tagName}{attrs}></{element.tagName}>")
        
        return result
    
    # 处理根元素和它的所有子元素
    formatted_lines = []
    formatted_lines.append(f"<{root_tag}{' ' if elem.attrib else ''}{' '.join([f'{k}=\"{v}\"' for k, v in elem.attrib.items()])}>")
    
    # 处理子元素
    for child in parsed.documentElement.childNodes:
        if child.nodeType == child.ELEMENT_NODE:
            formatted_lines.extend(['  ' + line for line in format_element(child)])
    
    # 添加根元素的结束标签
    formatted_lines.append(f"</{root_tag}>")
    
    return "\n".join(formatted_lines)

def extract_test_cases(answer):
    """从回答中提取测试用例，使用更可靠的XML解析方式"""
    test_cases = []
    
    # 尝试使用更可靠的方法处理XML
    # 首先尝试创建一个完整的XML文档
    try:
        # 尝试将回答内容包装成完整的XML文档
        wrapped_content = f"<TestCasesRoot>{answer}</TestCasesRoot>"
        root = ET.fromstring(wrapped_content)
        
        # 查找所有测试用例标签
        test_case_elements = root.findall(".//TestCase")
        
        # 如果没有找到使用标准格式，尝试处理可能的空格问题
        if not test_case_elements:
            # 替换标签中可能的空格，使其更规范
            normalized_content = re.sub(r'<\s*Test\s*Case\s*>', '<TestCase>', answer)
            normalized_content = re.sub(r'<\s*/\s*Test\s*Case\s*>', '</TestCase>', normalized_content)
            normalized_content = re.sub(r'<\s*Scenario\s*Type\s*>', '<ScenarioType>', normalized_content)
            normalized_content = re.sub(r'<\s*/\s*Scenario\s*Type\s*>', '</ScenarioType>', normalized_content)
            normalized_content = re.sub(r'<\s*Mutation\s*Steps\s*>', '<MutationSteps>', normalized_content)
            normalized_content = re.sub(r'<\s*/\s*Mutation\s*Steps\s*>', '</MutationSteps>', normalized_content)
            
            wrapped_content = f"<TestCasesRoot>{normalized_content}</TestCasesRoot>"
            try:
                root = ET.fromstring(wrapped_content)
                test_case_elements = root.findall(".//TestCase")
            except ET.ParseError:
                # 如果仍然无法解析，使用正则表达式回退方案
                return extract_test_cases_regex(answer)
        
        # 处理找到的测试用例元素
        for tc_elem in test_case_elements:
            test_case = {}
            
            # 提取场景类型
            scenario_elem = tc_elem.find(".//ScenarioType")
            if scenario_elem is not None and scenario_elem.text:
                test_case["Scenario Type"] = normalize_text(scenario_elem.text)
            
            # 提取分析
            analysis_elem = tc_elem.find(".//Analysis")
            if analysis_elem is not None and analysis_elem.text:
                test_case["Analysis"] = normalize_text(analysis_elem.text)
            
            # 提取变异步骤
            steps_elem = tc_elem.find(".//MutationSteps")
            if steps_elem is not None and steps_elem.text:
                test_case["Mutation Steps"] = normalize_text(steps_elem.text)
            
            # 提取验证
            validation_elem = tc_elem.find(".//Validation")
            if validation_elem is not None and validation_elem.text:
                test_case["Validation"] = normalize_text(validation_elem.text)
            
            if test_case:  # 只有当测试用例不为空时才添加
                test_cases.append(test_case)
                
    except ET.ParseError:
        # 如果XML解析失败，回退到正则表达式方法
        return extract_test_cases_regex(answer)
    
    return test_cases

def normalize_text(text):
    """标准化文本，移除多余的空白和换行"""
    if text is None:
        return ""
    text = text.strip()
    text = re.sub(r'\s*\n\s*', ' ', text)  # 将换行替换为空格
    text = re.sub(r'\s+', ' ', text)       # 将连续空格替换为单个空格
    return text

def extract_test_cases_regex(answer):
    """使用正则表达式从回答中提取测试用例（作为备选方案）"""
    test_cases = []
    
    # 查找所有的测试用例，处理标签中的空格
    pattern = r'<Test\s*Case>\s*(.*?)\s*</Test\s*Case>'
    matches = re.findall(pattern, answer, re.DOTALL)
    
    for match in matches:
        test_case = {}
        
        # 提取场景类型（处理标签中的空格）
        scenario_match = re.search(r'<Scenario\s*Type>\s*(.*?)\s*</Scenario\s*Type>', match, re.DOTALL)
        if scenario_match:
            test_case["Scenario Type"] = normalize_text(scenario_match.group(1))
        
        # 提取分析（处理标签中的空格）
        analysis_match = re.search(r'<Analysis>\s*(.*?)\s*</Analysis>', match, re.DOTALL)
        if analysis_match:
            test_case["Analysis"] = normalize_text(analysis_match.group(1))
        
        # 提取变异步骤（处理标签中的空格）
        steps_match = re.search(r'<Mutation\s*Steps>\s*(.*?)\s*</Mutation\s*Steps>', match, re.DOTALL)
        if steps_match:
            test_case["Mutation Steps"] = normalize_text(steps_match.group(1))
        
        # 提取验证（处理标签中的空格）
        validation_match = re.search(r'<Validation>\s*(.*?)\s*</Validation>', match, re.DOTALL)
        if validation_match:
            test_case["Validation"] = normalize_text(validation_match.group(1))
        
        if test_case:  # 只有当测试用例不为空时才添加
            test_cases.append(test_case)
    
    return test_cases

def find_in_xml(packet_name, xml_file_path=None):
    """检查数据包是否已存在于XML文件中"""
    global state_seed_file_path
    
    # 如果未提供xml_file_path，则使用全局变量state_seed_file_path
    if xml_file_path is None:
        xml_file_path = state_seed_file_path
        
    if not os.path.exists(xml_file_path) or os.path.getsize(xml_file_path) == 0:
        return False
    
    try:
        # 读取文件内容
        with open(xml_file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
        
        # 检查内容是否为有效的XML
        if (not content.startswith("<?xml") and not content.startswith("<TestCases")) or "<Packet" not in content:
            print(f"警告: 文件 {xml_file_path} 不包含有效的XML或没有Packet元素")
            return False
            
        # 尝试解析XML
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()
        except ET.ParseError as pe:
            print(f"解析XML文件 {xml_file_path} 时出错: {pe}")
            # 尝试修复XML结构
            if content.startswith("<?xml"):
                xml_parts = content.split("?>", 1)
                if len(xml_parts) > 1:
                    content = xml_parts[1].strip()
            
            if "<TestCases>" not in content:
                content = f"<TestCases>{content}</TestCases>"
            
            try:
                root = ET.fromstring(content)
            except ET.ParseError:
                print(f"无法修复XML文件 {xml_file_path}，假定数据包不存在")
                return False
        
        # 查找数据包
        for packet in root.findall(".//Packet"):
            if packet.get("name") == packet_name:
                return True
        
        return False
    except Exception as e:
        print(f"检查XML文件时出错: {e}")
        return False

def test_append_testcase():
    """测试向已有数据包追加测试用例的功能"""
    global state_seed_file_path
    
    # 设置测试用的XML文件路径
    original_path = state_seed_file_path
    test_path = os.path.join(os.path.dirname(state_seed_file_path), "test_state_seed.xml")
    state_seed_file_path = test_path
    
    try:
        # 创建测试XML文件
        root = ET.Element("TestCases")
        packet = ET.SubElement(root, "Packet")
        packet.set("name", "Test_Packet")
        
        test_case = ET.SubElement(packet, "TestCase")
        scenario = ET.SubElement(test_case, "ScenarioType")
        scenario.text = "Original Test Case"
        
        # 使用ElementTree写入文件，确保XML结构正确
        tree = ET.ElementTree(root)
        os.makedirs(os.path.dirname(test_path), exist_ok=True)
        tree.write(test_path, encoding='utf-8', xml_declaration=True)
        
        print(f"Created test XML file with one test case")
        
        # 创建一个新的测试用例答案
        test_answer = """
        <TestCase>
            <ScenarioType>Appended Test Case</ScenarioType>
            <Analysis>This is a test analysis</Analysis>
            <MutationSteps>Step 1, Step 2, Step 3</MutationSteps>
            <Validation>Test validation</Validation>
        </TestCase>
        """
        
        # 调用追加函数
        result = answer_to_xml("Test_Packet", test_answer)
        
        if result:
            # 验证结果
            tree = ET.parse(test_path)
            root = tree.getroot()
            
            # 查找测试用例
            packet_element = root.find(".//Packet[@name='Test_Packet']")
            if packet_element is not None:
                test_cases = packet_element.findall("TestCase")
                
                if len(test_cases) == 2:
                    # 验证原始测试用例和新追加的测试用例
                    scenario_types = [tc.find("ScenarioType").text for tc in test_cases if tc.find("ScenarioType") is not None]
                    
                    if "Original Test Case" in scenario_types and "Appended Test Case" in scenario_types:
                        print("测试成功：找到原始测试用例和新追加的测试用例")
                    else:
                        print(f"测试失败：未找到预期的场景类型，找到的是 {scenario_types}")
                else:
                    print(f"测试失败：预期找到2个测试用例，但找到了 {len(test_cases)} 个")
            else:
                print(f"测试失败：未找到名为Test_Packet的Packet元素")
        else:
            print("测试失败：answer_to_xml 返回 False")
    
    except Exception as e:
        print(f"测试出错：{e}")
        import traceback
        traceback.print_exc()
    finally:
        # 清理并恢复原始路径
        if os.path.exists(test_path):
            os.remove(test_path)
        state_seed_file_path = original_path
        print("测试完成，已恢复原始路径")

def main():
    # 判断 xml_file_path 是否存在，不存在则创建

    
    if not os.path.exists(state_seed_file_path):
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(state_seed_file_path), exist_ok=True)
            # 创建文件并写入初始 XML 结构
            root = ET.Element("TestCases")
            tree = ET.ElementTree(root)
            xml_str = minidom.parseString(ET.tostring(root, encoding='utf-8')).toprettyxml(indent="  ")
            with open(state_seed_file_path, "w", encoding="utf-8") as f:
                f.write(xml_str)
            print(f"Created new XML file at {state_seed_file_path}")
        except Exception as e:
            print(f"Error creating XML file: {e}")
            return
    elif os.path.getsize(state_seed_file_path) == 0:
        # 文件存在但为空，写入初始 XML 结构
        try:
            root = ET.Element("TestCases")
            tree = ET.ElementTree(root)
            xml_str = minidom.parseString(ET.tostring(root, encoding='utf-8')).toprettyxml(indent="  ")
            with open(state_seed_file_path, "w", encoding="utf-8") as f:
                f.write(xml_str)
            print(f"Initialized empty XML file at {state_seed_file_path}")
        except Exception as e:
            print(f"Error initializing XML file: {e}")
            return
    
    # 获取数据包列表
    pkt = pkt_list(alphabet, "SMP")
    
    for i in range(len(pkt)):  # 使用索引而不是直接迭代
        current_packet = pkt[i]
        packet_name = current_packet["packet name"]
          
        if find_in_xml(packet_name, semseed_file_path):
            # 判断是否是最后一个数据包
            if i == len(pkt) - 1:
                get_answer(packet_name)
            else:
                # 判断下一个是否存在
                next_packet = pkt[i + 1]
                if find_in_xml(next_packet["packet name"], semseed_file_path):
                    continue
                else:
                    get_answer(packet_name)
        else:
            get_answer(packet_name)

        
        

if __name__ == "__main__":
    # 取消注释以运行测试
    pkt = pkt_list(alphabet, "SMP")
    print(pkt)
    # main()
    



