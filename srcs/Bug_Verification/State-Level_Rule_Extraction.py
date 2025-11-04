import os
import sys
import json
import xml.etree.ElementTree as ET

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")

from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS
from langchain.chains import RetrievalQA
from langchain.agents import initialize_agent, Tool, AgentType
from langchain.prompts import PromptTemplate
from BSFuzz.srcs.llm_model.ModConf import ModelConfig
# from BSFuzz.srcs.prompt.SemFieldRspPrompt import get_field_prompt
from BSFuzz.srcs.prompt.SemExpectStateRsp import get_prompt


llpkts = ['ll_pkts','ll_connection_update_ind_pkt', 'll_channel_map_req_pkt', 'll_terminate_ind_pkt', 'll_enc_req_pkt', 'll_enc_rsp_pkt', 'll_start_enc_req_pkt', 'll_start_enc_rsp_pkt', 'll_unknown_rsp_pkt', 'll_feature_req_pkt', 'll_feature_rsp_pkt', 'll_pause_enc_req_pkt', 'll_pause_enc_rsp_pkt', 'll_version_ind_pkt', 'll_reject_ind_pkt', 'll_slave_feature_req_pkt', 'll_connection_param_req_pkt', 'll_connection_param_rsp_pkt', 'll_reject_ind_ext_pkt', 'll_ping_req_pkt', 'll_ping_rsp_pkt', 'll_length_req_pkt', 'll_length_rsp_pkt','ll_empty_pkt']
smppkts = ['smp_pkts','pairing_request_pkt', 'pairing_response_pkt', 'pairing_confirm_pkt', 'pairing_random_pkt', 'pairing_failed_pkt', 'encryption_information_pkt', 'master_identification_pkt', 'identity_information_pkt', 'identity_address_information_pkt', 'signing_information_pkt', 'security_request_pkt', 'pairing_public_key_pkt', 'pairing_dhkey_check_pkt', 'pairing_keypress_notification_pkt']
pkts = {
    "ll_pkts": llpkts,
    "smp_pkts": smppkts
}


with open("/home/yangting/Documents/BSFuzz/config/semresult_config.json", "r") as file:
    config = json.load(file)
    field_model_config = ModelConfig(config.get("llm", {}).get("field_model_provider"))
    state_model_config = ModelConfig(config.get("llm", {}).get("state_model_provider"))
    base_model_config = ModelConfig(config.get("llm", {}).get("base_model_provider"))


    field_model = config.get("llm", {}).get("model")
    state_model = config.get("llm", {}).get("state_model")
    base_model = config.get("llm", {}).get("base_model")
# 
    field_model_config.update_config({"model":config.get("llm", {}).get("field_model"),"temperature":config.get("llm", {}).get("temperature"),})
    state_model_config.update_config({"model":config.get("llm", {}).get("state_model"),"temperature":config.get("llm", {}).get("temperature"),})
    base_model_config.update_config({"model":config.get("llm", {}).get("base_model"),"temperature":config.get("llm", {}).get("temperature"),})
    field_llm = field_model_config.get_llm()
    state_llm = state_model_config.get_llm()
    base_llm = base_model_config.get_llm()
    smp_faiss_index_path = config.get("faiss_index_path", {}).get("smp_faiss_index_path")
    l2cap_faiss_index_path = config.get("faiss_index_path", {}).get("l2cap_faiss_index_path")
    att_faiss_index_path = config.get("faiss_index_path", {}).get("att_faiss_index_path")
    ll_faiss_index_path = config.get("faiss_index_path", {}).get("ll_faiss_index_path")
    seed_result_file_path = config.get("semresult", {}).get("seed_result_file_path")
    answer_result_file_path = config.get("semresult", {}).get("state_validation_result_file_path")
    sem_info_file_path = config.get("sem_info", {}).get("sem_info_file_path")


def load_sem_info(sem_info_file_path):
    tree = ET.parse(sem_info_file_path)
    root = tree.getroot()
    return root

def get_packet_fields(sem_info_file_path):
    tree = ET.parse(sem_info_file_path)
    root = tree.getroot()
    field_info = []
    for packet in root.findall('.//packet'):
        packet_name = packet.get('name')
        for field in packet.findall('.//field'):
            field_name = field.get('name')
            semantic = field.find('semantic')
            defined_values = field.find('defined_values')
            field_info.append({
                'layer_name': packet_name,
                'field_name': field_name,
                'semantic': semantic.text if semantic is not None else None,
                'defined_values': defined_values.text if defined_values is not None else None
            })
    return field_info

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
    
    Answer in a clear, concise, and technical manner.
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
    
    Answer in a clear, concise, and technical manner.
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
    
    Answer in a clear, concise, and technical manner.
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
    
    Answer in a clear, concise, and technical manner.
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
        llm=llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION, 
        verbose=True
    )
    return agent

def read_logs(log_path):
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            # 如果文件内容为空，返回空列表
            if not content:
                return []
            
            # 尝试解析整个文件内容作为一个JSON对象
            try:
                result = json.loads(content)
                return [result]  # 返回包含单个JSON对象的列表
            except json.JSONDecodeError as e:
                print(f"failed to parse complete JSON: {e}")
             
                results = []
                current_json = ""
                for line in content.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    current_json += line
                    try:
                       
                        json_obj = json.loads(current_json)
                        results.append(json_obj)
                        current_json = ""  # 重置当前JSON
                    except json.JSONDecodeError:
                      
                        continue
                
                if results:
                    print(f"success to read {len(results)} JSON objects")
                    return results
                else:
                    print("failed to parse any JSON objects")
                    return []
    except Exception as e:
        print(f"failed to read file: {e}")
        return []






def main():
    # log_path = "/home/yangting/Documents/Semantic/result/log_file/Esp32/answer_result2.json"
    
    agent = create_agent(base_llm,k_value=20)
    result = {}

    for layer_name, packet_names in pkts.items():
        print(f"start to process {layer_name} layer")
        for packet_name in packet_names[1:]:
            prompt = get_prompt(layer = layer_name, packet_name = packet_name)
            response = agent.invoke(prompt)
            result = response['output'].replace("```json\n", "").replace("```", "")
            json_result = json.loads(result)
            InputTemplate = json_result.get('InputTemplate')
            OutputTemplate = json_result.get('OutputTemplate')
            # 创建一个新的字典，确保Input在最前面
            new_output_template = {'Input': InputTemplate}
            # 将其他键值对添加到新字典中
            for key, value in OutputTemplate.items():
                new_output_template[key] = value
            # 将OutputTemplate写入文件
            with open(answer_result_file_path, "a") as file:
                file.write(json.dumps(new_output_template, indent=2))
                file.write('\n')

    # 将result写入文件


if __name__ == "__main__":
    main()