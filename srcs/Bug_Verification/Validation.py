import os
import sys
import json
import re

from time import sleep


sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")

from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS
from langchain.chains import RetrievalQA
from langchain.agents import initialize_agent, Tool, AgentType
from langchain.prompts import PromptTemplate

from BSFuzz.srcs.llm_model.ModConf import ModelConfig
# from BSFuzz.srcs.prompt.SemFieldRspPrompt import get_field_prompt
# from BSFuzz.srcs.prompt.SemStateRspPrompt import get_state_prompt
from BSFuzz.srcs.prompt.SemFieldRspValidation import get_field_prompt
from BSFuzz.srcs.prompt.SemStateRspValidation import get_state_prompt






with open("/home/yangting/Documents/BSFuzz/config/semresult_config.json", "r") as file:
    config = json.load(file)
    field_model_config = ModelConfig(config.get("llm", {}).get("field_model_provider"))
    state_model_config = ModelConfig(config.get("llm", {}).get("state_model_provider"))
    base_model_config = ModelConfig(config.get("llm", {}).get("base_model_provider"))


    field_model = config.get("llm", {}).get("model")
    state_model = config.get("llm", {}).get("state_model")
    base_model = config.get("llm", {}).get("base_model")
 
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
    field_validation_rule_file_path = config.get("semresult", {}).get("field_validation_rule_file_path")
    state_validation_rule_file_path = config.get("semresult", {}).get("state_validation_rule_file_path")
    answer_result_file_path = config.get("semresult", {}).get("answer_result_file_path")


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
        logs = []
        
        with open(log_path, 'r') as f:
 
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    logs.append(log_entry)
                except json.JSONDecodeError as e:
                    print(f"error to parse JSON line: {e}")
                    continue
        
        print(f"success to read {len(logs)} log records")
        return logs

def write_result(result):
    with open(answer_result_file_path, "a") as file:
        file.write(result)
        file.write('\n')

def read_field_validation_rule(field_validation_rule_file_path, layer_name, field_name):
    """
    读取field validation rule文件，根据layer_name 和 field_name过滤
    返回匹配的ProtocolComplianceCheck和ExpectedDeviceBehavior
    """
    with open(field_validation_rule_file_path, "r") as file:
        content = file.read()
    
    # 解析多个JSON对象（每个对象可能跨多行）
    # 使用括号计数来正确分割JSON对象
    objects = []
    buffer = ''
    depth = 0
    
    for char in content:
        if char == '{':
            if depth == 0:
                buffer = ''  # 开始新对象
            depth += 1
            buffer += char
        elif char == '}':
            buffer += char
            depth -= 1
            if depth == 0:
                # 找到一个完整的对象
                try:
                    obj = json.loads(buffer.strip())
                    objects.append(obj)
                except json.JSONDecodeError:
                    pass
                buffer = ''
        elif depth > 0:
            buffer += char
    
    # 查找匹配的条目
    for entry in objects:
        if entry.get("info_str", {}).get("layer_name") == layer_name and entry.get("info_str", {}).get("field_name") == field_name:
            protocol_compliance = entry.get("ProtocolComplianceCheck", {})
            expected_device_behavior = entry.get("ExpectedDeviceBehavior", {})
            # 转换为 JSON 字符串格式
            protocol_compliance_str = json.dumps(protocol_compliance) if protocol_compliance else "null"
            expected_device_behavior_str = json.dumps(expected_device_behavior) if expected_device_behavior else "null"
            return protocol_compliance_str, expected_device_behavior_str
    return "null", "null"

def read_state_validation_rule(state_validation_rule_file_path, packet_name):
    """
    读取state validation rule文件，根据packet_name过滤
    返回匹配的PreviousStateAnalysis,ExpectedBehavior和StateInvalidResponse
    """
    with open(state_validation_rule_file_path, "r") as file:
        content = file.read()

    # 解析文件中连续拼接的多个 JSON 对象
    objects = []
    buffer = ''
    depth = 0

    for char in content:
        if char == '{':
            if depth == 0:
                buffer = ''
            depth += 1
            buffer += char
        elif char == '}':
            buffer += char
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(buffer.strip())
                    objects.append(obj)
                except json.JSONDecodeError:
                    pass
                buffer = ''
        elif depth > 0:
            buffer += char

    # 根据 Input.PacketContext.PacketType 匹配 packet_name
    for entry in objects:
        pkt_type = (
            entry.get("Input", {})
                 .get("PacketContext", {})
                 .get("PacketType")
        )
        if pkt_type == packet_name:
            previous_state = entry.get("PreviousStateAnalysis", {})
            expected_behavior = entry.get("ExpectedBehavior", {})
            state_invalid_response = expected_behavior.get("StateInvalidResponse", {})
            # 转换为 JSON 字符串格式
            previous_state_str = json.dumps(previous_state) if previous_state else "null"
            expected_behavior_str = json.dumps(expected_behavior) if expected_behavior else "null"
            state_invalid_response_str = json.dumps(state_invalid_response) if state_invalid_response else "null"
            return previous_state_str, expected_behavior_str, state_invalid_response_str

    return "null", "null", "null"

# def main():
#     "输出变成string格式"
#     field_validation_rule = read_field_validation_rule("/home/yangting/Documents/BSFuzz/result/log_file/Test/answer_result_field.json", "BTLE_ADV", "RxAdd")
#     # state_validation_rule = read_state_validation_rule()
#     print(type(field_validation_rule[0]))
#     print(field_validation_rule[0])
#     print(field_validation_rule[1])

#     prev_state, expected_behavior, state_invalid = read_state_validation_rule(
#         "/home/yangting/Documents/BSFuzz/result/log_file/Test/answer_result_state.json",
#         "ll_channel_map_req_pkt",
#     )
#     print(type(prev_state))
#     print(prev_state)
#     print(expected_behavior)
#     print(state_invalid)



# Step 6: Main function to run the agent
def main():
    seed_result_list = read_logs(seed_result_file_path)

    log = 0
    index = 0
    while index < len(seed_result_list):
        seed_result = seed_result_list[index]
        # print(field_validation_rule_file_path)
        # print(state_validation_rule_file_path)
        # print(seed_result['mutation'].split(',')[1])
        # print(seed_result['mutation'].split(',')[2])
        # print(seed_result['mutation'].split(',')[0])
        

        # print(field_validation_rule)
        # print(expected_device_behavior)
        # print(previous_state)
        # print(expected_behavior)
        # print(state_invalid_response)
        # seed_result = seed_result_list[index]
        # [INSEQ=seed_result['base_path'], OUTSEQ=seed_result['outputs'], MUTINF=seed_result['mutation'], RSP=seed_result['fuzz_result']]
        if index < log:
            index += 1
            continue
        try:
            if seed_result['fuzz_result'] is not None:
                #seed mutation
                field_validation_rule, expected_device_behavior = read_field_validation_rule(field_validation_rule_file_path, layer_name=seed_result['mutation'].split(',')[1], field_name=seed_result['mutation'].split(',')[2])
                # print(field_validation_rule)
                # print(expected_device_behavior)
                # agent = create_agent(field_llm,k_value=20)
                # query = get_field_prompt(MUTINF=seed_result['mutation'], ACTUAL_RESPONSE=seed_result['fuzz_result'], SPECIFICATION_SECTION=field_validation_rule, EXPECTED_DEVICE_BEHAVIOR=expected_device_behavior)
                # # print(query)
                # response = agent.invoke(query)
                # final_result = response['output'].replace("```json\n", "").replace("```", "")
                # final_result = json.dumps({"log_id":index, "analysis":final_result})
                # write_result(final_result)
                index += 1
                print(f"finish the {index}th seed")     

            else:
                #state mutation
                previous_state, expected_behavior, state_invalid_response = read_state_validation_rule(state_validation_rule_file_path, packet_name=seed_result['mutation'])
                # print(previous_state)
                # print(expected_behavior)
                # print(state_invalid_response)
                agent = create_agent(state_llm,k_value=20)
                query = get_state_prompt(INSEQ=seed_result['base_path'], OUTSEQ=seed_result['outputs'], PACKET_NAME=seed_result['mutation'], Precondition=previous_state, Valid_Response=expected_behavior, Invalid_Response=state_invalid_response)
                # print(query)

                response = agent.invoke(query)
                final_result = response['output'].replace("```json\n", "").replace("```", "")
                final_result = json.dumps({"log_id":index, "analysis":final_result})
                write_result(final_result)
                index += 1
                print(f"finish the {index}th seed")
        except ValueError as e:
            try:
                # 使用正则表达式找到 JSON 部分
                # 查找 ```json 和 ``` 之间的内容
                error_message = str(e)
                json_match = re.search(r'```json\n(.*?)\n```', error_message, re.DOTALL)
                #replace("```json\n", "").replace("```", "")
                if json_match:
                    final_result = json_match.group(1).replace("```json\n", "").replace("```", "")
                    final_result = json.dumps({"log_id":index, "analysis":final_result})
                    write_result(final_result)             
                    index += 1
                    print(f"finish the {index}th seed")
            except Exception as e:
                #写一个空json
                final_result = json.dumps({"log_id":index, "error":str(e)})
                write_result(final_result)
                print(f"error in the {index}th seed")            
                
        except Exception as e:

            # sleep(10)
            final_result = json.dumps({"log_id":index, "error":str(e)})
            write_result(final_result)
            print(f"error in the {index}th seed")
        


if __name__ == "__main__":
    main()