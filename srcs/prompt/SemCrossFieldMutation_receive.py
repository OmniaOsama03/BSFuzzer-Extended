 
import os
import sys
import json

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
from langchain.prompts import PromptTemplate





# template = """You are a Bluetooth protocol testing expert, and your task is to generate field dependency mutations for semantic fuzz test that comply with specifications. Generate the {target} packet mutation test cases as client role based on the background information.

# <Background Information>
# {background}
# </Background Information>
#  <Target Packet> {target} </Target Packet> 
# <Task Background> Generate two types of protocol packet mutations: 
# Cross_Packet_Field_Dependent_Mutations: Create field dependency exceptions across multiple PDUs 
# </Task Background>
# Please follow these steps:
# <Generation Rules> 
# 1. Internal Mutation Requirements: 
#  Identify logically dependent field combinations within the packet (e.g., authentication parameters and capability declarations)
#  Each mutation must contain explicit dependency descriptions between fields
# 2. Sequence Mutation Requirements:
# Analyze field dependencies across packet flows
# Include field association descriptions between preceding and subsequent packets
# All mutations must be based on legal field value ranges defined in protocol specifications
# Each mutation should have clear testing purpose descriptions
# </Generation Rules>
# IMPORTANT: Your final answer MUST be in JSON format with this structure:
# ```json
# {{
#   "Cross_Packet_Field_Dependent_Mutations": [
#     {{
#       "Mutation_Type": "SC_Bit_Set_No_PublicKey",
#       "Description": "Secure Connections bit is set in the AuthReq of the Pairing Request, but the next packet in the sequence (Pairing Public Key) is absent or invalid, causing a discrepancy in Secure Connections pairing flow.",
#       "Packet_Sequence": [
#         {{
#           "Send_Packet1": ,
#           "Modified_Fields": {{
#             "IOCapability": "0x04",
#             "OOBDataFlag": "0x00",
#             "AuthReq": "0x0D",
#             "MaxEncKeySize": "0x10",
#             "InitiatorKeyDist": "0x07",
#             "ResponderKeyDist": "0x07"
#           }}
#         }},
#         {{
#           "Send_Packet2": "Pairing_Public_Key",
#           "Modified_Fields": {{
#             "PublicKeyX": "ABSENT",
#             "PublicKeyY": "ABSENT"
#           }}
#         }}
#       ]
#     }}
#   ]
# }}
   
# </Output Example>
# Please only output the JSON format answer, no other text or comments.
# """
# SemStateMutationPrompt = PromptTemplate(
#     input_variables=["target",],  # 定义模板中的变量
#     template=template,  # 模板内容
# )


template = """
As a Bluetooth protocol testing expert, you need to generate cross-package field dependency fuzz test cases as client role that comply with the specification. 
Please follow the following process strictly: 
1. Parse background information:
< background information> 
packet_name_1: {packet_name_1}
packet_name_2: {packet_name_2}
field_dependency_info: {dependency_info} 
receive_packet_information: {receive_packet_information}
</background information> 
2. Specify the transmission order and direction of the two packets.
3. Generating mutation rules: 
• Generates only semantically divergent mutations in the field, no mutations in the structure of the data packet
• Modify only the specified fields
• The type of mutation should reflect the logical contradictions in the security mechanism (such as setting the security flag but missing the necessary elements) 
• 10 test cases per pair of dependency fields
4. When constructing test cases: 
• "Mutation_Type" naming should reflect the security mechanism flaws
• "Description" should clearly state the violation scenario and expected exceptions 
• Packet_Sequence should specify the transmission order and direction of the two packets
• Modified_Fields should be accurate to the bit level modification 
5. Output requirements: 
• Strictly follow the provided JSON format template 
• Field modifications with 2 consecutive data packets per mutation use case 
• Field values use hexadecimal  
• Exclude non-directly dependent fields
6. Validation checks: 
✓ Each mutation corresponds to a valid dependency in "explanation" 
✓ Does not violate the Bluetooth Core Specification requirements 
✓ Client side role behavior conforms to the behavior pattern of the initializing device, output the final result in the < mutations > tag, ensuring JSON syntax is correct. Start analyzing background information immediately. 
<output format requirements>
```json
{{"Mutation_Strategy": 
  {{
    "Mutation_Type": "< variant type >", 
    "Description": "< attack logic description >",
    "Packet_Sequence ": [ 
      {{
        "Packet_Name1": "< data packet type >", 
        "Direction": "< Central ↔ Peripheral >", 
        "Modified_Fields ": {{ "< field name >": "< tampered value >", "< field name >" : "< tampered values >" }}, 
      }},
      ...
    ], 
    "Expected_Impact": ["DoS", "Auth_Bypass", "Data_Exfiltration",...]
      }}
  }}
</output format requirements>
"""

# def get_prompt(target):
#     return SemStateMutationPrompt.format(target=target)
SemStateMutationPrompt = PromptTemplate(
    input_variables=["packet_name_1","packet_name_2","dependency_info"],  # 定义模板中的变量
    template=template,  # 模板内容
)


def get_prompt(packet_name_1,packet_name_2,dependency_info):
    return SemStateMutationPrompt.format(packet_name_1=packet_name_1,packet_name_2=packet_name_2,dependency_info=dependency_info)


if __name__ == "__main__":
    packet_name_1 = "ll_feature_rsp_pkt"
    packet_name_2 = "ll_length_req_pkt"
    dependency_info ="""
                 "feature_set vs max_rx_bytes": "If the feature_set in ll_feature_rsp indicates support for Data Length Extension (DLE), the max_rx_bytes in ll_length_req can be set to values larger than the default 27 bytes (up to 251 bytes).",
                "feature_set vs max_rx_time": "The max_rx_time in ll_length_req depends on the DLE support in feature_set, as the transmission time calculation directly uses the supported max_rx_bytes (which is enabled by DLE).",
                "feature_set vs max_tx_bytes": "The max_tx_bytes in ll_length_req is directly constrained by the DLE support in feature_set, similar to max_rx_bytes.",
                "feature_set vs max_tx_time": "The max_tx_time in ll_length_req is derived from the max_tx_bytes value, which is enabled by DLE support in feature_set." """
    print(get_prompt(packet_name_1,packet_name_2,dependency_info))

