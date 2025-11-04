 
import os
import sys
import json

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
from langchain_core.prompts import PromptTemplate



template = """
As a Bluetooth protocol testing expert, your task is to generate protocol state mutation as Client Role target packet {packet_name},The packet that are dependent on smp_pairing_failed_pkt are as follows:
<Interdependent packets>
{dependency_info}
</Interdependent packets>
<Client Role>{base_path} </Client Role>
Generate state mutations of {packet_name}, based on Interdependent packets:
1. Parsing Interdependent packets
2. Based on analyzing above, construct packet sequence that violates any of the following: 
  Type 1: Mutation Conditional Dependency: The value of one field depends on the specific value of another field. 
  Type 2: Mutation Order Dependency: The order in which fields appear or are valid depends on other field states.
3. Verification requirements - Each test case must be clear: 
  • Correspondence of the offending fields 
  • Complete packet transmission path 
  • Specific violation type description 
  • Technical basis description (cite the protocol chapter or specification clause) 
4. Output specification, generating a JSON object containing the following structure: 
  {{
    "field_pair": "Primary violation field → impact field", 
    "description": "Concise technical description", 
    "sequence ": [ {{" packet": "packet name", "fields": {{"key field": "set value"}}}},... Other packet], 
    "violation": "Specific violation type description (including error code)"
  }} 
  Example reference: 
  {{
    "field_pair": "iocap → reason", 
    "description": "Exception failure with valid IO capability", 
    "sequence ": [ {{" packet": "smp_pairing_request_pkt", "fields": {{"iocap": "Keyboard Display "}}}}, {{" packet": "smp_pairing_failed_pkt", "fields": {{"reason": "Authentication Requirements (0x03 )"}}}} ], 
    "violation": "IO capability meets but returns authentication requirements error (0x03)"
  }} 
  Please make sure : 1. Each test case contains one more main violation type 2. The packet sequence conforms to the basic process framework of the protocol 3.Do not repeat.
  Output only JSON object, no other text or comments.
"""

# def get_prompt(target):
#     return SemStateMutationPrompt.format(target=target)
SemStateMutationPrompt = PromptTemplate(
    input_variables=["packet_name","dependency_info","base_path"],  # 定义模板中的变量
    template=template,  # 模板内容
)


def get_prompt(packet_name,dependency_info,base_path):
    return SemStateMutationPrompt.format(packet_name=packet_name,dependency_info=dependency_info,base_path=base_path)


if __name__ == "__main__":
    packet_name= "ll_feature_rsp_pkt"
    dependency_info ="""
    Interdependent packet:ll_connection_param_rsp_pkt,  Interdependent field: feature_set -> preferred_periodicity:The 'preferred_periodicity' in ll connection param rsp is only valid if the 'Periodic Advertising' feature bit in 'feature_set' of ll feature rsp is enabled. The protocol mandates this feature support for periodicity usage.
    """
    base_path = "LL Feature Request → LL Length Request → LL Version Ind → Pairing Request → Pairing Confirm → Pairing Random → LL Encryption Request → LL Start Encryption Response → LL Pause Encryptin Request"
    print(get_prompt(packet_name,dependency_info,base_path))
