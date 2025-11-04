 
import os
import sys
import json

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
from langchain_core.prompts import PromptTemplate





template = """You are a Bluetooth protocol testing expert, and your task is to generate field dependency mutations for semantic fuzz test that comply with specifications. Generate the {target} packet mutation test cases as client role based on the background information.


<Background Information>
{background}
</Background Information>
 <Target Packet> {target} </Target Packet> 
<Task Background> Generate two types of protocol packet mutations: 
Internal Packet Field Dependency Mutations: Modify interrelated field combinations within the same PDU 
</Task Background>
Please follow these steps:
<Generation Rules> 
 Identify logically dependent field combinations within the packet (e.g., authentication parameters and capability declarations)
 Each mutation must contain explicit dependency descriptions between fields
 Generate at least 10 mutations
 Mutated_Packet only contains the field name to be mutated and its value, with the value in hex format.
</Generation Rules>

```json
{{
  "Inner_Packet_Field_Dependent_Mutations": [
    {{
      "Mutation_Type": "Incompatible_IO_MITM",
      "Description": "Sets IO Capability to NoInputNoOutput (0x03) while AuthReq requests MITM. This combination is logically inconsistent because the device cannot handle Passkey or Numeric Comparison inputs despite requesting MITM protection.",
      "Packet_Name": "Pairing_Request",
      "Mutated_Packet": {{
        "Code": "0x01",
        "IOCapability": "0x03",
        "OOBDataFlag": "0x00",
        "AuthReq": "0x05",
        "MaxEncKeySize": "0x10",
        "InitiatorKeyDist": "0x07",
        "ResponderKeyDist": "0x07"
      }}
    }}
  ]
}}
   
</Output Example>
Please only output the JSON format answer, no other text or comments.
"""
# SemStateMutationPrompt = PromptTemplate(
#     input_variables=["target",],  # 定义模板中的变量
#     template=template,  # 模板内容
# )


# def get_prompt(target):
#     return SemStateMutationPrompt.format(target=target)
SemStateMutationPrompt = PromptTemplate(
    input_variables=["background","target"],  # 定义模板中的变量
    template=template,  # 模板内容
)


def get_prompt(background,target):
    return SemStateMutationPrompt.format(background=background,target=target)




