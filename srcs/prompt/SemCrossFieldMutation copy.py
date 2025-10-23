 
import os
import sys
import json

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
from langchain.prompts import PromptTemplate





template = """You are a Bluetooth protocol testing expert, and your task is to generate field dependency mutations for semantic fuzz test that comply with specifications. Generate the {target} packet mutation test cases as client role based on the background information.

<Background Information>
{background}
</Background Information>
 <Target Packet> {target} </Target Packet> 
<Task Background> Generate two types of protocol packet mutations: 
Cross_Packet_Field_Dependent_Mutations: Create field dependency exceptions across multiple PDUs 
</Task Background>
Please follow these steps:
<Generation Rules> 
1. Internal Mutation Requirements: 
 Identify logically dependent field combinations within the packet (e.g., authentication parameters and capability declarations)
 Each mutation must contain explicit dependency descriptions between fields
2. Sequence Mutation Requirements:
Analyze field dependencies across packet flows
Include field association descriptions between preceding and subsequent packets
All mutations must be based on legal field value ranges defined in protocol specifications
Each mutation should have clear testing purpose descriptions
</Generation Rules>
IMPORTANT: Your final answer MUST be in JSON format with this structure:
```json
{{
  "Cross_Packet_Field_Dependent_Mutations": [
    {{
      "packet_name_1": "Pairing_Request",
      "packet_name_2": "Pairing_Public_Key",
      "Mutation_Type": "SC_Bit_Set_No_PublicKey",
      "Description": "Secure Connections bit is set in the AuthReq of the Pairing Request, but the next packet in the sequence (Pairing Public Key) is absent or invalid, causing a discrepancy in Secure Connections pairing flow.",
      "Packet_Sequence": [
        {{
          "Send_Packet1": "Pairing_Request",
          "Modified_Fields": {{
            "IOCapability": "0x04",
            "OOBDataFlag": "0x00",
            "AuthReq": "0x0D",
            "MaxEncKeySize": "0x10",
            "InitiatorKeyDist": "0x07",
            "ResponderKeyDist": "0x07"
          }}
        }},
        {{
          "Send_Packet2": "Pairing_Public_Key",
          "Modified_Fields": {{
            "PublicKeyX": "ABSENT",
            "PublicKeyY": "ABSENT"
          }}
        }}
      ]
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




