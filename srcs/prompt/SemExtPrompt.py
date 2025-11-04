

from langchain_core.prompts import PromptTemplate


#  """"You are a Bluetooth protocol expert tasked with analyzing the protocol specifications within a technical document.
# The specific task is to analyze a particular packet field defined in the document and determine the most likely seed for fuzz testing mutations of this field.Please carefully review the protocol document:
# Here are the specific steps for the analysis:
# Locate the packet named {packet_name} within the document.
# Conduct a detailed analysis of the {field} field within this packet.
# Initially explore the boundary values of this field as the starting seeds for fuzz testing mutations.
# Taking into account the semantics of the field and any possible constraints mentioned in the document, determine the most probable seed for fuzz testing mutations.
# In the <thinking> tag, provide a detailed analysis of your reasoning for determining the fuzz testing mutation seed. Then, in the <answer> tag, provide the final answer, following the example format, which includes the semantic description, defined values, and fuzz testing seed.
# <thinking>
# [Here, detail your analytical process for determining the fuzz testing mutation seed]
# </thinking>
# <answer>
# [semantic:'[Fill in the semantic description of the field]',defined_values:'[Fill in the defined values]',fuzz_seed:'[Fill in the fuzz testing seed]']
# </answer>
# """

template ="""
As a Bluetooth protocol expert, please perform the following protocol analysis task:

Analysis Objective: Determine the optimal fuzz testing mutation seed for the {field} field
Analysis Target: The {field} field in the {packet_name} packet

Execution Steps:

Locate Packet Structure

Accurately identify the definition of the {packet_name} packet in the protocol document.

Parse the binary structure of the {field} field.

Field Semantic Analysis

Extract the intended purpose and functional description of the field.

Value Range Derivation
a. Basic Value Range:

Determine the bit-length of the field.

Calculate the theoretical minimum (0) and maximum (2^n - 1) values.

b. Semantic Value Range:

Extract descriptions of reserved bits.

Output Requirements:

Present the analysis results in the <answer> tag using the following structure:
[field_bit_length:'Field bit length',semantic:'Field functional description', defined_values:'All defined valid value enumeration',]

Example:
<answer>
    <field_bit_length>8</field_bit_length>
    <semantic>Defines the input and output capabilities of a Bluetooth device, influencing the selection of pairing methods and security levels.</semantic>
    <defined_values>0x00 (DisplayOnly), 0x01 (DisplayYesNo), 0x02 (KeyboardOnly), 0x03 (NoInputNoOutput), 0x04 (KeyboardDisplay), 0x05-0xFF (Reserved for future use)</defined_values>
</answer>

Do not include any additional text or explanations outside of this XML format.
"""
SemExtPrompt = PromptTemplate(
    input_variables=["packet_name", "field"],  # 定义模板中的变量
    template=template,  # 模板内容
)

# prompt = SemExtPrompt.format(packet_name="pairing request", field="io_cap")
# print(prompt)
def get_prompt(packet_name, field):
    return SemExtPrompt.format(packet_name=packet_name, field=field)

if __name__ == "__main__":
    print(get_prompt(packet_name="Provisioning Invite", field="Attention Duration"))
