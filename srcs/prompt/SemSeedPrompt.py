import os
import sys


sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
from langchain_core.prompts import PromptTemplate


# Define the template for fuzz testing
template = """
You are a Bluetooth protocol testing expert specializing in fuzz testing for Bluetooth server, given the following packet and field information, generate mutations targeting this field.

<Background Information>
{Background}
</Background Information>


<Field Mutation>
Field Mutation: boundary conditions, semantic invalid cases, bit-flip tests, random values 
</Field Mutation>



<Output Example>

    {{  
        "MutationType": "Field Mutation",
        "TestCases": [
            {{ "iocap": "0x00",  "TestType": "Boundary Test - Minimum Defined Value (DisplayOnly)" }},
            {{ "iocap": "0x04",  "TestType": "Boundary Test - Maximum Defined Value (KeyboardDisplay)" }},
            {{ "iocap": "0x05",  "TestType": "Semantic Invalid - First Reserved Value" }},
            {{ "iocap": "0xFF",  "TestType": "Semantic Invalid - Maximum Reserved Value" }},
            {{ "iocap": "0x06",  "TestType": "Semantic Invalid - Arbitrary Reserved Value" }},
            {{ "iocap": "0x80",  "TestType": "Bit Flip - High Bit Set" }},
            {{ "iocap": "0x7F",  "TestType": "Bit Flip - All Bits Except High Bit" }},
            {{ "iocap": "0xFE",  "TestType": "Bit Flip - High Bits Set (Near Maximum Reserved)" }},
            {{ "iocap": "0x03",  "TestType": "Boundary Test - NoInputNoOutput" }},
            {{ "iocap": "0x02",  "TestType": "Boundary Test - KeyboardOnly" }},
            {{ "iocap": "0x01",  "TestType": "Boundary Test - DisplayYesNo" }},
            {{ "iocap": "0xFA",  "TestType": "Random Value - Reserved Range" }},
            {{ "iocap": "0x10",  "TestType": "Random Value - Non-Standard Bit Pattern" }}
        ]
    }}
</Output Example>
Only output the json format, no other text.
"""
SemExtPrompt = PromptTemplate(
    input_variables=["Background"],  # 定义模板中的变量
    template=template,  # 模板内容
)
# prompt = SemExtPrompt.format(packet_name="pairing request", field="io_cap")
# print(prompt)
def get_prompt(background_info: str) -> str:
    """Returns a formatted prompt string with the given background information."""
    return SemExtPrompt.format(Background=background_info)

# if __name__ == "__main__":
#     xml_path = "/home/yangting/Documents/Semantic/data/sem_seed/merged.xml"

