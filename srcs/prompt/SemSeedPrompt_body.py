import os
import sys
import json

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
from langchain_core.prompts import PromptTemplate



from langchain.prompts import PromptTemplate

# Define the template for fuzz testing
template = """
You are a Bluetooth protocol testing expert specializing in fuzz testing for Bluetooth server, given the following packet and field information, generate mutations targeting this field.

<Background Information>
{Background}
</Background Information>


 <Field Mutation>
Field Mutation: boundary conditions, semantic invalid cases, bit-flip tests, random values, 
Structural Mutation: Field length Addition, Field length Reduction, 
</Field Mutation>



<Output Example>
[
    {
        "MutationType": "Field Mutation",
        "TestCases": [
            { "iocap": "0x00", "BitLength": "8", "TestType": "Boundary Test - Minimum Defined Value (DisplayOnly)" },
            { "iocap": "0x04", "BitLength": "8", "TestType": "Boundary Test - Maximum Defined Value (KeyboardDisplay)" },
            { "iocap": "0x05", "BitLength": "8", "TestType": "Semantic Invalid - First Reserved Value" },
            { "iocap": "0xFF", "BitLength": "8", "TestType": "Semantic Invalid - Maximum Reserved Value" },
            { "iocap": "0x06", "BitLength": "8", "TestType": "Semantic Invalid - Arbitrary Reserved Value" },
            { "iocap": "0x80", "BitLength": "8", "TestType": "Bit Flip - High Bit Set" },
            { "iocap": "0x7F", "BitLength": "8", "TestType": "Bit Flip - All Bits Except High Bit" },
            { "iocap": "0xFE", "BitLength": "8", "TestType": "Bit Flip - High Bits Set (Near Maximum Reserved)" },
            { "iocap": "0x03", "BitLength": "8", "TestType": "Boundary Test - NoInputNoOutput" },
            { "iocap": "0x02", "BitLength": "8", "TestType": "Boundary Test - KeyboardOnly" },
            { "iocap": "0x01", "BitLength": "8", "TestType": "Boundary Test - DisplayYesNo" },
            { "iocap": "0xFA", "BitLength": "8", "TestType": "Random Value - Reserved Range" },
            { "iocap": "0x10", "BitLength": "8", "TestType": "Random Value - Non-Standard Bit Pattern" }
        ]
    },
    {
        "MutationType": "Structural Mutation",
        "TestCases": [
            { "iocap": "0x000", "BitLength": "12", "TestType": "Field Length Addition" },
            { "iocap": "", "BitLength": "0", "TestType": "Field Length Reduction - Field Removed" },
            { "iocap": "0x0000", "BitLength": "16", "TestType": "Field Length Addition - Extended Length" }
        ]
    }
]
</Output Example>
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

