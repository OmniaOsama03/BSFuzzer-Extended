import os
import sys


sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
from langchain.prompts import PromptTemplate



from langchain.prompts import PromptTemplate

# Define the template for fuzz testing
template = """
As a Bluetooth protocol testing expert, your task is to generate protocol mutation test cases as client role based on state dependencies,target packet is {Target}.  
Please follow the process below:  

<Target Data Packet> {Target} </Target Data Packet> 
<Client Role>LL Feature Request → LL Length Request → LL Version Ind → Pairing Request → Pairing Confirm → Pairing Random → LL Encryption Request → LL Start Encryption Response → LL Pause Encryptin Request </Client Role>

### Generation Rules:  
- Analyze the semantics of each field in {Target}, and analyze the potential state security issues based on its generation process. 
- Comprehensive coverage of {Target}-related protocol violations to ensure comprehensive testing
- Based on the state transition requirements, generate the packet transmission path, at least one of the following state dependencies must be violated:  
- Must include: {Target} packet
- Prestate Not Completed  
- Repeated Operations Not Following Protocol Specifications 
- Unexpected State Change 
- Combinations containing the above variants
- Each test case corresponds to a specific failure scenario

### Generation Steps:  

1. List violations of specific parts and descriptions related to {Target} in < Analysis > tags.
2. Generate the packet transmission path. 
3. Only focus on the {Target} related state transition mutation.
3. Confirm in the <Validation> tag whether each mutation directly violates protocol clauses. 
4. Describe the specific mutation steps in < Mutation Steps >, using only: - Send [data packet name] - Skip [data packet name].
5. Generate 30 test cases, no repeat.

### Example Format:  

```xml
<Packet name="{Target}">
<TestCase ScenarioType="Pairing Process Interruption"> 
<Analysis>  
Based on Protocol Specification
</Analysis>  

<MutationSteps>  
1. Send Pairing Request.  
2. Skip Pairing Confirm.  
3. Directly send Encryption Request.  
</MutationSteps>  

<Validation>  
✔ Must include: {Target} packet
✔ Violates Prestate Not Completed  
✔ Violates Encryption Handshake Process Specification.  
✔ Add Unexpected State Change   

</Validation>  
</TestCase>  
</Packet>
```

Please generate a complete set of test cases following this format, covering all specified failure scenarios, only output the xml format, no other text.                 
"""
SemExtPrompt = PromptTemplate(
    input_variables=["Background","Target"],  # 定义模板中的变量
    template=template,  # 模板内容
)

# prompt = SemExtPrompt.format(packet_name="pairing request", field="io_cap")
# print(prompt)
def get_prompt(background_info: str,target: str) -> str:
    """Returns a formatted prompt string with the given background information."""
    return SemExtPrompt.format(Background=background_info,Target=target)

if __name__ == "__main__":
    print(get_prompt("Pairing Failed"))

