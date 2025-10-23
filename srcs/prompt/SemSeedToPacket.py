import os
import sys


sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
from langchain.prompts import PromptTemplate



from langchain.prompts import PromptTemplate

# Define the template for fuzz testing
template = """
As a Bluetooth protocol testing expert, your task is to generate protocol mutation test cases as client role based on state dependencies.  
Please follow the process below:  

<Protocol Specification> {Background} </Protocol Specification>  
<Target Data Packet> {Target} </Target Data Packet> 
<Client Role>LL Feature Request → LL Length Request → LL Version Ind → Pairing Request → Pairing Confirm → Pairing Random → LL Encryption Request → LL Start Encryption Response → LL Pause Encryptin Request </Client Role>

### Generation Rules:  

At least one of the following state dependencies must be violated:  

- Prestate Not Completed  
- Repeated Operations Not Following Protocol Specifications  

Each test case corresponds to a specific failure scenario:  

- Pairing process interruption  
- Encryption handshake failure  
- Service discovery conflict  
- Feature value read/write order error  
- Connection parameter update conflict  

### Generation Steps:  

1. List relevant state transition requirements from the protocol specification in the <Analysis> tag.  
2. Generate the packet transmission path.  
3. Confirm in the <Validation> tag whether each mutation directly violates protocol clauses.  

### Example Format:  

```xml
<Test Case>  
<Scenario Type> Pairing Process Interruption </Scenario Type>  

<Analysis>  
Protocol Section 4.2 states: The pairing process must be completed sequentially in the following order:  
Pairing Request → Pairing Confirm → DHKey Exchange.  

Protocol Section 5.1 states: An encrypted session must be established only after a successful pairing.  
</Analysis>  

<Mutation Steps>  
1. Send Pairing Request.  
2. Skip Pairing Confirm.  
3. Directly send Encryption Request.  
</Mutation Steps>  

<Validation>  
✔ Violates Prestate Not Completed (Pairing Confirm is missing).  
✔ Violates Encryption Handshake Process Specification.  
</Validation>  
</Test Case>  
```

Please generate a complete set of test cases following this format, covering all specified failure scenarios.
                   
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

# if __name__ == "__main__":
#     xml_path = "/home/yangting/Documents/Semantic/data/sem_seed/merged.xml"

