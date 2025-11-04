
from langchain_core.prompts import PromptTemplate

StateConstructionPrompt = PromptTemplate(
            input_variables=["FILENAME","MARKDOWN_TEXT"],
            template="""
            Please convert the following Mermaid sequence diagram into a Finite State Machine (FSM) represented in DOT format.

            Conversion Rules:
            1. Messages sent from Client → Peripheral are treated as Inputs.
            2. Messages sent from Peripheral → Client are treated as Outputs.
            3. Consecutive response messages from the Peripheral should be merged into a single Output, separated by commas.
            4. If a Client message has no response, set the Output to "empty".
            5. If the sequence starts with a Peripheral → Client message, the first Input should be "empty".
            6. Response messages cannot be treated as Inputs.
            7. Each state transition must follow this format:
            current_state -> next_state [label="Input/Output"];

            Sequence Diagram:
            {MARKDOWN_TEXT}

            Output Format (DOT Template):
            digraph {FILENAME} {{
                s0 [label="s0"];
                s1 [label="s1"];
                s2 [label="s2"];
                
                s0 -> s1 [label="Input/Output"];
                // ... more states
                __start0 [label="", shape=none];
                __start0 -> initial_state [label=""];
            }}

    """
        )

def get_field_prompt(FILENAME, MARKDOWN_TEXT):
    return StateConstructionPrompt.format(FILENAME=FILENAME, MARKDOWN_TEXT=MARKDOWN_TEXT)

if __name__ == "__main__":
    print(get_field_prompt(FILENAME="Initiating_Connection", MARKDOWN_TEXT="aa"))


