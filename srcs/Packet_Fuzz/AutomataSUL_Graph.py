from aalpy.automata import MealyMachine
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from aalpy.utils import load_automaton_from_file



class AutomataSUL_Graph:
    def __init__(self, path:str):

        self.exclude_list = ["UNKNOWN", "REJECT"]
        self.outputlist = set()
        self.automaton = load_automaton_from_file(path, 'mealy', compute_prefixes=True)
        self.graph = nx.DiGraph()
    def mealy_to_graph(self):
        for state in self.automaton.states:
            
            # if state.state_id == 's0':
            #     state.state_id = "start"


            # elif state.get_diff_state_transitions() == []:
            #     if state.state_id == 'start':
            #         pass
            #     else:
            #         state.state_id = "end"
            #         state.transitions = {}
            #         state.output_fun = {}

            self.graph.add_node(state.state_id)

        for state in self.automaton.states:
            # 去除不同状态中包含unknown和reject的输出

        
            for next_state_id,input in state.get_diff_state_transitions_dict().items():     
                for i in input:
                    if any(s in state.output_fun[i] for s in self.exclude_list):
                        continue
                    else:
                        self.outputlist.add(f'{i}/{state.output_fun[i].replace("BTLE|BTLE_CTRL|BTLE_DATA", "BTLE_RSP")}')
                if self.outputlist:
                    self.graph.add_edge(state.state_id, next_state_id, lable = ", ".join(self.outputlist))
                    self.outputlist.clear()
            # for next_state_id,input in state.get_diff_state_transitions_dict().items():
            #     for i in input:
            #         self.outputlist.add(f'{i}/{state.output_fun[i].replace("BTLE|BTLE_CTRL|BTLE_DATA", "BTLE_RSP")}')
            #     if self.outputlist:
            #         self.graph.add_edge(state.state_id, next_state_id, lable = ", ".join(self.outputlist))
            #         self.outputlist.clear()                    
            # 去除相同状态中包含unknown和reject和ind的输出
            if state.get_same_state_transitions() == []:
                continue
            else:
                for same_state in state.get_same_state_transitions():
                    if any(s in state.output_fun[same_state] for s in self.exclude_list):
                        continue
                    elif ('req' in same_state) and ("empty" in state.output_fun[same_state]):
                        continue
                    else:
                        self.outputlist.add(f'{same_state}/{state.output_fun[same_state].replace("BTLE|BTLE_CTRL|BTLE_DATA", "BTLE_RSP")}')
                if self.outputlist:
                    
                    self.graph.add_edge(state.state_id, state.state_id, lable = ", ".join(self.outputlist))
                self.outputlist.clear()
        return self.graph
#   find all paths
    def find_all_paths(self,graph,start="start",end="end"):
        all_paths = list(nx.all_simple_paths(graph, source=start, target=end))
        # longest_path = max(all_paths, key=len)
        return all_paths
#   visualize the graph
    def visualize_graph(self,graph,graph_path):
        plt.figure()
        nx.draw(graph, with_labels=True, node_size=1000, node_color='skyblue', font_size=10, font_color='black', edge_color='black', width=1, edge_cmap=plt.cm.Blues)
        nx.draw_networkx_edge_labels(graph, pos=nx.spring_layout(graph),font_size=5, edge_labels={(n1, n2): d['lable'] for n1, n2, d in graph.edges(data=True)})
        plt.savefig(graph_path)
    
#     def fuzz_graph_path(self,graph):
# #   find longest path
#         out_path = set()
#         diff_path = set()
#         all_paths = list(nx.all_simple_paths(graph, source="start", target="end"))
#         all_paths = sorted(all_paths, key=len, reverse=False)
#         longest_path = all_paths[-1]
#         difference = [item for item in graph.nodes if item not in longest_path]
#         diff_path = set(difference)
#         if not difference:
#             return longest_path
#         else:

#             for i in diff_path:
#                 for j in all_paths:
#                     if i in j:
#                         out_path.add(tuple(j))
#                         break
#         out_path.add(tuple(longest_path))
#         return out_path




