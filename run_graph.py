from typing import TypedDict, List
from langgraph.graph import StateGraph, END

class State(TypedDict):
    inputs: List[str]
    outputs: List[str]

def process_batch(state: State) -> State:
    results = []
    for item in state["inputs"]:
        results.append(item.upper())
    return {
        "inputs": state["inputs"],
        "outputs": results
    }

graph = StateGraph(State)
graph.add_node("process", process_batch)
graph.set_entry_point("process")
graph.add_edge("process", END)

app = graph.compile()

if __name__ == "__main__":
    result = app.invoke({
        "inputs": ["hello", "langgraph", "batch"]
    })
    print(result)
