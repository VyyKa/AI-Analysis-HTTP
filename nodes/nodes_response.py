from soc_state import SOCState
from builders.response_builder import response_builder

def response_node(state: SOCState):
    return response_builder(state)
