from soc_state import SOCState
from response_builder import response_builder

def response_node(state: SOCState):
    return response_builder(state)
