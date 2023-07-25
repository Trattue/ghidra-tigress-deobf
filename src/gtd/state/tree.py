from gtd.state.state import State


class StateTree:
    """
    A graph, more specifically a tree, of states connected by jumps.

    Attributes:
    -----------
    states : dict[int, State]
        All states in the state tree, indexed by their id.
    """

    initial_state_id = 0

    def __init__(self) -> None:
        self.states: dict[int, State] = {}

    def __str__(self) -> str:
        formatted = ["local vpc:8 = inst_start;", "local vsp:8 = VSP;"]
        formatted.extend(map(lambda state: f"{state}", list(self.__iter__())))
        # TODO: end might not be used...
        formatted.append("<end>")
        return "\n".join(formatted)

    def __iter__(self):
        # Simple BFS iteration.
        queue = [self.initial_state_id]
        while len(queue) > 0:
            current = self.states[queue.pop(0)]
            yield current
            queue.extend(map(lambda jump: jump.target_id, current.jumps.values()))
