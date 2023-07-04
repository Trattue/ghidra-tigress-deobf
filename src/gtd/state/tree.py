from gtd.state.state import State


class StateTree:
    states: dict[int, State]

    def __init__(self) -> None:
        self.states = {}

    def __str__(self) -> str:
        result = ""
        queue = [0]
        while len(queue) > 0:
            current = self.states[queue.pop(0)]
            if current.id != 0:
                result += "\n"
            result += f"{current}"
            queue.extend(map(lambda jump: jump.target_id, current.jumps))
        result += "\n<end>:"
        return result
