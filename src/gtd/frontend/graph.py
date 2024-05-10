import angr
import claripy
import gtd.frontend.sim_actions
from gtd.config.handler import Handler
from gtd.config.locations import Locations
from gtd.frontend.state import State
from gtd.frontend.statement import (
    CallStatement,
    ReadStatement,
    WriteStatement,
)


class StateGraph:
    """
    A graph of states connected by jumps.

    Parameters:
    -----------
    handler : Handler
        The handler this graph represents.
    locations : Locations
        Important addresses, for example VPC.
    vpc : claripy.ast.BV
        The symbolic variable for VPC.

    Attributes:
    -----------
    nodes : dict[int, State]
        All states in the state graph, indexed by their id.
    """

    END_GOTO_VPC_ID = -2
    END_REGULAR_ID = -1
    START_ID = 0

    def __init__(self, handler: Handler, locations: Locations, vpc: claripy.ast.BV):
        self.end_goto_vpc = State(self.END_GOTO_VPC_ID)
        self.end_regular = State(self.END_REGULAR_ID)
        self.nodes: dict[int, State] = {
            self.END_GOTO_VPC_ID: self.end_goto_vpc,
            self.END_REGULAR_ID: self.end_regular,
        }
        self.handler = handler
        self.locations = locations
        self.vpc = vpc

    def __iter__(self):
        # A simple BFS implementation won't be enough for iteration, we need to keep
        # track of dependencies. That's start BFS from the two end nodes (if those
        # are used) and iterate through the predecessors. Once we reverse this order,
        # we'll have an ordering that ensures that nodes are only returned after all of
        # their dependencies. Additionally, by first doing BFS on the regular and and
        # then on the goto end, it will exnsure it the final iteration order the goto
        # end is always first.

        # BFS after regular end
        reverse_queue = []
        if len(self.nodes[self.END_REGULAR_ID].predecessors) > 0:
            reverse_queue.append(self.END_REGULAR_ID)
        idx = 0
        while idx < len(reverse_queue):
            current = self.nodes[reverse_queue[idx]]
            reverse_queue.extend(current.predecessors)
            idx += 1

        # BFS after goto end
        if len(self.nodes[self.END_GOTO_VPC_ID].predecessors) > 0:
            reverse_queue.append(self.END_GOTO_VPC_ID)
        while idx < len(reverse_queue):
            current = self.nodes[reverse_queue[idx]]
            reverse_queue.extend(current.predecessors)
            idx += 1

        # Apparently this is how you do ordered sets? This will make sure (after
        # reversing) to keep only the first occurence of state ids in the iteration
        # order.
        queue = list(dict.fromkeys(reversed(reverse_queue)))
        for node in queue:
            yield self.nodes[node]

    def add_solution(self, solution: angr.sim_state.SimState):
        """Adds a solution to the graph."""
        current = State(self.START_ID)
        current_jump = None
        saved_jump = None
        saved_id = self.START_ID
        # (previous state, target address) -> guard
        jump_table: dict[tuple[int, int], claripy.ast.bool.Bool] = {}

        for action in solution.history.actions.hardcopy:
            match type(action):
                case angr.state_plugins.SimActionData:
                    # Nothing really special here, we simply add the read/write
                    # statements to the current state.
                    if action.action == "write":
                        target = action.addr.to_claripy()
                        data = action.data.to_claripy()
                        current.statements.append(WriteStatement(target, data))
                    elif action.action == "read":
                        data = action.data.to_claripy()
                        origin = action.addr.to_claripy()
                        current.statements.append(ReadStatement(data, origin))
                case gtd.frontend.sim_actions.SimActionCall:
                    # Similar to reads and writes, simply append it to current state's
                    # statements.
                    # We do have to keep the architecture's calling convention in mind,
                    # though. In x86_64, the return address is pushed to the stack...
                    # Since we don't actually follow calls, this push serves no use and
                    # we need to remove it. That push most likely is the last statement
                    # before the call, so let's simply remove that.
                    current.statements.pop(-1)
                    current.statements.append(
                        CallStatement(action.target, action.arguments)
                    )
                case gtd.frontend.sim_actions.SimActionJump:
                    # When we encounter a jump, we have two things to consider:
                    # 1) We can safely ignore unconditional jumps within the same state
                    #    since execution will continue at the jump target.
                    # 2) Conditional jumps lead to a state fork, we do, however, not yet
                    #    know the target state's id. The next state in the solution's
                    #    history will be the state we jump to.
                    # Therefore, we will store the jump condition in a variable. This
                    # allows us to overwrite unconditional jumps and to wait until we
                    # know the target id.
                    current_jump = action.guard
                case gtd.frontend.sim_actions.SimActionFork:
                    # At this point, we get to know the right id of the current state,
                    # so let's correct it and create a state object for the next state.
                    id = action.id
                    current.id = id
                    new_current = State(self.START_ID)
                    new_current.predecessors.add(id)

                    # We need to add any jumps to this state we saved earlier and save
                    # the jump to the next state. We don't have issues with duplicate
                    # jumps to the same state since jumps are stored in a dictionary.
                    if saved_jump != None:
                        self.nodes[saved_id].jumps[id] = saved_jump
                    saved_jump = current_jump
                    current_jump = None

                    # Since solutions share states in the beginning, we need to check if
                    # for duplicates in the graph. If a state with the same id exists,
                    # it is the same as the current state.
                    if self.nodes.get(id) != None:
                        self.nodes[id].predecessors.union(current.predecessors)
                        current = new_current
                        saved_id = id
                        continue
                    saved_id = id
                    self.nodes[id] = current
                    current = new_current
                case gtd.frontend.sim_actions.SimActionJumpTable:
                    # Similar behavior to forks, but we need to save our jump table.
                    # Set current ID:
                    id = action.id
                    current.id = id
                    new_current = State(self.START_ID)
                    new_current.predecessors.add(id)

                    # Jumps to this state:
                    if saved_jump != None:
                        self.nodes[saved_id].jumps[id] = saved_jump
                    saved_jump = current_jump
                    current_jump = None

                    # Fill jump table
                    for target, guard in action.jumps.items():
                        jump_table[(id, target)] = guard

                    # Check for duplicates
                    if self.nodes.get(id) != None:
                        self.nodes[id].predecessors.union(current.predecessors)
                        current = new_current
                        saved_id = id
                        continue

                    saved_id = id
                    self.nodes[id] = current
                    current = new_current
                case gtd.frontend.sim_actions.SimActionJumpTableTarget:
                    if saved_jump == None and (saved_id, action.addr) in jump_table:
                        saved_jump = jump_table[(saved_id, action.addr)]
                case gtd.frontend.sim_actions.SimActionEnd:
                    # Since this is the last state in a solution, we can omit cleanup of
                    # some variables and creation of the next state. Apart from that,
                    # same behavior as with forks, we get the right state id, ...
                    id = action.id
                    current.id = id

                    # ... save jumps to the current state (we can ignore the current
                    # jump since there is no next state, though)...
                    if saved_jump != None:
                        self.nodes[saved_id].jumps[id] = saved_jump

                    # ... and add the state to the graph.
                    if self.nodes.get(id) != None:
                        self.nodes[id].predecessors.union(current.predecessors)
                        continue
                    self.nodes[id] = current

                    # Lastly, we check whether vpc points to the next instruction or
                    # whether we will need a goto.
                    vpc = solution.mem[self.locations.vpc].uint64_t.resolved
                    size = sum(self.handler.operand_sizes) + 1
                    tmp = claripy.simplify(vpc - size)
                    if (
                        isinstance(tmp, claripy.ast.bv.BV)
                        and tmp.op == "BVS"
                        and tmp.args[0].startswith("vpc")
                    ):
                        self.nodes[id].jumps[self.END_REGULAR_ID] = None
                        self.nodes[self.END_REGULAR_ID].predecessors.add(id)
                    else:
                        self.nodes[id].jumps[self.END_GOTO_VPC_ID] = None
                        self.nodes[self.END_GOTO_VPC_ID].predecessors.add(id)
