"""behaviour.py - watches HOW an agent behaves, not just what one action says.

Three things are detected:
  LOOP             the agent repeats the same action again and again
  TOKEN_SPIKE      one action uses far more tokens than the agent's usual
  BUDGET_EXCEEDED  the agent has used more tokens / money than allowed

The engine blocks on LOOP and BUDGET_EXCEEDED, and just logs TOKEN_SPIKE.
"""
from collections import defaultdict


class BehaviourMonitor:
    def __init__(self, loop_limit=3, spike_factor=3.0,
                 token_budget=50_000, cost_budget=5.0):
        self.loop_limit = loop_limit        # same action this many times in a row = loop
        self.spike_factor = spike_factor    # > 3x the recent average = spike
        self.token_budget = token_budget    # total tokens allowed per agent
        self.cost_budget = cost_budget      # total money (USD) allowed per agent
        self.actions = defaultdict(list)    # agent -> past actions
        self.token_history = defaultdict(list)
        self.total_tokens = defaultdict(int)
        self.total_cost = defaultdict(float)

    def check(self, agent, action, tokens=0, cost=0.0):
        """Record one action and return a list of flags (empty = all fine)."""
        flags = []
        action = " ".join(action.lower().split())

        # 1) loop: last (loop_limit - 1) actions are identical to this one
        recent = self.actions[agent][-(self.loop_limit - 1):]
        if len(recent) == self.loop_limit - 1 and all(a == action for a in recent):
            flags.append("LOOP")

        # 2) token spike: compare with the average of the last 10 actions
        past = self.token_history[agent][-10:]
        if tokens and len(past) >= 3:
            average = sum(past) / len(past)
            if average > 0 and tokens > self.spike_factor * average:
                flags.append("TOKEN_SPIKE")

        # 3) budget: running totals
        self.total_tokens[agent] += tokens
        self.total_cost[agent] += cost
        if (self.total_tokens[agent] > self.token_budget
                or self.total_cost[agent] > self.cost_budget):
            flags.append("BUDGET_EXCEEDED")

        self.actions[agent].append(action)
        if tokens:
            self.token_history[agent].append(tokens)
        return flags

    def reset(self, agent):
        self.actions.pop(agent, None)
        self.token_history.pop(agent, None)
        self.total_tokens.pop(agent, None)
        self.total_cost.pop(agent, None)
