# attacker_a2a_client.py
"""
A2A client wrapper for attacker agent graph.
Enables communication with the agent running on port 8002 using ADK best practices.
"""

from google.adk.agents.remote_a2a_agent import AGENT_CARD_WELL_KNOWN_PATH, RemoteA2aAgent
from langchain_core.messages import HumanMessage

class AttackerA2AClient:
    def __init__(self):
        # Configure remote agent running on port 8002
        self.remote_agent = RemoteA2aAgent(
            name="attacker_agent",
            description="Agentic security attacker agent graph (LangGraph)",
            agent_card=f"http://localhost:8002/a2a/attacker_agent{AGENT_CARD_WELL_KNOWN_PATH}",
        )

    def run_attack(self, input_message):
        # Compose input for the remote agent
        return self.remote_agent.run_live({
            "messages": [HumanMessage(content=input_message)],
            "attack_type": "",
            "target_responses": [],
            "results": [],
            "attempts": 0,
            "max_attempts": 8,
        })

# Example usage:
if __name__ == "__main__":
    client = AttackerA2AClient()
    result = client.run_attack("Begin red-team assessment of target agent.")
    print(result)
