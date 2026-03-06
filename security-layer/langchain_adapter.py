"""
AgentShield — LangChain Integration
Drop-in wrapper for any LangChain chain or agent.
"""
from .core import AgentShield, ShieldConfig, SecurityViolation


class ShieldedLangChainAgent:
    """
    Wraps any LangChain chain/agent/runnable with AgentShield security.

    Usage:
        from langchain_openai import ChatOpenAI
        from langchain.chains import LLMChain
        from agentshield.integrations.langchain import ShieldedLangChainAgent

        chain = LLMChain(llm=ChatOpenAI(), prompt=my_prompt)
        safe_agent = ShieldedLangChainAgent(chain, config=ShieldConfig(
            system_prompt="You are a helpful assistant...",
            max_calls_per_minute=30,
        ))

        result = safe_agent.invoke("user input", user_id="user_123")
    """

    def __init__(self, chain, config: ShieldConfig = None):
        self.chain = chain
        self.shield = AgentShield(config or ShieldConfig())

    def invoke(self, user_input: str, user_id: str = "anonymous", **kwargs) -> dict:
        # Check input
        safe_input = self.shield.check_input(user_input, user_id)

        # Rate limit
        self.shield.check_rate_limit(user_id)

        # Run the real chain
        raw_result = self.chain.invoke({"input": safe_input}, **kwargs)

        # Extract output text (handles different chain output formats)
        output_text = raw_result if isinstance(raw_result, str) else raw_result.get("output") or str(raw_result)

        # Filter output
        safe_output = self.shield.filter_output(output_text, user_id)

        return {"output": safe_output, "security_summary": self.shield.get_audit_summary()}

    @property
    def audit_log(self):
        return self.shield.get_audit_log()
