import asyncio
import os
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

# 1. Define the URL where your A2A server is hosted
# The ADK automatically exposes the Agent Card at the standard .well-known path
A2A_SERVER_URL = os.getenv("A2A_SERVER_URL", "http://127.0.0.1:8001")
AGENT_CARD_URL = f"{A2A_SERVER_URL}/.well-known/agent-card.json"

async def main():
    print("=" * 60)
    print(f"🔗 Connecting to A2A Server at: {A2A_SERVER_URL}")
    print("=" * 60)

    # 2. Initialize the Remote A2A Agent
    # This acts as a proxy. It will fetch the AgentCard from the URL, 
    # validate the skills, and handle all the JSON-RPC networking natively.
    remote_researcher = RemoteA2aAgent(
        name="remote_query_agent",
        description="A remote proxy that delegates to the A2A research pipeline.",
        agent_card=AGENT_CARD_URL 
    )

    # 3. Setup the Runner and Session Service
    # We use InMemorySessionService just like a local agent
    session_service = InMemorySessionService()
    
    runner = Runner(
        agent=remote_researcher, 
        app_name="a2a_client_app", 
        session_service=session_service
    )

    # 4. Create a new session
    session = await session_service.create_session(
        app_name="a2a_client_app",
        user_id="client_user_1",
    )

    # 5. Define the query
    # Because your server's `_parse_user_input` accepts raw text or JSON,
    # we can send a standard text string here.
    user_query = "What are the latest best practices for securing LangGraph agents?"
    
    message = types.Content(
        role="user", 
        parts=[types.Part(text=user_query)]
    )

    print(f"\n🗣️  Sending Query: {user_query}")
    print("⏳ Waiting for the remote pipeline to process (researching & evaluating)...\n")

    # 6. Execute the run loop
    # We stream the events back from the server asynchronously
    final_text = ""
    
    async for event in runner.run_async(
        session_id=session.id, 
        user_id="client_user_1", 
        new_message=message
    ):
        # Optional: You can print intermediate event types to see what the server is doing
        # print(f"  [Server Update] Status: {event.type}")
        
        if event.is_final_response() and event.content and event.content.parts:
            final_text = "".join(p.text for p in event.content.parts if p.text)

    print("-" * 60)
    print("✅ Final Answer Received from Server:")
    print("-" * 60)
    print(final_text)

if __name__ == "__main__":
    # Ensure graceful exit and handle connection errors
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nClient stopped by user.")
    except Exception as e:
        print(f"\n❌ Error connecting to the A2A server: {e}")
        print("Please make sure your server is running on port 8001.")