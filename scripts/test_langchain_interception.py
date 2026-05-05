#!/usr/bin/env python3
import asyncio
import logging
from typing import Any, Dict, List
import uuid

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Mock a basic exception for security blocks
class SecurityBlockException(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"Tool execution blocked: {reason}")

# Mock of the LangChain AsyncCallbackHandler we would build
class SecurityCallbackHandler:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        # In reality this would have a redis client
    
    async def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        tags: List[str] | None = None,
        metadata: Dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", "unknown")
        logger.info(f"LangChain Handler intercepted tool start: {tool_name}")
        
        # Simulate Redis rate limiting step
        logger.info("Simulating Redis rate limit check...")
        
        # We simulate a block if tool_name is "dangerous_tool"
        if tool_name == "dangerous_tool":
            logger.warning("Policy violation detected by handler. Raising exception.")
            raise SecurityBlockException("Access to dangerous_tool is forbidden")
        
        logger.info("Tool execution allowed by handler")

async def test_langchain_interception():
    handler = SecurityCallbackHandler(agent_id="agent_123")
    
    # Test 1: Allowed tool
    try:
        logger.info("--- Test 1: Allowed Tool ---")
        await handler.on_tool_start(
            serialized={"name": "safe_search"},
            input_str="find python tutorials",
            run_id=uuid.uuid4()
        )
        logger.info("✓ Safe tool passed successfully")
    except SecurityBlockException:
        logger.error("✗ Safe tool was incorrectly blocked")
        return False
        
    # Test 2: Blocked tool
    try:
        logger.info("--- Test 2: Blocked Tool ---")
        await handler.on_tool_start(
            serialized={"name": "dangerous_tool"},
            input_str="execute rm -rf /",
            run_id=uuid.uuid4()
        )
        logger.error("✗ Dangerous tool was incorrectly allowed")
        return False
    except SecurityBlockException as e:
        logger.info(f"✓ Dangerous tool correctly blocked: {e}")
        
    return True

if __name__ == "__main__":
    success = asyncio.run(test_langchain_interception())
    if success:
        logger.info("=== LangChain Interception Validation PASSED ===")
    else:
        logger.error("=== LangChain Interception Validation FAILED ===")
        exit(1)
