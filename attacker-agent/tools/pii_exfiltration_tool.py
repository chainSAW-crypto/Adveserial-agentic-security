from langchain.tools import tool
from typing import List, Dict

import base64

# Utility functions for PII exfiltration techniques
from utils.exfiltration import PIIExfiltrationTool

# Tool wrapper for agent usage

@tool
def exfiltrate_pii(data, method="base64"):
    """
    Exfiltrate PII using the specified method.
    Methods: base64, leetspeak, morse, emoji, gist
    """
    return PIIExfiltrationTool.exfiltrate(data, method)

# Example usage:
# result = exfiltrate_pii("user@gmail.com", method="leetspeak")
# print(result)