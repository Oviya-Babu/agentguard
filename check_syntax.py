#!/usr/bin/env python3
import sys
import py_compile

try:
    py_compile.compile('/home/oviya/projects/agentguard/app/main.py', doraise=True)
    print("✅ Syntax valid")
    sys.exit(0)
except py_compile.PyCompileError as e:
    print(f"❌ Syntax error: {e}")
    sys.exit(1)
