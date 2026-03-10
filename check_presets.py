import sys, os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.getcwd())

# Force reload
if 'orchestrator' in sys.modules:
    del sys.modules['orchestrator']
if 'orchestrator.main' in sys.modules:
    del sys.modules['orchestrator.main']

from orchestrator.main import PRESET_PROMPTS
for k, v in PRESET_PROMPTS.items():
    print(f"  {k}: {v['label']}")
