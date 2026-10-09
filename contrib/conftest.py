import os
import sys

# the contrib packages are imported as installed; only the core suite's test helpers (factories) come from the checkout
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests"))
