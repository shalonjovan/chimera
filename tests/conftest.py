import shutil

import pytest

from chimera.config.settings import settings

BRIDGE_PATH = settings.cyberchef_bridge_path.resolve()
NODE = shutil.which(settings.cyberchef_node_path)

pytestmark = pytest.mark.skipif(
    not NODE or not BRIDGE_PATH.exists(),
    reason="CyberChef bridge or node unavailable (run scripts/setup_cyberchef.sh)",
)
