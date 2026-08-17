from chimera.core.logging import get_logger
from chimera.core.server import server
from chimera.tools.builtin.filesystem import filesystem_read, filesystem_write, filesystem_search
from chimera.tools.builtin.shell import shell_exec
from chimera.tools.cyberchef import cyberchef_operation, cyberchef_operations, cyberchef_recipe
from chimera.tools.dispatcher import dispatcher

log = get_logger(__name__)


def register_builtin_tools() -> None:
    dispatcher.register_builtin("shell_exec", shell_exec)
    dispatcher.register_builtin("filesystem_read", filesystem_read)
    dispatcher.register_builtin("filesystem_write", filesystem_write)
    dispatcher.register_builtin("filesystem_search", filesystem_search)

    server.register_tool(shell_exec, description="Execute a shell command and return output")
    server.register_tool(filesystem_read, description="Read a file from the filesystem")
    server.register_tool(filesystem_write, description="Write content to a file")
    server.register_tool(filesystem_search, description="Search for files by glob pattern")

    dispatcher.register_builtin("cyberchef_operations", cyberchef_operations)
    dispatcher.register_builtin("cyberchef_operation", cyberchef_operation)
    dispatcher.register_builtin("cyberchef_recipe", cyberchef_recipe)

    server.register_tool(cyberchef_operations, description="List CyberChef operations, optionally filtered by query")
    server.register_tool(cyberchef_operation, description="Run a single CyberChef operation with optional args")
    server.register_tool(cyberchef_recipe, description="Run a chain of CyberChef operations as a recipe")

    log.info("Registered 7 built-in tools")
