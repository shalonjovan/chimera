from chimera.core.logging import get_logger
from chimera.core.server import server
from chimera.tools.builtin.filesystem import filesystem_read, filesystem_write, filesystem_search
from chimera.tools.builtin.shell import shell_exec
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

    log.info("Registered 4 built-in tools")
