"""
StormShell - Listener Module

A lightweight TCP socket listener that accepts incoming reverse shell
connections.  After a client connects, the listener enters an interactive
command loop — sending operator commands to the agent and displaying the
agent's responses.  Includes robust error handling and graceful teardown.
"""

import socket
import sys
import logging

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BUFFER_SIZE = 4096  # Max bytes to receive per recv() call

# ---------------------------------------------------------------------------
# Logger configuration
# ---------------------------------------------------------------------------
logger = logging.getLogger("stormshell.listener")


class Listener:
    """
    TCP socket listener that binds to a given host and port, waits for a
    single inbound connection, and then enters an interactive command loop
    to exchange data with the connected agent.

    Attributes:
        host (str):   IP address to bind the listener to.
        port (int):   TCP port number to listen on.
        server (socket.socket | None): The server socket instance.
        client (socket.socket | None): The accepted client socket instance.
        client_address (tuple | None):  (ip, port) of the connected client.
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
    # Interactive command loop
    # ------------------------------------------------------------------

    def _interactive_loop(self) -> None:
        """
        Enter an interactive command loop after a connection has been
        established.  The operator types commands which are sent to the
        agent; the agent's response is then printed to the console.

        Special commands:
            exit  — Send a shutdown signal to the agent and break out of
                    the loop, triggering a graceful teardown.
        """
        print("[*] Interactive session started. Type 'exit' to quit.\n")
        logger.info("Interactive command loop started.")

        while True:
            try:
                command = input("StormShell> ").strip()
            except (EOFError, KeyboardInterrupt):
                # Operator pressed Ctrl+C or Ctrl+D at the prompt.
                print("\n[!] Interrupt received. Ending session …")
                logger.warning("Operator interrupted the command prompt.")
                # Attempt to notify the agent before exiting.
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

            # --- Receive the agent's response ---
            try:
                response = self.client.recv(BUFFER_SIZE)
                if not response:
                    # Empty response means the agent disconnected.
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
        Full listener lifecycle: create → bind → listen → accept one
        connection → interactive command loop → graceful shutdown.
        """
        try:
            self._create_server_socket()
            self._bind_and_listen()
            self._accept_connection()
            self._interactive_loop()

        except KeyboardInterrupt:
            print("\n[!] Keyboard interrupt received. Shutting down …")
            logger.warning("Keyboard interrupt — shutting down.")

        finally:
            self._cleanup()
            print("[*] All sockets closed. Exiting.\n")
            logger.info("All sockets closed. Listener exited.")
