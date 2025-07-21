"""OpsBox command-line interface."""

import logging

from opsbox.utils import get_system_info

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    """Display OpsBox system information and available modules."""
    logger.info("OpsBox - Server Operations Tools")
    logger.info("=" * 40)

    # Display system information
    logger.info("\nSystem Information:")
    info = get_system_info()
    for key, value in info.items():
        logger.info("  %s: %s", key, value)

    logger.info("\nAvailable modules:")
    logger.info("  - backup: Server backup functionality")
    logger.info("  - mail: Encrypted mail operations")
    logger.info("  - utils: Common utility functions")

    logger.info("\nFor more information, see the documentation.")


if __name__ == "__main__":
    main()
