#!/usr/bin/env python3

# ====================================================
# File: hunt.py
# Author: Thomas Obarowski
# Email: thomas.obarowski@zeronetworks.com
# Created: 2025-10-29
# Description:
# ====================================================


import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from textwrap import dedent

from loguru import logger

from src.git_ops import clone_and_validate
from src.rmmdata import RMMData, load_yaml_files
from src.zero_threat_hunt_tools import ZeroThreatHuntTools #TODO remove after testing


def setup_logging(verbose_level: int = 0) -> None:
    """
    Configure loguru logging with console and file handlers.
    
    Sets up comprehensive logging with both console and file output, including
    colorized console output, file rotation, compression, and detailed formatting
    with function location tracking and exception handling.
    
    :param verbose_level: Logging verbosity level (0=INFO, 1=DEBUG, 2=TRACE)
    :type verbose_level: int
    :return: None
    :rtype: None
    """
    # Remove default handler
    logger.remove()

    # Determine log level based on verbose level
    log_level = "INFO"
    if verbose_level == 1:
        log_level = "DEBUG"
    elif verbose_level >= 2:
        log_level = "TRACE"

    # Console handler with colors
    console_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level>"
    )

    logger.add(
        sys.stderr,
        format=console_format,
        level=log_level,
        colorize=True,
        backtrace=True,
        diagnose=True,
    )

    # File handler with rotation
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    file_format = (
        "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
        "{level: <8} | "
        "{name}:{function}:{line} | "
        "{message}"
    )

    logger.add(
        log_dir / "hunt.log",
        format=file_format,
        level=log_level,
        rotation="10 MB",
        retention=5,
        compression="zip",
        backtrace=True,
        diagnose=True,
        enqueue=True,  # Thread-safe logging
    )


def parse_arguments() -> argparse.Namespace:
    """
    Parse and validate command line arguments.
    
    Creates an argument parser with support for verbose logging, API key
    configuration, and datetime specification.
    
    :return: Parsed command line arguments namespace
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(
        description=dedent("""
        --------------------------------
        Zero Networks - Hunt for RMMLs:
        --------------------------------
        Searches your Zero Networks tenant activities for any source or 
        destination domains or processes which might be related to the 
        known Remote Management and Monitoring (RMML) software listed within:
        https://github.com/LivingInSyn/RMML/tree/22207b061b2b3c2599adbb6f725e0d491f116cab/RMMs
        --------------------------------
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent("""
        Examples:
            python hunt.py
            # Use UTC
            python hunt.py --from "2024-01-01T00:00:00Z"
            # Or, add the offset to the timestamp
            python hunt.py -v --from "2024-01-01T00:00:00-05:00"
            # Specify both from and to timestamps
            python hunt.py --from "2024-01-01T00:00:00Z" --to "2024-01-31T23:59:59Z"
            python hunt.py -vv
            
        Environment Variables:
            ZN_API_KEY    Zero Networks API key for authentication
        """),
    )

    # Verbose options
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Enable verbose logging (-v for DEBUG, -vv for TRACE)",
    )


    # Time range
    parser.add_argument(
        "--from",
        dest="from_timestamp",
        type=str,
        required=False,
        help="Start datetime for querying Zero API (ISO8601 format, e.g., '2024-01-01T00:00:00Z'). Defaults to one week ago if not specified.",
    )

    parser.add_argument(
        "--to",
        dest="to_timestamp",
        type=str,
        required=False,
        help="End datetime for querying Zero API (ISO8601 format, e.g., '2024-01-31T23:59:59Z'). Defaults to current time if not specified.",
    )

    # Repository URL
    parser.add_argument(
        "--repo-url",
        dest="repo_url",
        type=str,
        default="https://github.com/LivingInSyn/RMML.git",
        help="URL of the RMML repository to clone. Defaults to https://github.com/LivingInSyn/RMML.git",
    )

    return parser.parse_args()


def load_api_key() -> str:
    """
    Load Zero Networks API key from environment variable.
    
    :return: API key from ZN_API_KEY environment variable
    :rtype: str
    :raises ValueError: If ZN_API_KEY environment variable is not set or empty
    """
    api_key = os.getenv("ZN_API_KEY")
    if not api_key or len(api_key.strip()) == 0:
        raise ValueError("ZN_API_KEY environment variable is not set or empty")
    return api_key.strip()


def main() -> int:
    """
    Main entry point for the Hunt for RMMLs script.
    
    Orchestrates the entire threat hunting workflow including argument parsing,
    logging setup, input validation, and initialization of hunting operations.
    
    :return: Exit code indicating script success or failure (0=success, 1=error)
    :rtype: int
    """
    try:
        # Parse arguments
        args = parse_arguments()

        # Setup logging based on verbose level
        setup_logging(args.verbose)

        # Log startup information
        logger.info("Starting Hunt for RMMLs script")
        logger.debug(f"Arguments: {args}")

        # Set from_timestamp: use provided value or default to one week ago in ISO8601 format
        if args.from_timestamp:
            from_timestamp = args.from_timestamp
            logger.info(f"Using provided from_timestamp: {from_timestamp}")
        else:
            # Use default: one week ago, converted to ISO8601 format with UTC timezone
            one_week_ago = datetime.now(timezone.utc) - timedelta(weeks=1)
            from_timestamp = one_week_ago.isoformat()
            logger.info(f"No --from argument provided, using default: one week ago ({from_timestamp})")

        # Set to_timestamp: use provided value or default to current time in ISO8601 format
        if args.to_timestamp:
            to_timestamp = args.to_timestamp
            logger.info(f"Using provided to_timestamp: {to_timestamp}")
        else:
            # Use default: current time, converted to ISO8601 format with UTC timezone
            now = datetime.now(timezone.utc)
            to_timestamp = now.isoformat()
            logger.info(f"No --to argument provided, using default: current time ({to_timestamp})")

        # Load and validate API key from environment
        try:
            api_key = load_api_key()
            logger.info("API key loaded from environment variable ZN_API_KEY")
            logger.debug(f"API key loaded successfully (length: {len(api_key)})")
        except ValueError as e:
            logger.error(f"API key validation failed: {e}")
            logger.error("Please set the ZN_API_KEY environment variable")
            return 1

        logger.info("Hunt script initialized successfully")
        
        # Clone the target RMML repository. This extracts the YAML files to a dedicated RMML directory
        repo_url: str = args.repo_url
        logger.info(f"Attempting to clone and validate the RMML repository: {repo_url}")
        rmms_path = clone_and_validate(repo_url=repo_url)
        logger.debug(f"RMM YAMLs downloaded to: {rmms_path}")

        # Load the YAML files into a RMMData object
        rmm_data: RMMData = load_yaml_files(rmms_path)
        logger.info(f"Loaded data for {len(rmm_data.rmm_list)} RMMs")

        #Load Zero Networks Hunt Operations class
        """zn_hunt_ops:ZNHuntOps = ZNHuntOps(api_key=api_key, rmm_data=rmm_data)
        zn_hunt_ops.execute_hunt(from_timestamp=from_timestamp, to_timestamp=to_timestamp)"""
        zero_hunt: ZeroThreatHuntTools = ZeroThreatHuntTools(api_key=api_key)
        zero_hunt.get_activities_to_domains(domains=["microsoft"],from_timestamp=from_timestamp, to_timestamp=to_timestamp)



        logger.info("Hunt completed successfully")

        return 0

    except KeyboardInterrupt:
        logger.warning("Script interrupted by user")
        return 1
    except Exception as e:
        logger.exception(f"Unexpected error occurred: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
