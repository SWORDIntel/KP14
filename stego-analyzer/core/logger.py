"""Placeholder for logger module.

This module configures and provides a logger for the Stego Analyzer project.
It sets up console and rotating file handlers.
"""
import os
import logging
import logging.handlers

# Import configuration variables from core.config
try:
    from core.config import LOG_DIR, DEFAULT_LOG_FILE, VERBOSE, LOG_LEVEL
except ImportError:
    # Fallback for direct execution or if config is not yet fully integrated
    print("Warning: core.config not found, using default logger settings.")
    PROJECT_ROOT_FALLBACK = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    LOG_DIR = os.path.join(PROJECT_ROOT_FALLBACK, 'output', 'logs')
    DEFAULT_LOG_FILE = os.path.join(LOG_DIR, 'pipeline_fallback.log')
    VERBOSE = True
    LOG_LEVEL = 'DEBUG'


def setup_logger(name='stego_analyzer_logger', log_file_path=None):
    """
    Configures and returns a logger instance.

    Args:
        name (str): The name for the logger.
        log_file_path (str, optional): Specific path for the log file.
                                       Defaults to DEFAULT_LOG_FILE from config.

    Returns:
        logging.Logger: Configured logger object.
    """
    logger = logging.getLogger(name)

    # Determine overall logger level based on VERBOSE and LOG_LEVEL from config
    if VERBOSE:
        level = logging.DEBUG
    else:
        level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(level)

    # Prevent multiple handlers if logger is already configured (e.g., in interactive sessions)
    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s')

    # Console Handler
    ch = logging.StreamHandler()
    # Console handler level can also be controlled by VERBOSE or a separate config
    ch.setLevel(logging.DEBUG if VERBOSE else level) # Show debug on console if VERBOSE
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Rotating File Handler
    # Ensure LOG_DIR exists
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except OSError as e:
        # Fallback to a simple console log if directory creation fails
        print(f"Error creating log directory {LOG_DIR}: {e}. File logging will be disabled.")
        logger.warning(f"Log directory {LOG_DIR} could not be created. File logging disabled.")
        return logger # Return logger with console handler only

    file_handler_path = log_file_path if log_file_path else DEFAULT_LOG_FILE

    # Use RotatingFileHandler
    # Rotates logs at 10MB, keeping 5 backup files.
    try:
        rfh = logging.handlers.RotatingFileHandler(
            file_handler_path,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5
        )
        rfh.setLevel(logging.DEBUG)  # File logger should generally log everything (DEBUG and up)
        rfh.setFormatter(formatter)
        logger.addHandler(rfh)
    except Exception as e:
        # If file handler setup fails, log to console and continue
        logger.error(f"Failed to set up RotatingFileHandler at {file_handler_path}: {e}")


    logger.debug(f"Logger '{name}' configured. Level: {logging.getLevelName(logger.level)}. Outputting to console and {file_handler_path}")
    return logger

# Create a default logger instance for easy import elsewhere
# This instance can be imported by other modules as `from core.logger import log`
log = setup_logger()

if __name__ == '__main__':
    # Example usage of the logger
    print(f"Testing logger. Default log file should be at: {DEFAULT_LOG_FILE}")
    log.debug("This is a debug message from logger_test.")
    log.info("This is an info message from logger_test.")
    log.warning("This is a warning message from logger_test.")
    log.error("This is an error message from logger_test.")
    log.critical("This is a critical message from logger_test.")

    print("\nTesting with a different logger name and file path...")
    custom_log_path = os.path.join(LOG_DIR, 'custom_test.log')
    custom_logger = setup_logger('my_custom_logger', log_file_path=custom_log_path)
    custom_logger.info(f"This is an info message from the custom logger to {custom_log_path}")
    print(f"Custom logger messages should be in console and in {custom_log_path}")

    # Verify log file creation
    if os.path.exists(DEFAULT_LOG_FILE):
        print(f"\nDefault log file CREATED: {DEFAULT_LOG_FILE}")
        with open(DEFAULT_LOG_FILE, 'r') as f:
            print("First few lines of default log:")
            for i in range(5):
                line = f.readline().strip()
                if line:
                    print(line)
                else:
                    break
    else:
        print(f"\nDefault log file NOT created: {DEFAULT_LOG_FILE}")

    if os.path.exists(custom_log_path):
        print(f"\nCustom log file CREATED: {custom_log_path}")
    else:
        print(f"\nCustom log file NOT created: {custom_log_path}")
