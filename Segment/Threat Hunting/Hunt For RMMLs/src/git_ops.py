#!/usr/bin/env python3

"""
<<MODULE NAME>>

File: git_ops.py
Author: Thomas Obarowski
Email: thomas.obarowski@zeronetworks.com
Created: 2025-10-29

<<DESCRIPTION>>
"""

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional
from loguru import logger


def check_git_availability() -> None:
    """
    Check if git is available on the command line.
    
    Launches a subprocess to verify git is installed and accessible.
    All output is logged in real-time.
    
    :raises RuntimeError: If git is not available or command fails
    :raises subprocess.CalledProcessError: If git command fails
    """
    logger.info("Checking git availability...")
    
    try:
        # Run git --version to check availability
        result = subprocess.run(
            ["git", "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Log the git version output
        if result.stdout:
            logger.info(f"Git version: {result.stdout.strip()}")
        if result.stderr:
            logger.warning(f"Git stderr: {result.stderr.strip()}")
            raise Exception(f"Git returned an error: {result.stderr.strip()}")
            
        logger.info("Git is available and working")
        
    except subprocess.TimeoutExpired:
        error_msg = "Git command timed out after 10 seconds"
        logger.error(error_msg)
        raise RuntimeError(error_msg)
        
    except FileNotFoundError:
        error_msg = "Git is not installed or not found in PATH"
        logger.error(error_msg)
        raise RuntimeError(error_msg)
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Git command failed with exit code {e.returncode}"
        logger.error(error_msg)
        if e.stdout:
            logger.error(f"Git stdout: {e.stdout}")
        if e.stderr:
            logger.error(f"Git stderr: {e.stderr}")
        raise RuntimeError(error_msg) from e
        
    except Exception as e:
        error_msg = f"Unexpected error checking git availability: {e}"
        logger.error(error_msg)
        raise RuntimeError(error_msg) from e


def clone_repository(repo_url: str, branch: Optional[str] = None) -> str:
    """
    Clone a git repository to the current directory.
    
    Launches a subprocess to clone the repository with real-time output logging.
    The repository will be cloned to a directory named after the repository in the current working directory.
    If the target directory already exists, it will be removed before cloning.
    Validates that the clone operation was successful.
    
    :param repo_url: URL of the repository to clone
    :type repo_url: str
    :param branch: Optional branch to checkout after cloning
    :type branch: Optional[str]
    :return: Path to the cloned repository directory
    :rtype: str
    :raises ValueError: If repo_url is invalid
    :raises RuntimeError: If git clone command fails or if directory removal fails
    :raises subprocess.CalledProcessError: If git clone command fails
    """
    # Validate inputs
    if not repo_url or not repo_url.strip():
        raise ValueError("Repository URL cannot be empty")
    
    # Extract repository name from URL for target directory
    repo_name = repo_url.rstrip('/').split('/')[-1]
    if repo_name.endswith('.git'):
        repo_name = repo_name[:-4]  # Remove .git extension
    
    # Clone to current directory
    target_path = Path.cwd() / repo_name
    
    logger.info("Starting git clone operation")
    logger.info(f"Repository URL: {repo_url}")
    logger.info(f"Target directory: {target_path}")
    if branch:
        logger.info(f"Target branch: {branch}")
    
    # Check if target directory already exists and remove it
    if target_path.exists():
        logger.info(f"Target directory exists, removing it: {target_path}")
        try:
            shutil.rmtree(target_path)
            logger.info("Target directory removed successfully")
        except Exception as e:
            error_msg = f"Failed to remove existing target directory: {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e
    
    try:
        # Prepare git clone command
        cmd = ["git", "clone", repo_url, str(target_path)]
        if branch:
            cmd.extend(["-b", branch])
        
        logger.debug(f"Executing command: {' '.join(cmd)}")
        
        # Run git clone with real-time output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Log output in real-time
        for line in iter(process.stdout.readline, ''):
            if line:
                logger.info(f"Git clone: {line.strip()}")
        
        # Wait for process to complete
        return_code = process.wait()
        
        if return_code != 0:
            error_msg = f"Git clone failed with exit code {return_code}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        logger.info("Git clone completed successfully")
        return str(target_path)
        
    except subprocess.TimeoutExpired:
        error_msg = "Git clone command timed out"
        logger.error(error_msg)
        raise RuntimeError(error_msg)
        
    except FileNotFoundError:
        error_msg = "Git command not found - ensure git is installed"
        logger.error(error_msg)
        raise RuntimeError(error_msg)
        
    except Exception as e:
        error_msg = f"Unexpected error during git clone: {e}"
        logger.error(error_msg)
        raise RuntimeError(error_msg) from e


def validate_cloned_repository(repo_path: str) -> bool:
    """
    Validate that the cloned repository has the required RMMs structure.
    
    :param repo_path: Path to the cloned repository
    :type repo_path: str
    :return: True if repository is valid
    :rtype: bool
    :raises ValueError: If repository structure is invalid
    """
    logger.info("Validating cloned repository...")
    
    repo_path_obj = Path(repo_path).resolve()
    
    # Define required checks with clear error messages
    checks = [
        (repo_path_obj.exists(), f"Repository directory does not exist: {repo_path_obj}"),
        (repo_path_obj.is_dir(), f"Repository path is not a directory: {repo_path_obj}"),
        ((repo_path_obj / ".git").is_dir(), f"Not a valid git repository: {repo_path_obj}"),
        ((repo_path_obj / "RMMs").is_dir(), f"RMMs directory not found: {repo_path_obj / 'RMMs'}"),
    ]
    
    # Run all checks
    for is_valid, error_msg in checks:
        if not is_valid:
            logger.error(error_msg)
            raise ValueError(error_msg)
    
    # Check for YAML files
    rmms_dir = repo_path_obj / "RMMs"
    yaml_files = list(rmms_dir.glob("*.yaml")) + list(rmms_dir.glob("*.yml"))
    
    if not yaml_files:
        error_msg = f"No YAML files found in RMMs directory: {rmms_dir}"
        logger.error(error_msg)
        raise FileNotFoundError(error_msg)
    
    logger.info(f"Found {len(yaml_files)} YAML file(s) in RMMs directory")
    logger.info("Repository validation completed successfully")
    return True


def clone_and_validate(repo_url: str, branch: Optional[str] = None) -> str:
    """
    Complete workflow: check git, clone repository, and validate the result.
    
    This is a convenience function that combines all operations in the correct order.
    The repository will be cloned to the current directory.
    If the target directory already exists, it will be removed before cloning.
    
    :param repo_url: URL of the repository to clone
    :type repo_url: str
    :param branch: Optional branch to checkout after cloning
    :type branch: Optional[str]
    :return: Path to the cloned repository directory
    :rtype: str
    :raises RuntimeError: If any step in the workflow fails
    :raises ValueError: If validation fails
    """
    try:
        # Step 1: Check git availability
        check_git_availability()
        
        # Step 2: Clone the repository
        repo_path = clone_repository(repo_url, branch)
        
        # Step 3: Validate the cloned repository
        validate_cloned_repository(repo_path)
        
        logger.info("Complete git workflow completed successfully")
        return repo_path
        
    except Exception as e:
        logger.error(f"Git workflow failed: {e}")
        raise RuntimeError(f"Git workflow failed: {e}") from e
