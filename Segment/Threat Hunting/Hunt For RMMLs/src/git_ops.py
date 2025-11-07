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
    logger.debug(f"Repository URL: {repo_url}")
    logger.debug(f"Target directory: {target_path}")
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


def validate_cloned_repository(repo_path: str, target_rmms_path: Optional[str] = None) -> Path:
    """
    Validate cloned repository structure, move YAML files to target directory, and clean up.
    
    Validates that the RMML directory exists, the RMMs directory exists within it,
    and that the RMMs directory contains YAML files. If validation succeeds, moves
    all YAML files to the target directory and removes the original RMML directory.
    
    :param repo_path: Path to the cloned RMML repository directory
    :type repo_path: str
    :param target_rmms_path: Optional path to target RMMs directory. If not provided,
                             defaults to RMMs in current working directory
    :type target_rmms_path: Optional[str]
    :return: Path object to the target RMMs directory where YAML files were moved
    :rtype: Path
    :raises ValueError: If repository structure is invalid
    :raises FileNotFoundError: If no YAML files are found in RMMs directory
    :raises RuntimeError: If file operations fail
    """
    logger.info("Validating cloned repository and moving YAML files to target directory...")
    
    repo_path_obj = Path(repo_path).resolve()
    
    # Step 1: Validate RMML directory exists
    logger.info("Step 1: Validating RMML directory exists...")
    if not repo_path_obj.exists():
        error_msg = f"Cloned RMML repository directory does not exist at path: {repo_path_obj}"
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    if not repo_path_obj.is_dir():
        error_msg = f"Path to cloned RMML repository is not a directory: {repo_path_obj}"
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    logger.debug(f"Cloned RMML repository directory validated: {repo_path_obj}")
    
    # Step 2: Validate RMMs directory exists
    logger.info("Step 2: Validating RMMs directory exists within cloned repository...")
    rmms_dir = repo_path_obj / "RMMs"
    if not rmms_dir.is_dir():
        error_msg = f"RMMs directory not found: {rmms_dir}"
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    logger.debug(f"RMMs directory validated: {rmms_dir}")
    
    # Step 3: Validate RMMs directory has YAML files
    logger.info("Step 3: Validating RMMs directory contains YAML files...")
    yaml_files = list(rmms_dir.glob("*.yaml")) + list(rmms_dir.glob("*.yml"))
    
    if not yaml_files:
        error_msg = f"No YAML files found in RMMs directory: {rmms_dir}"
        logger.error(error_msg)
        raise FileNotFoundError(error_msg)
    
    logger.debug(f"Found {len(yaml_files)} YAML file(s) in RMMs directory")
    
    # Step 4: Move YAML files to target directory
    logger.info("Step 4: Moving YAML files to target directory...")
    
    # Determine target directory
    if target_rmms_path:
        target_dir = Path(target_rmms_path).resolve()
    else:
        # Default to RMML/RMMs in current working directory
        target_dir = Path.cwd() / "RMMs"
    
    # Create target directory if it doesn't exist
    target_dir.mkdir(parents=True, exist_ok=True)
    logger.debug(f"Target directory: {target_dir}")
    
    # Move each YAML file to target directory
    moved_count = 0
    try:
        for yaml_file in yaml_files:
            target_file = target_dir / yaml_file.name
            
            # If target file exists, remove it first
            if target_file.exists():
                logger.warning(f"Target file exists, removing: {target_file}")
                target_file.unlink()
            
            # Move the file
            shutil.move(str(yaml_file), str(target_file))
            moved_count += 1
            logger.debug(f"Moved {yaml_file.name} to {target_dir}")
        
        logger.info(f"Successfully moved {moved_count} YAML file(s) to {target_dir}")
        
    except Exception as e:
        error_msg = f"Failed to move YAML files to target directory: {e}"
        logger.error(error_msg)
        raise RuntimeError(error_msg) from e
    
    # Step 5: Remove the original RMML directory
    logger.info("Step 5: Removing original RMML directory...")
    try:
        shutil.rmtree(repo_path_obj)
        logger.info(f"Successfully removed original RMML directory: {repo_path_obj}")
    except Exception as e:
        error_msg = f"Failed to remove original RMML directory: {e}"
        logger.error(error_msg)
        raise RuntimeError(error_msg) from e
    
    logger.info("Repository validation and file operations completed successfully")
    return target_dir


def clone_and_validate(repo_url: str, branch: Optional[str] = None, target_rmms_path: Optional[str] = None) -> Path:
    """
    Complete workflow: check git, clone repository, validate, move files, and clean up.
    
    This is a convenience function that combines all operations in the correct order.
    The repository will be cloned to the current directory.
    If the target directory already exists, it will be removed before cloning.
    After validation, YAML files are moved to the target directory and the cloned
    repository is removed.
    
    :param repo_url: URL of the repository to clone
    :type repo_url: str
    :param branch: Optional branch to checkout after cloning
    :type branch: Optional[str]
    :param target_rmms_path: Optional path to target RMMs directory. If not provided,
                             defaults to RMMs in current working directory
    :type target_rmms_path: Optional[str]
    :return: Path object to the target RMMs directory where YAML files were moved
    :rtype: Path
    :raises RuntimeError: If any step in the workflow fails
    :raises ValueError: If validation fails
    """
    try:
        # Step 1: Check git availability
        check_git_availability()
        
        # Step 2: Clone the repository
        repo_path = clone_repository(repo_url, branch)
        
        # Step 3: Validate the cloned repository, move files, and clean up
        rmms_path = validate_cloned_repository(repo_path, target_rmms_path)
        
        logger.info("Completed git clone and validation workflow")
        return rmms_path
        
    except Exception as e:
        logger.error(f"Git workflow failed: {e}")
        raise RuntimeError(f"Git workflow failed: {e}") from e
