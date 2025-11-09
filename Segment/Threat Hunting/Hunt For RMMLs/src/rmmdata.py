#!/usr/bin/env python3

"""
YAML Operations Module

File: yaml_ops.py
Author: Thomas Obarowski
Email: thomas.obarowski@zeronetworks.com
Created: 2025-10-30

This module provides functions to read and load YAML files from a directory
into a list of dictionary objects that mirror the structure of the YAML files.
"""

from pathlib import Path
from typing import Any, Optional

import yaml
from loguru import logger


class RMMData:
    """
    Class for loading and querying RMM YAML files.
    
    This class loads YAML files once and provides methods to query the loaded data
    without needing to pass the list around between function calls.
    
    Example:
        rmm_data = RMMData(Path("RMMs"))
        rmm = rmm_data.get_full_details_by_name_or_id("TeamViewer")
        domains = rmm_data.get_all_domains()
    """
    
    def __init__(self, rmms_dir: Path, include_filename: bool = True):
        """
        Initialize RMMData and load YAML files from the specified directory.
        
        :param rmms_dir: Path to the directory containing YAML files
        :type rmms_dir: Path
        :param include_filename: Whether to include the name in each dictionary
                               (added as 'name' key, using filename stem). Defaults to True.
        :type include_filename: bool
        :raises FileNotFoundError: If the target directory does not exist
        :raises ValueError: If the directory exists but contains no YAML files
        """
        self.rmms_dir = Path(rmms_dir).resolve()
        self.include_filename = include_filename
        self.rmm_list: list[dict[str, Any]] = []
        self.rmm_simplified_list: list[dict[str, Any]] = []
        self._load_files()
        self._build_simplified_list()
    
    def _load_files(self) -> None:
        """Internal method to load YAML files into rmm_list attribute."""
        # Validate directory exists
        if not self.rmms_dir.exists():
            error_msg = f"RMMs directory does not exist: {self.rmms_dir}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)
        
        if not self.rmms_dir.is_dir():
            error_msg = f"Path is not a directory: {self.rmms_dir}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        logger.info(f"Loading YAML files from directory: {self.rmms_dir}")
        
        # Find all YAML files
        yaml_files = list(self.rmms_dir.glob("*.yaml")) + list(self.rmms_dir.glob("*.yml"))
        
        if not yaml_files:
            error_msg = f"No YAML files found in directory: {self.rmms_dir}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        logger.info(f"Found {len(yaml_files)} YAML file(s)")
        
        # Load each YAML file into a dictionary
        failed_files: list[str] = []
        
        for yaml_file in yaml_files:
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    yaml_data = yaml.safe_load(f)
                
                # If include_filename is True, add the name (from filename stem) to the dictionary
                if self.include_filename:
                    if yaml_data is None:
                        yaml_data = {}
                    yaml_data['name'] = Path(yaml_file.name).stem
                
                self.rmm_list.append(yaml_data)
                logger.debug(f"Successfully loaded: {yaml_file.name}")
                
            except yaml.YAMLError as e:
                error_msg = f"Failed to parse YAML file {yaml_file.name}: {e}"
                logger.error(error_msg)
                failed_files.append(yaml_file.name)
            except Exception as e:
                error_msg = f"Unexpected error loading {yaml_file.name}: {e}"
                logger.error(error_msg)
                failed_files.append(yaml_file.name)
        
        if failed_files:
            logger.warning(f"Failed to load {len(failed_files)} file(s): {', '.join(failed_files)}")
        
        logger.info(f"Successfully loaded {len(self.rmm_list)} YAML file(s)")
    
    def _build_simplified_list(self) -> None:
        """
        Build a simplified list of RMM data containing only executables, domains, ports, and meta.
        
        Each item in rmm_simplified_list contains:
        - executables: dict with Linux, MacOS, Windows keys only
        - domains: list from NetConn.Domains
        - ports: list from NetConn.Ports
        - meta: dict with id (from Meta.ID) and name (from 'name' attribute in rmm_list)
        """
        self.rmm_simplified_list.clear()
        
        for rmm in self.rmm_list:
            simplified = {}
            
            # Extract executables (only Linux, MacOS, Windows)
            if 'Executables' in rmm:
                executables = {}
                for platform in ['Linux', 'MacOS', 'Windows']:
                    if platform in rmm['Executables']:
                        platform_data = rmm['Executables'][platform]
                        if platform_data is not None:
                            executables[platform] = platform_data
                if executables:
                    simplified['executables'] = executables
            
            # Extract domains
            if 'NetConn' in rmm and 'Domains' in rmm['NetConn']:
                domains = rmm['NetConn']['Domains']
                if domains is not None:
                    simplified['domains'] = domains
            
            # Extract ports
            if 'NetConn' in rmm and 'Ports' in rmm['NetConn']:
                ports = rmm['NetConn']['Ports']
                if ports is not None:
                    simplified['ports'] = ports
            
            # Extract meta (id and name)
            meta = {}
            if 'Meta' in rmm and 'ID' in rmm['Meta']:
                meta['id'] = rmm['Meta']['ID']
            
            # Get name from 'name' attribute (which is filename stem)
            if 'name' in rmm:
                meta['name'] = rmm['name']
            elif 'Meta' in rmm and 'Description' in rmm['Meta']:
                # Fallback to description if name not available
                meta['name'] = rmm['Meta']['Description']
            
            if meta:
                simplified['meta'] = meta
            
            self.rmm_simplified_list.append(simplified)
        
        logger.debug(f"Built simplified list with {len(self.rmm_simplified_list)} entries")
    
    def reload(self) -> None:
        """
        Reload YAML files from the directory, clearing the current lists.
        
        Useful if YAML files have been updated and you want to refresh the data.
        """
        logger.info("Reloading YAML files...")
        self.rmm_list.clear()
        self.rmm_simplified_list.clear()
        self._load_files()
        self._build_simplified_list()
    
    def get_full_details_by_name_or_id(self, name: str) -> Optional[dict[str, Any]]:
        """
        Find an RMM dictionary by its name or Meta ID.
        
        :param name: Name to search for (name attribute or Meta ID)
        :type name: str
        :return: Dictionary matching the name, or None if not found
        :rtype: Optional[dict[str, Any]]
        """
        for rmm in self.rmm_list:
            # Check name attribute
            if 'name' in rmm:
                if rmm['name'].lower() == name.lower():
                    return rmm
            
            # Check Meta ID
            if 'Meta' in rmm and 'ID' in rmm['Meta']:
                if rmm['Meta']['ID'].lower() == name.lower():
                    return rmm
        
        return None
    
    def get_all_domains(self) -> list[str]:
        """
        Extract all unique domains from all RMM dictionaries.
        
        :return: List of unique domain strings
        :rtype: list[str]
        """
        domains = set()
        
        for rmm in self.rmm_list:
            if 'NetConn' in rmm and 'Domains' in rmm['NetConn']:
                domain_list = rmm['NetConn']['Domains']
                if domain_list is not None:
                    domains.update(domain_list)
        
        return sorted(list(domains))
    
    def get_all_ports(self) -> list[int]:
        """
        Extract all unique ports from all RMM dictionaries.
        
        :return: List of unique port integers
        :rtype: list[int]
        """
        ports = set()
        
        for rmm in self.rmm_list:
            if 'NetConn' in rmm and 'Ports' in rmm['NetConn']:
                port_list = rmm['NetConn']['Ports']
                if port_list is not None:
                    ports.update(port_list)
        
        return sorted(list(ports))
    
    def __len__(self) -> int:
        """Return the number of loaded RMM entries."""
        return len(self.rmm_list)
    
    def __iter__(self):
        """Allow iteration over RMM entries."""
        return iter(self.rmm_list)
    
    def __getitem__(self, index: int) -> dict[str, Any]:
        """Allow indexing into RMM list."""
        return self.rmm_list[index]


def to_json_serializable(rmm_obj: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a YAML object from rmm_list or rmm_simplified_list to a JSON-serializable dictionary.
    
    Recursively processes the dictionary and converts any non-serializable attribute values
    to strings. This ensures the returned dictionary can be safely serialized to JSON.
    
    Handles the following non-serializable types:
    - Sets: converted to sorted lists
    - Tuples: converted to lists
    - Path objects: converted to string representation
    - Other non-serializable objects: converted to string representation
    
    :param rmm_obj: YAML object dictionary from rmm_list or rmm_simplified_list
    :type rmm_obj: dict[str, Any]
    :return: New dictionary that is JSON-serializable
    :rtype: dict[str, Any]
    
    Example:
        rmm_data = load_yaml_files(Path("RMMs"))
        rmm = rmm_data.rmm_list[0]
        json_ready = to_json_serializable(rmm)
        json_str = json.dumps(json_ready)  # Now safe to serialize
    """
    def convert_value(value: Any) -> Any:
        """
        Recursively convert a value to a JSON-serializable type.
        
        :param value: Value to convert
        :type value: Any
        :return: JSON-serializable value
        :rtype: Any
        """
        # Handle None
        if value is None:
            return None
        
        # Handle basic JSON-serializable types
        if isinstance(value, (str, int, float, bool)):
            return value
        
        # Handle dictionaries - recurse
        if isinstance(value, dict):
            return {str(k): convert_value(v) for k, v in value.items()}
        
        # Handle lists and tuples - recurse
        if isinstance(value, (list, tuple)):
            return [convert_value(item) for item in value]
        
        # Handle sets - convert to sorted list
        if isinstance(value, set):
            try:
                # Try to sort if elements are comparable
                return sorted([convert_value(item) for item in value])
            except TypeError:
                # If not sortable, just convert to list
                return [convert_value(item) for item in value]
        
        # Handle Path objects
        if isinstance(value, Path):
            return str(value)
        
        # For any other type, convert to string
        try:
            # Try to get a meaningful string representation
            return str(value)
        except Exception:
            # Fallback if string conversion fails
            return repr(value)
    
    # Validate input
    if not isinstance(rmm_obj, dict):
        raise TypeError(f"Expected dict, got {type(rmm_obj).__name__}")
    
    # Convert the entire dictionary
    result = convert_value(rmm_obj)
    
    # Ensure result is a dict (should always be, but validate for safety)
    if not isinstance(result, dict):
        raise ValueError("Conversion resulted in non-dict type")
    
    return result


def load_yaml_files(rmms_dir: Path, include_filename: bool = True) -> RMMData:
    """
    Read all YAML files from a target directory and return an RMMData instance.
    
    This function creates and returns an RMMData instance containing the loaded YAML data.
    
    :param rmms_dir: Path to the directory containing YAML files
    :type rmms_dir: Path
    :param include_filename: Whether to include the name in each dictionary
                           (added as 'name' key, using filename stem). Defaults to True.
    :type include_filename: bool
    :return: RMMData instance containing loaded YAML data
    :rtype: RMMData
    :raises FileNotFoundError: If the target directory does not exist
    :raises ValueError: If the directory exists but contains no YAML files
    """
    return RMMData(rmms_dir, include_filename)
