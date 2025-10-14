"""Dynamic AWS service model loader from botocore."""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional
from functools import lru_cache


class ServiceModelLoader:
    """Load AWS service models dynamically from botocore data files."""

    def __init__(self):
        self.botocore_data_path: Optional[Path] = None
        self._service_cache: Dict[str, dict] = {}
        self._find_botocore_path()

    def _find_botocore_path(self) -> None:
        """Find botocore data directory by checking common locations."""
        possible_paths = []

        # Try to import botocore and get its path
        try:
            import botocore

            botocore_module_path = Path(botocore.__file__).parent
            possible_paths.append(botocore_module_path / "data")
        except ImportError:
            pass

        # Check AWS CLI v2 bundled botocore (Homebrew on macOS)
        if sys.platform == "darwin":
            homebrew_paths = [
                Path("/opt/homebrew/Cellar/awscli"),
                Path("/usr/local/Cellar/awscli"),
            ]
            for base_path in homebrew_paths:
                if base_path.exists():
                    for version_dir in base_path.glob(
                        "*/libexec/lib/python*/site-packages/awscli/botocore/data"
                    ):
                        possible_paths.append(version_dir)

        # Check common Linux installation paths
        if sys.platform.startswith("linux"):
            linux_paths = [
                Path("/usr/local/aws-cli/v2/current/dist/awscli/botocore/data"),
                Path("/usr/lib/python*/site-packages/botocore/data"),
            ]
            for pattern in linux_paths:
                for path in Path("/").glob(str(pattern).lstrip("/")):
                    possible_paths.append(path)

        # Check user's site-packages
        try:
            import site

            for site_dir in site.getsitepackages():
                possible_paths.append(Path(site_dir) / "botocore" / "data")
                possible_paths.append(Path(site_dir) / "awscli" / "botocore" / "data")
        except Exception:
            pass

        # Find the first valid path
        for path in possible_paths:
            if path.exists() and (path / "ec2").exists():
                self.botocore_data_path = path
                return

        # Fallback: assume botocore is not available
        self.botocore_data_path = None

    def is_available(self) -> bool:
        """Check if botocore data is available."""
        return self.botocore_data_path is not None

    @lru_cache(maxsize=512)
    def get_all_services(self) -> List[str]:
        """Get list of all available AWS services."""
        if not self.botocore_data_path:
            return []

        services = []
        for service_dir in self.botocore_data_path.iterdir():
            if service_dir.is_dir() and not service_dir.name.startswith("."):
                services.append(service_dir.name)

        return sorted(services)

    def _load_service_model(self, service: str) -> Optional[dict]:
        """Load service-2.json for a given service."""
        if not self.botocore_data_path:
            return None

        if service in self._service_cache:
            return self._service_cache[service]

        service_path = self.botocore_data_path / service
        if not service_path.exists():
            return None

        # Find the latest version directory
        version_dirs = [d for d in service_path.iterdir() if d.is_dir()]
        if not version_dirs:
            return None

        # Use the first (usually only) version
        version_dir = version_dirs[0]
        service_file = version_dir / "service-2.json"

        if not service_file.exists():
            return None

        try:
            with open(service_file, "r", encoding="utf-8") as f:
                model = json.load(f)
                self._service_cache[service] = model
                return model
        except (json.JSONDecodeError, IOError):
            return None

    @staticmethod
    def _camel_to_kebab(name: str) -> str:
        """Convert CamelCase to kebab-case."""
        # Insert hyphen before uppercase letters (except at start)
        s1 = re.sub("(.)([A-Z][a-z]+)", r"\1-\2", name)
        # Insert hyphen before uppercase letters followed by lowercase
        s2 = re.sub("([a-z0-9])([A-Z])", r"\1-\2", s1)
        return s2.lower()

    @lru_cache(maxsize=512)
    def get_service_operations(self, service: str) -> List[str]:
        """Get all operations (commands) for a service in kebab-case."""
        model = self._load_service_model(service)
        if not model or "operations" not in model:
            return []

        operations = model["operations"].keys()
        # Convert CamelCase to kebab-case for CLI
        return sorted([self._camel_to_kebab(op) for op in operations])

    @lru_cache(maxsize=1024)
    def get_operation_parameters(self, service: str, operation: str) -> List[str]:
        """Get parameters for a specific operation."""
        model = self._load_service_model(service)
        if not model or "operations" not in model:
            return []

        # Convert kebab-case back to CamelCase to find in model
        operation_camel = "".join(word.capitalize() for word in operation.split("-"))

        if operation_camel not in model["operations"]:
            return []

        operation_def = model["operations"][operation_camel]
        if "input" not in operation_def:
            return []

        input_shape_name = operation_def["input"].get("shape")
        if not input_shape_name or "shapes" not in model:
            return []

        input_shape = model["shapes"].get(input_shape_name, {})
        members = input_shape.get("members", {})

        # Convert member names to CLI parameter format (--parameter-name)
        parameters = []
        for member_name in members.keys():
            param_name = self._camel_to_kebab(member_name)
            parameters.append(f"--{param_name}")

        return sorted(parameters)

    def get_service_metadata(self, service: str) -> Optional[dict]:
        """Get service metadata (name, description, etc.)."""
        model = self._load_service_model(service)
        if not model:
            return None

        return model.get("metadata", {})


# Global singleton instance
_loader_instance: Optional[ServiceModelLoader] = None


def get_service_loader() -> ServiceModelLoader:
    """Get or create the global ServiceModelLoader instance."""
    global _loader_instance
    if _loader_instance is None:
        _loader_instance = ServiceModelLoader()
    return _loader_instance
