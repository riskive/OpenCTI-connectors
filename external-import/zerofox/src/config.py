from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any
from pycti import get_config_variable
import yaml

CONNECTOR_RUN_EVERY = "connector.run_every"
CONNECTOR_FIRST_RUN = "connector.first_run"
CONNECTOR_UPDATE_EXISTING_DATA = "connector.update_existing_data"

ZEROFOX_USERNAME = "zerofox.username"
ZEROFOX_PASSWORD = "zerofox.password"
ZEROFOX_COLLECTORS = "zerofox.collectors"

@dataclass
class ConnectorConfig:
    interval: str
    first_run_interval: str
    update_existing_data: bool
    zerofox_username: str
    zerofox_password: str
    zerofox_collectors: str | None

    def __post_init__(self):
        self._validate_interval("CONNECTOR_RUN_EVERY", self.interval)
        self._validate_interval("CONNECTOR_FIRST_RUN", self.first_run_interval)

    def _validate_interval(self, env_var, interval):
        try:
            unit = interval[-1]
            if unit not in ["d", "h", "m", "s"]:
                raise TypeError
            int(interval[:-1])
        except TypeError as ex:
            msg = (
                f"Error ({ex}) when grabbing {env_var} environment variable: '{interval}'. "
                "It SHOULD be a string in the format '7d', '12h', '10m', '30s' where the final letter "
                "SHOULD be one of 'd', 'h', 'm', 's' standing for day, hour, minute, second respectively. "
            )
            raise ValueError(msg) from ex
        
    @classmethod
    def _get_configuration(
        cls, config: dict[str, Any], config_name: str, default=None, is_number: bool = False
    ) -> Any:
        yaml_path = cls._get_yaml_path(config_name)
        env_var_name = cls._get_environment_variable_name(yaml_path)
        config_value = get_config_variable(
            env_var_name, yaml_path, config, isNumber=is_number
        )
        return config_value

    @staticmethod
    def _get_yaml_path(config_name: str) -> list[str]:
        return config_name.split(".")

    @staticmethod
    def _get_environment_variable_name(yaml_path: list[str]) -> str:
        return "_".join(yaml_path).upper()

        
    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[2].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        return config
        
    @staticmethod
    def get_config():
        load = ConnectorConfig._load_config()
        interval = ConnectorConfig._get_configuration(load, CONNECTOR_RUN_EVERY, "1d").lower()
        first_run_interval = ConnectorConfig._get_configuration(load, CONNECTOR_FIRST_RUN, "1d").lower()
        update_existing_data = ConnectorConfig._get_configuration(load, CONNECTOR_UPDATE_EXISTING_DATA, "false")
        zerofox_username = ConnectorConfig._get_configuration(load, ZEROFOX_USERNAME, "")
        zerofox_password = ConnectorConfig._get_configuration(load, ZEROFOX_PASSWORD, "")
        zerofox_collectors = ConnectorConfig._get_configuration(load, ZEROFOX_COLLECTORS, "")

        return ConnectorConfig(
            interval=interval,
            first_run_interval=first_run_interval,
            update_existing_data=update_existing_data,
            zerofox_username=zerofox_username,
            zerofox_password=zerofox_password,
            zerofox_collectors=zerofox_collectors,
        )
