
import ta_thehive_create_alert_declare

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    DataInputModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunk_aoblib.rest_migration import ConfigMigrationHandler

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        'interval',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.Pattern(
            regex=r"""^\-[1-9]\d*$|^\d*$""", 
        )
    ), 
    field.RestField(
        'index',
        required=True,
        encrypted=False,
        default='default',
        validator=validator.String(
            max_len=80, 
            min_len=1, 
        )
    ), 
    field.RestField(
        'thehive_url',
        required=True,
        encrypted=False,
        default='http://hive.example.com/',
        validator=validator.String(
            max_len=8192, 
            min_len=0, 
        )
    ), 
    field.RestField(
        'thehive_key',
        required=False,
        encrypted=True,
        default='***API*KEY***',
        validator=validator.String(
            max_len=8192, 
            min_len=0, 
        )
    ), 
    field.RestField(
        'thehive_verifycert',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'thehive_use_proxy',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'client_use_cert',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'client_cert_full_path',
        required=False,
        encrypted=False,
        default=None,
        validator=validator.String(
            max_len=8192, 
            min_len=0, 
        )
    ), 

    field.RestField(
        'disabled',
        required=False,
        validator=None
    )

]
model = RestModel(fields, name=None)



endpoint = DataInputModel(
    'connector_to_thehive_instance',
    model,
)


if __name__ == '__main__':
    admin_external.handle(
        endpoint,
        handler=ConfigMigrationHandler,
    )
