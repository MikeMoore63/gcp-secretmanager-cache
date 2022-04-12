# -*- coding: utf-8 -*-

"""
Some frameworks for handling secrets.

Designed to support variou secret patterns

add new reap old - At rotation period past last secret adds new secret. But has a means of knowing
                   deleting secrets over rotation period + buffer time old.
blue green       - 2 logical secrets exist blue,green if blue is active the grean secret is
                   updated becomes active blue rotation time later  time later blue is updated
                   becomes active
master manager   - In this strategy a master secret allows access to a resource and is given an
                   user account to update a secret for. The secret may or may not have an expiry time.
change own       - In this the secret being changes is sued as a means to connect to a service to
                   update.

This assumes all secrets are in json of format. They are expected to be utf-8 encoded
as per the json specification.

{
    "secret_type": "enum (Secret Type)",
    "username": "string" , # A user name null if user name is not required
    "password": "string",  # A password null or not set  if not required
    "key":      "string",  # A key of some kind i.e. private key, api key
    "change_data": {       # a map used to help provide properties needed to manage the secret type
       string : value      # that a secret changer can use to manage the rotation so for example
       ...                 # a database might need some form of connection string
                           # an api key the restrictions expected
    }
}
"""


class BootStrapSecrets:
    pass
