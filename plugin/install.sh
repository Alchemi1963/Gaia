#!/bin/bash


scp -r admin/* root@10.99.1.102:/usr/share/fusiondirectory/plugins/admin
scp contrib/openldap/* root@10.99.1.102:/etc/ldap/schema/fusiondirectory/
scp -r locale/* root@10.99.1.102:/usr/share/fusiondirectory/locale/plugins
scp -r personal/* root@10.99.1.102:/usr/share/fusiondirectory/plugins/personal

insert="fusiondirectory-schema-manager --ldapuri ldap://10.99.1.101 --binddn cn=admin,cn=config --bindpwd WOWgeenGOSA2022! --simplebind --replace-schema"

ssh root@10.99.1.102 "fusiondirectory-configuration-manager --update-cache; ${insert} /etc/ldap/schema/fusiondirectory/bolkdata-fd.schema; ${insert} /etc/ldap/schema/fusiondirectory/bolkdata-avg-fd.schema; ${insert} /etc/ldap/schema/fusiondirectory/bolkdata-mail-fd.schema"
