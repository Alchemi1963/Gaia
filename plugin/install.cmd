@echo off

scp contrib/openldap/* root@fusion:/etc/ldap/schema/fusiondirectory/
scp -r locale/* root@fusion:/usr/share/fusiondirectory/locale/plugins
scp -r personal/* root@fusion:/usr/share/fusiondirectory/plugins/personal

ssh root@fusion "fusiondirectory-setup --update-cache; fusiondirectory-insert-schema -i /etc/ldap/schema/fusiondirectory/bolkdata-fd.schema -o \"-H ldap://ldap -D 'cn=admin,cn=config' -w openLDAP2023! -x\"; fusiondirectory-insert-schema -i /etc/ldap/schema/fusiondirectory/bolkdata-avg-fd.schema -o \"-H ldap://ldap -D 'cn=admin,cn=config' -w openLDAP2023! -x\""
pause