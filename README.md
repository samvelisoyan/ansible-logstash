logstash
=========

An Ansible Role that installs and configures Logstash

Before deployment of Logstash configuration files under conf.d directory,
we clean up existing files according to current user's owner(not permissions elevation)


Requirements
------------

### Ansible User Prerequisites

Some tasks of this role need to be run as root(thanks to condition 'when ansible_user_id == root')
So, a 'non-root' user just can deploy configuration files under conf.d directory.
Java and Logstash installations and admin settings (conf.d directory path) are reserved by root user.

### Operating Systems support

* Centos 7
* Redhat 7,8


Dependencies
------------

This role automatically can install JAVA (java-1.8.0-openjdk)
You(with good rights) can use 'users' role as a dependency, when it is required to create user accounts used by application (like 'www' user)

Variables
---------

In OPS ui, when you design your application, you have to use the software model(provider: ansible) related to this role
and so you benefited from data form

### Role Variables

| Variables | Required | Default value | Description |
|-----------|----------|---------------|-------------|
| logstash_disable_java18_openjdk_install  | false | *false* | Disabling Java 1.8.0 openjdk package installation (as root user) |
| logstash_jvm_options_heap_min | false | *256M* | JVM options : Xms represents the initial size of total heap space |
| logstash_jvm_options_heap_max | false | *1g* | JVM options : Xmx represents the maximum size of total heap space |
| logstash_disable_install | false | *false* | Will skip packages installation, plugins installation, service managed and directories creation(as root user) |
| logstash_version | false | *7.x*| Major version of Logstash package from elasticsearch repository (https://www.elastic.co/fr/downloads/logstash) (as root user) |
| logstash_install_dir| false | */usr/share/logstash* | Directory inside which Logstash is installed(as root user) |
| logstash_conf_dir| false | */etc/logstash* | Directory inside which Logstash configuration is installed(as root user) |
| logstash_local_syslog_path | false | */var/log/syslog* | Syslog directory path on server(as root user) |
| logstash_enabled_on_boot| false | *true* | enabled systemd service on boot(as root user) |
| logstash_install_plugins | false | *[]* | List of Logstash plugins that should be installed like : logstash-input-beats, logstash-filter-multiline |
| logstash_confd_dir | false | */etc/logstash/conf.d* | Conf.d directory inside which Logstash configuration files are installed(as root user) |
| logstash_confd_file_user | false | *www* | Owner of Logstash configuration files on server |
| logstash_confd_file_group | false| *server* | Group owning Logstash configuration files on server |
| logstash_service_name | false| *logstash* | customized Logstash service name |
| logstash_configuration_files| false | *{}* | Hash with those keys as configuration file names(without or not extension .conf) to install under conf.d directory and with as subkey named 'content' containing lines of file content |

### Role Vars file

By example, I would like to install(as root user) Logstash and set configuration files under `/MIDDLE/logstash/conf.d`, place following content into vars yaml file

```yaml
---

#logstash_version:
#logstash_install_dir:
#logstash_disable_install: true
logstash_disable_java18_openjdk_install: true

# for test in itsm devbox vm
#logstash_disable_http_proxies: true

logstash_jvm_options_heap_min: 256M
logstash_jvm_options_heap_max: 512M
logstash_install_plugins:
    - logstash-input-beats
    - logstash-filter-multiline

logstash_confd_dir: /MIDDLE/logstash/conf.d
logstash_confd_file_user: www
logstash_confd_file_group: server

logstash_configuration_files:
  01-beats-input.conf:
    content: >
      input {
        beats {
          port => 5044
        }
      }
  30-elasticsearch-output.conf:
    content: >
      output {
        elasticsearch {
          hosts => ["http://localhost:9200"]
          index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
        }
      }
  02-local-syslog-input:
    content: >
      input {
        file {
          path => "/var/log/syslog"
        }
      }
  10-syslog-filter:
    content: >
      filter {
        if [type] == "syslog" {
          if [message] =~ /last message repeated [0-9]+ times/ {
            drop { }
          }
          grok {
            match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
            add_field => [ "received_at", "%{@timestamp}" ]
            add_field => [ "received_from", "%{host}" ]
          }
          syslog_pri { }
          date {
            match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
            }
        }
      }
  11-ngnix-filter:
    content: >
      filter {
        if [type] == "nginx" {
          grok {
            match => { "message" => "%{COMBINEDAPACHELOG}" }
          }
        }
      }
  11-apache-filter:
    content: >
      filter {
        if [type] == "apache" {
            grok {
              match => { "message" => "%{COMBINEDAPACHELOG}"}
            }
            date {
              match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
            }
        }
      }

```

This definition data produces :

```
[root@centos7 /MIDDLE/logstash/conf.d ]$ status_service -a

Checking service logstash
        Checking resource systemd@logstash       [STOPPED]

[root@centos7 / ]$ cd /MIDDLE/logstash/conf.d/
[root@centos7 /MIDDLE/logstash/conf.d ]$ ls -lrt
total 24
-rw-r--r-- 1 www server  41 Apr  9 13:02 01-beats-input.conf
-rw-r--r-- 1 www server 123 Apr  9 13:02 30-elasticsearch-output.conf
-rw-r--r-- 1 www server  53 Apr  9 13:02 02-local-syslog-input.conf
-rw-r--r-- 1 www server 538 Apr  9 13:02 10-syslog-filter.conf
-rw-r--r-- 1 www server 112 Apr  9 13:02 11-ngnix-filter.conf
-rw-r--r-- 1 www server 198 Apr  9 13:02 11-apache-filter.conf

[root@centos7 /MIDDLE/logstash/conf.d ]$ cat 01-beats-input.conf
input {
  beats {
    port => 5044
  }
}

[root@centos7 /etc/logstash ]$ cat jvm.options
## JVM configuration

# Xms represents the initial size of total heap space
# Xmx represents the maximum size of total heap space
# the heap to 1 GB, set:
#
#-Xms1g
#-Xmx1g

-Xms256M
-Xmx512M

../..

[root@centos7 /etc/logstash ]$ cat pipelines.yml
# This file is where you define your pipelines. You can define multiple.
# For more information on multiple pipelines, see the documentation:
#   https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
  path.config: "/MIDDLE/logstash/conf.d/*.conf"


[root@centos7 /etc/logstash ]$ /usr/share/logstash/bin/logstash-plugin list
Using bundled JDK: /usr/share/logstash/jdk
../..
logstash-filter-multiline*
logstash-input-beats*
../..

```

Example Playbook
----------------

Including an example of how to use your role :
```yaml
---
    - hosts: servers
      vars_files:
        - vars_file.yml
      roles:
        - role: logstash
```

Tests
-----

The tests were done by using molecule integration test(inspec)
[More info](molecule-README.md#Requirements)

License
-------

BSD

Author Information
------------------
samvelisoyan@hotmail.com
