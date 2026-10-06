/**
 * The picker's browse list: software that actually shows up on servers and in company inventories, in the product
 * names the CVE data uses. It is a shortlist only; anything else is still found by typing. Names missing from the
 * CVE data (or with fewer than MIN_CVES records) are skipped when the list is built, so it never offers a dead end.
 */
export const MIN_CVES = 5;

export const COMMON_SOFTWARE: { group: string; products: string[] }[] = [
  { group: 'web', products: ['nginx', 'http_server', 'tomcat', 'internet_information_services', 'lighttpd', 'caddy', 'haproxy', 'traefik', 'squid', 'varnish', 'jetty', 'undertow'] },
  {
    group: 'runtime',
    products: ['php', 'python', 'node.js', 'openjdk', 'jre', 'jdk', 'ruby', 'perl', 'go', '.net_framework', '.net', 'asp.net_core', 'spring_framework', 'spring_boot', 'django', 'laravel', 'rails', 'struts', 'log4j', 'jackson-databind'],
  },
  { group: 'db', products: ['mysql', 'mariadb', 'postgresql', 'mongodb', 'redis', 'sql_server', 'database_server', 'sqlite', 'elasticsearch', 'opensearch', 'cassandra', 'couchdb', 'memcached', 'clickhouse', 'neo4j'] },
  {
    group: 'os',
    products: ['ubuntu_linux', 'debian_linux', 'enterprise_linux', 'linux_enterprise_server', 'almalinux', 'windows_server_2012', 'windows_server_2016', 'windows_server_2019', 'windows_server_2022', 'windows_server_2025', 'macos', 'freebsd', 'openbsd', 'netbsd', 'solaris', 'aix'],
  },
  {
    group: 'tools',
    products: ['openssh', 'openssl', 'gnutls', 'libssh', 'libssh2', 'sudo', 'bash', 'glibc', 'curl', 'libcurl', 'zlib', 'libxml2', 'libpng', 'libwebp', 'libtiff', 'libjpeg-turbo', 'xz', 'git', 'wget', 'vim', 'polkit', 'systemd', 'openldap', 'nss', 'ghostscript', 'samba', 'cups', 'imagemagick', 'ffmpeg', 'wireshark', 'libreoffice', '7-zip', 'winrar', 'putty', 'teamviewer', 'anydesk'],
  },
  { group: 'virt', products: ['esxi', 'vcenter_server', 'vm_virtualbox', 'qemu', 'xen', 'libvirt', 'openstack', 'docker', 'kubernetes', 'containerd', 'runc', 'podman'] },
  {
    group: 'devops',
    products: ['jenkins', 'gitlab', 'gitea', 'teamcity', 'bamboo', 'ansible', 'terraform', 'argo_cd', 'harbor', 'vault', 'consul', 'nomad', 'nexus_repository_manager', 'artifactory', 'sonarqube', 'grafana', 'prometheus', 'kibana', 'logstash', 'zabbix', 'nagios', 'cacti', 'rsyslog'],
  },
  {
    group: 'network',
    products: ['fortios', 'fortiproxy', 'pan-os', 'junos', 'ios_xe', 'nx-os', 'adaptive_security_appliance', 'sonicos', 'netscaler_application_delivery_controller', 'big-ip_local_traffic_manager', 'connect_secure', 'routeros', 'pfsense', 'opnsense', 'openvpn', 'openvpn_access_server', 'strongswan'],
  },
  {
    group: 'apps',
    products: ['wordpress', 'drupal', 'joomla', 'magento', 'prestashop', 'opencart', 'typo3', 'moodle', 'mediawiki', 'redmine', 'bugzilla', 'jira', 'jira_server', 'confluence_server', 'confluence_data_center', 'nextcloud', 'owncloud', 'phpmyadmin', 'mattermost_server', 'exchange_server', 'sharepoint_server'],
  },
  { group: 'messaging', products: ['rabbitmq', 'activemq', 'kafka', 'zookeeper', 'nats-server', 'mosquitto', 'postfix', 'exim', 'dovecot', 'sendmail', 'bind', 'unbound', 'dnsmasq', 'powerdns', 'coredns', 'proftpd', 'vsftpd'] },
  { group: 'bigdata', products: ['hadoop', 'solr'] },
];
