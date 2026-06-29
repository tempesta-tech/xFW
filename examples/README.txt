	Tempesta xFW Configuration Examples
	===================================

Reference the description for DNS and HTTP protection use cases at:

  https://tempesta-tech.com/tempesta-escudo/knowledge-base/DDoS-Protection-Use-Cases/


Main xFW configuration
----------------------

xfw-skb-host.json - host mode with XDP skb (higher compatibility)

xfw-native-gate.json - gate mode with XDP native (higher performance)

xfw_logger.json - Tempesta Logger configuration for Tempesta xFW events logging in
                  ClickHouse


Filtration Rules
----------------

xfw-http-rules.conf - filtration rules for HTTP services in host mode

xfw-dns-rules.conf - filtration rules for a DNS server in gate mode
