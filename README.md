# Logstash Input Fluent Secure Forward

This is a Java plugin for [Logstash](https://github.com/elastic/logstash) for accepting messages from fluentd secure_forward output.

It is fully free and fully open source. The license is Apache 2.0, meaning you are free to use it however you want.

Messages should come in the form of a MessagePack.

This plugin is largely based on [tagomoris/fluent-plugin-secure-forward](https://github.com/tagomoris/fluent-plugin-secure-forward)

## Building
Follow instructions [here](https://www.elastic.co/guide/en/logstash/7.2/java-input-plugin.html).

## Installing
Download the latest gem from the release page and install
```bash
bin/logstash-plugin install --no-verify --local logstash-input-fluent_secure_forward-1.0.0.gem
```

## Configuration

Every default input option (besides codec) is accepted.
Plugin also has builtin multiline support for joining multiple messages

| Key  | Type  | Description | Default | 
| -----|-------|-------------|-------- |
| host | String | Hostname to listen on | 0.0.0.0 |
| port | String | Port to listen on | 24284 |
| shared_key | String | A shared key that must match between fluentd outputs and this input. This property is required. |  |
| self_hostname | String | Hostname of server, validated against client.  If using a load balancer, set this to the load balancer name. | auto generated |
| ssl_version | String | SSL version to use | TLSv1.2 |
| ssl_ciphers | String | Space delimited list of ciphers to enable |  |
| ssl_enable | Boolean | Whether to bind as an SSL socket or not | true |
| ssl_cert | String | SSL certificate to use.  Required if ssl_enable |  |
| ssl_key | String | SSL private key.  Required if ssl_enable |  |
| authentication | Boolean | Require a valid username/password | false |
| users | Map | A map of usernames to passwords that can be used to authenticate | {} |
| multiline | Array | An array of multiline configuration | [] |
| multiline.match | Map | A map of fields to regex patterns to use to test whether message should process using this configuration | {} |
| multiline.continue | Boolean | Do not process further multiline configs if this one is used | false |
| multiline.field | String | Target field to join | message |
| multiline.group_key | String | Segment messages into different groups for multiline joining | >>default group<< |
| multiline.line_separator | String | Line separator for message joining | \n |
| multiline.pattern | String | Beginning pattern for new messages, messages not matching this are appended to previous message | .*
| multiline.discard_pattern | String | Discard messages matching this pattern | |
| multiline.inverse_match | Boolean | Inverse pattern | false |
| multiline.timeout | Number | After this amount of time in milliseconds messages are automatically flushed | 5000 |
| multiline.max_messages | Number | After this number is reached, messages are no longer appended, set to 0 for unlimited | 0 |
| multiline.multiline | Array | Nested configuration to send to after buffer is flushed.  In case another field is needed to be joined | [] |

  

Example logstash config: 
```
 inputs {
   fluent_secure_forward {
        host => "0.0.0.0"
        port => "24224"
        ssl_key => "/etc/logstash/key.pem"
        ssl_cert => "/etc/logstash/cert.pem"
        self_hostname => "logstash.company.com"
        shared_key => "secretsharedkey"
        ssl_version => "TLSv1.2"
        authentication => true
        users => { 
            username => "password"              
        } 
        multiline => [{
           group_key => "%{[host][name]}:%{[kubernetes][pod_name]}",
           match => {
             "[kubernetes][pod_name]" => "app1-.*"
           }
           pattern => "\\[.*"
           field => "message"
        }]
   }
 }
```

