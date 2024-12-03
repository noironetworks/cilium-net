# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [standalone-dns-proxy/standalone-dns-proxy.proto](#standalone-dns-proxy_standalone-dns-proxy-proto)
    - [DNSPolicies](#standalonednsproxy-DNSPolicies)
    - [DNSPolicy](#standalonednsproxy-DNSPolicy)
    - [DNSPolicyResponse](#standalonednsproxy-DNSPolicyResponse)
    - [DNSServer](#standalonednsproxy-DNSServer)
    - [FQDNMapping](#standalonednsproxy-FQDNMapping)
    - [UpdateMappingResponse](#standalonednsproxy-UpdateMappingResponse)
  
    - [ResponseCode](#standalonednsproxy-ResponseCode)
  
    - [FQDNData](#standalonednsproxy-FQDNData)
  
- [Scalar Value Types](#scalar-value-types)



<a name="standalone-dns-proxy_standalone-dns-proxy-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## standalone-dns-proxy/standalone-dns-proxy.proto



<a name="standalonednsproxy-DNSPolicies"></a>

### DNSPolicies
L7 DNS policy snapshot for all endpoints.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| egress_l7_dns_policy | [DNSPolicy](#standalonednsproxy-DNSPolicy) | repeated |  |
| request_id | [string](#string) |  | Random UUID based identifier which will be referenced in ACKs |






<a name="standalonednsproxy-DNSPolicy"></a>

### DNSPolicy
L7 DNS policy specifying which requests are permitted to which DNS server


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source_identity | [uint32](#uint32) |  | Identity of the workload this L7 DNS policy should apply to |
| dns_pattern | [string](#string) | repeated | Allowed DNS pattern this identity is allowed to resolve. |
| dns_servers | [DNSServer](#standalonednsproxy-DNSServer) | repeated | List of DNS servers to be allowed to |






<a name="standalonednsproxy-DNSPolicyResponse"></a>

### DNSPolicyResponse
Ack sent from SDP to Agent on processing DNS policy rules


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| response | [ResponseCode](#standalonednsproxy-ResponseCode) |  |  |
| request_id | [string](#string) |  | Request ID for which response is sent to |






<a name="standalonednsproxy-DNSServer"></a>

### DNSServer
DNServer identity, port and protocol the requests be allowed to


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| dns_server_identity | [uint32](#uint32) |  | Identity of destination DNS server |
| dns_server_port | [uint32](#uint32) |  |  |
| dns_server_proto | [uint32](#uint32) |  |  |






<a name="standalonednsproxy-FQDNMapping"></a>

### FQDNMapping
FQDN-IP mapping goalstate sent from SDP to agent


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| fqdn | [string](#string) |  | dns name |
| record_ip | [bytes](#bytes) | repeated | List of IPs corresponding to dns name |
| ttl | [uint32](#uint32) |  | TTL of DNS record |
| source_identity | [uint32](#uint32) |  | Identity of the client making the DNS request |
| source_ip | [bytes](#bytes) |  | IP address of the client making the DNS request |
| response_code | [uint32](#uint32) |  | DNS Response code as specified in RFC2316 |






<a name="standalonednsproxy-UpdateMappingResponse"></a>

### UpdateMappingResponse
Ack returned by cilium agent to SDP on receiving FQDN-IP mapping update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| response | [ResponseCode](#standalonednsproxy-ResponseCode) |  |  |





 


<a name="standalonednsproxy-ResponseCode"></a>

### ResponseCode
Response code returned by RPC methods.

| Name | Number | Description |
| ---- | ------ | ----------- |
| RESPONSE_CODE_UNSPECIFIED | 0 |  |
| RESPONSE_CODE_NO_ERROR | 1 |  |
| RESPONSE_CODE_FORMAT_ERROR | 2 |  |
| RESPONSE_CODE_SERVER_FAILURE | 3 |  |
| RESPONSE_CODE_NOT_IMPLEMENTED | 4 |  |
| RESPONSE_CODE_REFUSED | 5 |  |


 

 


<a name="standalonednsproxy-FQDNData"></a>

### FQDNData
Cilium agent runs the FQDNData service and Standalone DNS proxy connects to it to get the DNS Policy rules.
Standalone DNS proxy sends FQDN-IP mapping updates to Cilium Agent.
CFP: https://github.com/cilium/design-cfps/pull/54

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| SubscribeToDNSPolicies | [DNSPolicyResponse](#standalonednsproxy-DNSPolicyResponse) stream | [DNSPolicy](#standalonednsproxy-DNSPolicy) stream | SubscribeToDNSPolicies is used by the Standalone DNS proxy to subscribe to DNS policy rules. Cilium agent will stream DNS policies to Standalone DNS proxy. In case of any client side error, cilium agent will cancel the stream and SDP will have to re-subscribe. In case of any server side error, cilium agent will send an error response and SDP will have to re-subscribe. |
| UpdateMappingRequest | [FQDNMapping](#standalonednsproxy-FQDNMapping) | [UpdateMappingResponse](#standalonednsproxy-UpdateMappingResponse) | UpdateMappingRequest is used by the Standalone DNS proxy to update ciliium agent with FQDN-IP mappings which in turn update L3/L4 policy maps. In case of any error, SDP will either retry the connection if the error is server side or will error out. Note: In case of concurrent updates, since this is called in a callback(notifyDNSMsg) from the DNS server it follows the same behavior as the inbuilt dns proxy in cilium. |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

