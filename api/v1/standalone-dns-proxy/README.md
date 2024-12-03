# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [standalone-dns-proxy/standalone-dns-proxy.proto](#standalone-dns-proxy_standalone-dns-proxy-proto)
    - [DNSPolicies](#standalonednsproxy-DNSPolicies)
    - [DNSPoliciesResult](#standalonednsproxy-DNSPoliciesResult)
    - [DNSPolicy](#standalonednsproxy-DNSPolicy)
    - [DNSResponseData](#standalonednsproxy-DNSResponseData)
    - [DNSServer](#standalonednsproxy-DNSServer)
    - [FQDNMapping](#standalonednsproxy-FQDNMapping)
    - [UpdatesMappingsResult](#standalonednsproxy-UpdatesMappingsResult)
  
    - [FQDNData](#standalonednsproxy-FQDNData)
  
- [Scalar Value Types](#scalar-value-types)



<a name="standalone-dns-proxy_standalone-dns-proxy-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## standalone-dns-proxy/standalone-dns-proxy.proto



<a name="standalonednsproxy-DNSPolicies"></a>

### DNSPolicies



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| egress_l7_dns_policy | [DNSPolicy](#standalonednsproxy-DNSPolicy) | repeated |  |
| request_id | [string](#string) |  | Random UUID based identifier which will be referenced in ACKs |






<a name="standalonednsproxy-DNSPoliciesResult"></a>

### DNSPoliciesResult



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| success | [bool](#bool) |  |  |
| request_id | [string](#string) |  |  |






<a name="standalonednsproxy-DNSPolicy"></a>

### DNSPolicy



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source_identity | [uint32](#uint32) |  | Identity of the workload this L7 DNS policy should apply to |
| dns_pattern | [string](#string) | repeated | Allowed DNS pattern this identity is allowed to resolve. |
| dns_servers | [DNSServer](#standalonednsproxy-DNSServer) | repeated |  |






<a name="standalonednsproxy-DNSResponseData"></a>

### DNSResponseData



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| response | [bool](#bool) |  |  |
| cnames | [string](#string) | repeated |  |
| qtypes | [uint32](#uint32) | repeated |  |
| answer_times | [uint32](#uint32) | repeated |  |






<a name="standalonednsproxy-DNSServer"></a>

### DNSServer



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| dns_server_identity | [uint32](#uint32) |  | Identity of destination DNS server |
| dns_server_port | [uint32](#uint32) |  |  |
| dns_server_proto | [uint32](#uint32) |  |  |






<a name="standalonednsproxy-FQDNMapping"></a>

### FQDNMapping



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| FQDN | [string](#string) |  |  |
| IPS | [bytes](#bytes) | repeated |  |
| TTL | [uint32](#uint32) |  |  |
| source_identity | [uint32](#uint32) |  | Identity of the client making the DNS request |
| source_ip | [bytes](#bytes) |  | IP address of the client making the DNS request |
| response_code | [uint32](#uint32) |  |  |






<a name="standalonednsproxy-UpdatesMappingsResult"></a>

### UpdatesMappingsResult



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| success | [bool](#bool) |  |  |





 

 

 


<a name="standalonednsproxy-FQDNData"></a>

### FQDNData


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| SubscribeToDNSPolicies | [DNSPoliciesResult](#standalonednsproxy-DNSPoliciesResult) stream | [DNSPolicies](#standalonednsproxy-DNSPolicies) stream |  |
| UpdatesMappings | [FQDNMapping](#standalonednsproxy-FQDNMapping) | [UpdatesMappingsResult](#standalonednsproxy-UpdatesMappingsResult) |  |

 



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

