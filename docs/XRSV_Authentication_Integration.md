# XRSV Authentication Integration

## Overview

The XRSV (VREX Speech Request) component integrates with the authentication infrastructure provided by the underlying XRSR (Speech Router) layer. Rather than implementing authentication directly, XRSV components act as consumers of authenticated connections established and managed by XRSR. This design provides a clean separation between protocol-level authentication concerns and voice service implementation logic.

## Architecture

### Authentication Layer Separation
```
Application Layer
       ↓ (Authentication Configuration)
XRSR Protocol Layer (Authentication, Certificates, Tokens)
       ↓ (Authenticated Connections)
XRSV Voice Service Layer (Business Logic on Secure Connections)
       ↓ (Secure Voice Services)  
Voice Service Endpoints
```

### Component Responsibilities

#### XRSR Layer (Authentication Provider)
- **Certificate Management**: PKCS#12, PEM, and X.509 certificate handling
- **Token Authentication**: SAT (Subscriber Authentication Token) management
- **TLS/SSL Configuration**: Secure connection establishment and validation
- **OCSP Verification**: Certificate revocation checking via OCSP protocol
- **Connection Security**: Host verification and certificate validation

#### XRSV Layer (Authentication Consumer)
- **Session Configuration**: Receives authenticated session parameters from XRSR
- **Secure Message Transport**: Utilizes authenticated connections for voice data
- **Configuration Integration**: Passes authentication requirements to XRSR layer
- **Session State Management**: Maintains voice service state over secure connections

## Authentication Methods

### Token-Based Authentication (SAT)

#### SAT Token Integration
```c
// XRSR HTTP session configuration with SAT token
typedef struct {
   const char *sat_token;                    ///< NULL-terminated SAT token string
   const char *user_agent;                   ///< User agent for HTTP requests
   const char *query_strs[XRSR_QUERY_STRING_QTY_MAX + 1]; ///< Query parameters
   // ... other configuration fields
} xrsr_session_config_in_http_t;

// SAT token maximum length
#define XRSR_SAT_TOKEN_LEN_MAX (5120)  ///< Maximum SAT token string length
```

#### HTTP Authentication Implementation (XRSR)
```c
// SAT token header injection in HTTP protocol
if(http->session_config_in.http.sat_token != NULL && 
   http->session_config_in.http.sat_token[0] != '\0') {
    
    snprintf(sat_token_str, sizeof(sat_token_str), 
             "Authorization: Bearer %s", 
             http->session_config_in.http.sat_token);
    
    http->chunk = curl_slist_append(http->chunk, sat_token_str);
}
```

**Features**:
- **Bearer Token Format**: Standard OAuth2/JWT bearer token pattern
- **Automatic Header Injection**: Transparent integration with HTTP protocol stack
- **Token Validation**: Server-side validation ensures session authenticity
- **Flexible Length**: Support for tokens up to 5KB for complex credential structures

### Certificate-Based Authentication

#### Certificate Type Support
```c
typedef enum {
   XRSR_CERT_TYPE_NONE    = 0,  ///< No certificate authentication
   XRSR_CERT_TYPE_P12     = 1,  ///< PKCS#12 certificate bundle
   XRSR_CERT_TYPE_PEM     = 2,  ///< PEM-encoded certificate files
   XRSR_CERT_TYPE_X509    = 3,  ///< In-memory X.509 certificate objects
   XRSR_CERT_TYPE_INVALID = 4   ///< Invalid certificate type
} xrsr_cert_type_t;
```

#### PKCS#12 Certificate Configuration
```c
typedef struct {
   const char *filename;    ///< PKCS#12 bundle file path
   const char *passphrase;  ///< Decryption passphrase
} xrsr_cert_p12_t;

// PKCS#12 certificate setup (XRSR implementation)
if(config_in->client_cert.type == XRSR_CERT_TYPE_P12) {
    xrsr_cert_p12_t *cert_p12 = &config_in->client_cert.cert.p12;
    
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLCERTTYPE, "P12");
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLCERT, cert_p12->filename);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_KEYPASSWD, cert_p12->passphrase);
}
```

#### PEM Certificate Configuration
```c
typedef struct {
   const char *filename_cert;   ///< Certificate file path
   const char *filename_pkey;   ///< Private key file path  
   const char *filename_chain;  ///< Certificate chain file path
   const char *passphrase;      ///< Private key passphrase
} xrsr_cert_pem_t;

// PEM certificate setup (XRSR implementation)
if(config_in->client_cert.type == XRSR_CERT_TYPE_PEM) {
    xrsr_cert_pem_t *cert_pem = &config_in->client_cert.cert.pem;
    
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLCERTTYPE, "PEM");
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLCERT,   cert_pem->filename_cert);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSLKEY,    cert_pem->filename_pkey);
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_KEYPASSWD, cert_pem->passphrase);
    
    if(cert_pem->filename_chain != NULL) {
        CURL_EASY_SETOPT(http->easy_handle, CURLOPT_CAINFO, cert_pem->filename_chain);
    }
}
```

#### X.509 In-Memory Certificate Objects
```c
typedef struct {
   X509 *          x509;   ///< Certificate object
   EVP_PKEY *      pkey;   ///< Private key object
   STACK_OF(X509) *chain;  ///< Certificate chain stack
} xrsr_cert_x509_t;
```

**Features**:
- **Memory Management**: Direct OpenSSL object integration
- **Performance**: Eliminates file I/O during connection establishment
- **Dynamic Certificates**: Runtime certificate generation and injection
- **Chain Support**: Full certificate chain validation

#### Unified Certificate Structure
```c
typedef struct {
   xrsr_cert_type_t type;  ///< Certificate format type
   union {
      xrsr_cert_p12_t  p12;    ///< PKCS#12 configuration
      xrsr_cert_pem_t  pem;    ///< PEM file configuration
      xrsr_cert_x509_t x509;   ///< X.509 object configuration
   } cert;
} xrsr_cert_t;
```

## TLS/SSL Security Configuration

### Connection Security Features
```c
// XRSR HTTP session security configuration
typedef struct {
   // ... authentication fields
   bool host_verify;           ///< Verify hostname matches certificate
   bool ocsp_verify_stapling;  ///< OCSP stapling verification
   bool ocsp_verify_ca;        ///< OCSP CA verification
   // ... other fields
} xrsr_session_config_in_http_t;
```

### SSL/TLS Implementation (XRSR)
```c
// Certificate verification configuration
// CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSL_VERIFYHOST, 2L);  // Hostname verification
// CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSL_VERIFYPEER, 1L);  // Peer certificate verification

// OCSP stapling verification
if(config_in->ocsp_verify_stapling) {
    CURL_EASY_SETOPT(http->easy_handle, CURLOPT_SSL_VERIFYSTATUS, 1L);
}
```

### Security Features
- **Host Verification**: Ensures certificate hostname match
- **Peer Verification**: Validates server certificate chain
- **OCSP Stapling**: Real-time certificate revocation checking
- **Certificate Status Validation**: TLS extension-based certificate validation

## XRSV Authentication Integration Patterns

### HTTP Voice Service Authentication

#### Session Configuration (XRSV HTTP)
```c
// XRSV HTTP does not handle session configuration
bool xrsv_http_handlers(xrsv_http_object_t object, 
                       const xrsv_http_handlers_t *handlers_in, 
                       xrsr_handlers_t *handlers_out) {
    // ... handler setup
    handlers_out->session_config = NULL;  // No session config handling
    // ... other handlers
}
```

**Authentication Flow**:
1. **Application Configuration**: Application provides authentication parameters to XRSR
2. **XRSR Authentication**: XRSR establishes authenticated HTTP connection
3. **XRSV Integration**: XRSV HTTP service utilizes authenticated connection
4. **Transparent Security**: Voice service operates over secure, authenticated connection

### WebSocket NextGen Voice Service Authentication

#### Session Configuration Handler (XRSV WebSocket NextGen)
```c
void xrsv_ws_nextgen_handler_ws_session_config(void *data, 
                                              const uuid_t uuid, 
                                              xrsr_session_config_in_t *config_in) {
    xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
    
    if(config_in == NULL || config_in->ws.app_config == NULL) {
        XLOGD_ERROR("invalid stream params <%p>", config_in);
        return;
    }
    
    // Extract stream parameters from authenticated session
    xrsv_ws_nextgen_stream_params_t *stream_params = 
        (xrsv_ws_nextgen_stream_params_t *)config_in->ws.app_config;
    
    // Update voice service configuration based on authenticated session
    // ... configuration processing
}
```

#### Connection Handler with Authentication Context
```c
bool xrsv_ws_nextgen_handler_ws_connected(void *data, 
                                        const uuid_t uuid, 
                                        xrsr_handler_send_t send, 
                                        void *param, 
                                        rdkx_timestamp_t *timestamp, 
                                        xrsr_session_config_update_t *session_config_update) {
    xrsv_ws_nextgen_obj_t *obj = (xrsv_ws_nextgen_obj_t *)data;
    
    // Store authenticated connection parameters
    obj->send = send;  // Authenticated send function
    obj->param = param;  // Connection context with authentication
    obj->session_config_update = session_config_update;
    
    // Generate initialization message over authenticated connection
    uint8_t *buffer = NULL;
    uint32_t length = 0;
    xrsv_ws_nextgen_msg_init(obj, &buffer, &length);
    
    // Send over authenticated WebSocket connection
    xrsr_result_t result = (*send)(param, buffer, length);
    free(buffer);
    
    return (result == XRSR_RESULT_SUCCESS);
}
```

**Authentication Flow**:
1. **XRSR WebSocket Authentication**: XRSR establishes authenticated WebSocket connection
2. **Session Configuration**: XRSV receives authenticated session parameters
3. **Connection Handler**: XRSV receives authenticated send function and connection context
4. **Message Exchange**: Voice service messages exchanged over authenticated connection
5. **Dynamic Configuration**: Session-level authentication updates handled transparently

## Security Integration Patterns

### Authentication Abstraction
XRSV components operate on authenticated connections without direct authentication handling:

```c
// XRSV uses authenticated connection functions provided by XRSR
typedef xrsr_result_t (*xrsr_handler_send_t)(void *param, const uint8_t *buffer, uint32_t length);

// Connection established with authentication by XRSR
bool xrsv_handler_connected(..., xrsr_handler_send_t send, void *param, ...) {
    // 'send' function operates over authenticated connection
    // 'param' contains authentication context
    xrsr_result_t result = (*send)(param, message_buffer, message_length);
    return (result == XRSR_RESULT_SUCCESS);
}
```

### Configuration Propagation
Authentication configuration flows from application through XRSR to XRSV:

```c
// Application -> XRSR authentication configuration
xrsr_session_config_in_http_t http_config = {
    .sat_token = application_auth_token,
    .user_agent = "VoiceService/1.0",
    .client_cert = {
        .type = XRSR_CERT_TYPE_P12,
        .cert.p12 = {
            .filename = "/path/to/client.p12",
            .passphrase = "certificate_password"
        }
    },
    .host_verify = true,
    .ocsp_verify_stapling = true
};

// XRSR -> XRSV session configuration propagation via handlers
void xrsv_session_config_handler(void *data, const uuid_t uuid, 
                                 xrsr_session_config_in_t *config_in) {
    // XRSV receives configuration that includes authentication context
    // Voice service logic operates with authentication guarantees
}
```

## Error Handling and Security Events

### Authentication Error Propagation
```c
// XRSR authentication errors propagate to XRSV handlers
void xrsv_source_error_handler(xrsr_src_t src, void *user_data) {
    // Handle authentication failures reported by XRSR layer
    // Implement fallback mechanisms or user notification
}

void xrsv_disconnected_handler(const uuid_t uuid, bool retry, 
                              rdkx_timestamp_t *timestamp, void *user_data) {
    // Handle authentication-related disconnections
    // 'retry' indicates if reconnection with authentication should be attempted
}
```

### Certificate Validation Errors
```c
// SSL/TLS certificate errors handled by XRSR with logging filter
static const char *http_log_filter_patterns[] = {
    "SSL certificate problem: certificate has expired",
    "SSL certificate status: revoked (1)",
    "SSL certificate status1: revoked (1)",
    // ... other certificate error patterns
};
```

## Security Best Practices 

### Token Management
1. **Secure Storage**: SAT tokens should be stored securely by the application
2. **Token Rotation**: Implement token refresh mechanisms for long-running sessions
3. **Validation**: Server-side token validation ensures session integrity
4. **Scope Limitation**: Use token scopes to limit voice service access

### Certificate Management
1. **Certificate Rotation**: Regular certificate renewal and deployment
2. **Passphrase Security**: Secure passphrase management for encrypted certificates
3. **Chain Validation**: Complete certificate chain verification
4. **Revocation Checking**: OCSP validation for real-time certificate status

### Connection Security
1. **Host Verification**: Always verify hostname matches certificate
2. **Peer Validation**: Validate server certificate chains
3. **Protocol Versions**: Use modern TLS versions (TLS 1.2+)
4. **Cipher Suites**: Configure strong cipher suites in OpenSSL/cURL

## Integration Guidelines

### Application Integration
```c
// Recommended application authentication setup pattern
int setup_voice_service_authentication(void) {
    // 1. Configure XRSR authentication
    xrsr_session_config_in_http_t auth_config = {
        .sat_token = get_application_auth_token(),
        .client_cert = get_application_certificate(),
        .host_verify = true,
        .ocsp_verify_stapling = true,
        .ocsp_verify_ca = false  // Optional CA-based OCSP
    };
    
    // 2. Create XRSV voice service with authentication context
    xrsv_http_object_t voice_service = xrsv_http_create(&voice_params);
    
    // 3. Register handlers for authentication events
    xrsv_http_handlers_t handlers = {
        .source_error = handle_auth_errors,
        .disconnected = handle_auth_disconnections,
        // ... other handlers
    };
    
    xrsv_http_handlers(voice_service, &handlers, &xrsr_handlers);
    
    // 4. Pass authentication configuration to XRSR
    return xrsr_open(&xrsr_handlers, &auth_config);
}
```

### Error Handling Integration
```c
// Comprehensive authentication error handling
void handle_auth_errors(xrsr_src_t src, void *user_data) {
    switch(src) {
        case XRSR_SRC_MICROPHONE:
            // Audio input errors, not authentication-related
            break;
        case XRSR_SRC_HTTP_STREAM:
        case XRSR_SRC_WS_STREAM:
            // Network/authentication errors - implement retry with backoff
            schedule_authentication_retry();
            break;
    }
}

void handle_auth_disconnections(const uuid_t uuid, bool retry, 
                               rdkx_timestamp_t *timestamp, void *user_data) {
    if(retry) {
        // Authentication allows retry - refresh credentials if needed
        refresh_authentication_credentials();
    } else {
        // Authentication failure - user intervention required
        request_user_authentication();
    }
}
```

### Performance Considerations
1. **Certificate Caching**: Cache certificates in memory for repeated connections
2. **Connection Reuse**: Leverage HTTP/2 and WebSocket connection reuse
3. **Token Caching**: Cache valid tokens to avoid unnecessary authentication roundtrips
4. **OCSP Caching**: Cache OCSP responses to reduce certificate validation overhead

## Protocol-Specific Authentication Features

### HTTP Authentication
- **Bearer Token Integration**: Transparent SAT token injection into Authorization headers
- **Certificate Support**: Full PKCS#12, PEM, and X.509 certificate support
- **OCSP Validation**: Configurable certificate revocation checking
- **Connection Reuse**: Authentication context maintained across HTTP requests

### WebSocket Authentication
- **Session Configuration**: Authentication parameters passed through session configuration
- **Connection Context**: Authenticated connection context maintained throughout session
- **Dynamic Updates**: Session-level authentication parameter updates
- **Message Security**: All voice service messages exchanged over authenticated WebSocket

## Future Authentication Enhancements

### Planned Features
- **OAuth2 Integration**: Direct OAuth2 flow support for token acquisition
- **Hardware Security Modules**: HSM integration for certificate management
- **Multi-Factor Authentication**: MFA support for enhanced security
- **Certificate Pinning**: Public key pinning for additional security

### Extensibility
- **Custom Authentication**: Plugin architecture for custom authentication methods
- **Identity Providers**: Integration with enterprise identity management systems
- **Token Refresh**: Automatic token refresh mechanisms
- **Security Monitoring**: Authentication event logging and monitoring integration

The XRSV authentication integration provides a robust, secure foundation for voice service authentication while maintaining clean separation of concerns between protocol-level security and voice service business logic. This architecture ensures that voice services operate over authenticated, encrypted connections while abstracting the complexity of authentication management from the voice service implementation.