# Architecture — Full-Stack Intelligence
## Janapareddy Dyns Gowrish

My module scans API Gateway and CloudWatch. I drew these diagrams to explain what happens when the scan runs.

---

## Module flow

```mermaid
flowchart TD
    APIGW[POST /scan-fullstack] --> L

    subgraph Lambda: fullstack-analyzer
        L[lambda_handler] --> GetAPIs[get all REST APIs\napigateway.get_rest_apis]
        GetAPIs --> AuthCheck[check auth type\nper method per resource]
        GetAPIs --> ThrottleCheck[check throttling\nper stage]
        L --> ErrorRate[CloudWatch — 5XX errors\nlast 1 hour]
        L --> Latency[CloudWatch — API Latency\nlast 1 hour]

        AuthCheck --> Risk[build_risk]
        ThrottleCheck --> Risk
        ErrorRate --> Risk
        Latency --> Risk
        Risk --> Save[save to DynamoDB]
    end

    Save --> DDB[(DynamoDB)]

    style DDB fill:#4053D6,color:#fff
```

---

## How I check authentication

```mermaid
sequenceDiagram
    participant L as fullstack-analyzer
    participant AG as API Gateway SDK
    participant D as DynamoDB

    L->>AG: get_rest_apis()
    AG-->>L: list of APIs

    loop each API
        L->>AG: get_resources(restApiId)
        AG-->>L: resources

        loop each resource + each HTTP method
            L->>AG: get_method(restApiId, resourceId, httpMethod)
            AG-->>L: { authorizationType, apiKeyRequired }

            alt authorizationType == NONE and apiKeyRequired == false
                L->>D: PutItem — Unauthenticated Endpoint (High)
            end
        end
    end
```

That's the key check. If someone deploys an API with no Cognito, no IAM, no API key — it gets flagged.

---

## CloudWatch metrics I use

```mermaid
flowchart LR
    CW[CloudWatch] --> A[Namespace: AWS/ApiGateway\nMetric: 5XXError\nStatistic: Sum\nPeriod: 3600s]
    CW --> B[Namespace: AWS/ApiGateway\nMetric: Latency\nStatistic: Average\nPeriod: 3600s]

    A -->|sum > 10| R1[High: High 5XX Error Rate]
    B -->|avg > 2000ms| R2[Medium: High API Latency]
```

In a fresh account these return no data so the checks just don't trigger anything. Once APIs are deployed and getting traffic, this becomes useful.

---

## Priority logic

```mermaid
flowchart TD
    M([API Method]) --> B{authorizationType?}
    B -->|NONE + no API key| HIGH[High — Unauthenticated Endpoint]
    B -->|COGNITO_USER_POOLS| OK1([Secure])
    B -->|AWS_IAM| OK2([Secure])
    B -->|CUSTOM| OK3([Secure])

    S([API Stage]) --> C{throttlingBurstLimit?}
    C -->|not set| MED[Medium — No Rate Limiting]
    C -->|set| OK4([Fine])
```
