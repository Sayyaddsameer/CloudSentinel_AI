# Architecture — Mobile Backend Intelligence
## Muramalla Ambica Sai Ram

Notes on how my module is structured. Key difference from Gowrish's module: I use 1000ms as the latency threshold instead of 2000ms, and I also check CORS and Lambda error rates — both are critical for mobile backends.

---

## Module flow

```mermaid
flowchart TD
    APIGW[POST /scan-mobile] --> L

    subgraph Lambda: mobile-analyzer
        L[lambda_handler] --> Lat[scan_api_latency\np95 > 1000ms]
        L --> Err[scan_error_rates\n5XX > 10, 4XX > 50]
        L --> CORS[scan_cors_config\ncheck OPTIONS method per resource]
        L --> LambdaErr[scan_lambda_errors\nErrors metric per function]

        Lat --> Build[build_risk]
        Err --> Build
        CORS --> Build
        LambdaErr --> Build
        Build --> Save[save to DynamoDB]
    end

    L -->|calls| CW[CloudWatch]
    L -->|calls| AG[API Gateway SDK]
    L -->|calls| LF[Lambda SDK]

    style APIGW fill:#8C4FFF,color:#fff
    style CW fill:#FF9900,color:#000
```

---

## Mobile vs Web latency — why the different threshold

I talked to Gowrish about this early on. He uses 2000ms for web APIs. I use 1000ms. The reason:

```mermaid
flowchart LR
    subgraph Mobile context - my module
        M[Latency\n> 1000ms] --> MR[High risk]
    end
    subgraph Web context - Gowrish's module
        W[Latency\n> 2000ms] --> WR[Medium risk]
    end

    Note([Mobile users on 4G/5G\nexpect < 1 second API response.\nWeb users tolerate up to 2s.])
```

---

## CORS check

```mermaid
sequenceDiagram
    participant L as mobile-analyzer
    participant AG as API Gateway SDK
    participant D as DynamoDB

    L->>AG: get_rest_apis()
    AG-->>L: list of APIs

    loop each API
        L->>AG: get_resources(restApiId)
        AG-->>L: resources

        loop each resource
            L->>L: check resourceMethods.keys()
            alt OPTIONS not in methods
                L->>D: PutItem — Missing CORS (Medium)
            end
        end
    end
```

This is specifically relevant for Flutter Web and hybrid apps. Native Flutter doesn't trigger browser CORS checks, but Flutter Web does.

---

## Lambda error detection

```mermaid
sequenceDiagram
    participant L as mobile-analyzer
    participant LF as Lambda SDK
    participant CW as CloudWatch
    participant D as DynamoDB

    L->>LF: list_functions()
    LF-->>L: all Lambda functions

    loop each function
        L->>CW: get_metric_statistics\nMetric: Errors\nPeriod 3600s
        CW-->>L: error count

        alt count > 5
            L->>D: PutItem — High Lambda Error Rate (High)
        end
    end
```
