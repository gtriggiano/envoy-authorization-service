# Kubernetes Deployment

This guide shows the minimum viable Kubernetes manifests to deploy the Envoy Authorization Service with MaxMind GeoIP and ASN analysis capabilities.

## Manifests

Create a single `envoy-authorization-service.yaml` file with the following manifests:

### ConfigMap

Create a ConfigMap for service configuration:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: envoy-authorization-config
data:
  config.yaml: |
    server:
      address: ":9001"
    
    analysisControllers:
      - name: geoip
        type: maxmind-geoip
        settings:
          databasePath: /maxmind/GeoLite2-City.mmdb
      
      - name: asn
        type: maxmind-asn
        settings:
          databasePath: /maxmind/GeoLite2-ASN.mmdb
```

### Deployment

Create a Deployment with an **init container** to download MaxMind databases:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: envoy-authorization-service
spec:
  replicas: 1
  selector:
    matchLabels:
      app: envoy-authorization-service
  template:
    metadata:
      labels:
        app: envoy-authorization-service
    spec:
      initContainers:
        - name: maxmind-db-downloader
          image: curlimages/curl:latest
          command:
            - sh
            - -c
            - |
              curl -L -o /maxmind/GeoLite2-ASN.mmdb https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb
              curl -L -o /maxmind/GeoLite2-City.mmdb https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb
          volumeMounts:
            - name: maxmind-dbs
              mountPath: /maxmind
      containers:
        - name: envoy-authorization-service
          image: gtriggiano/envoy-authorization-service:{{VERSION}}
          args:
            - start
            - --config=/config/config.yaml
          ports:
            - name: grpc
              containerPort: 9001
            - name: metrics
              containerPort: 9090
          volumeMounts:
            - name: config
              mountPath: /config
            - name: maxmind-dbs
              mountPath: /maxmind
          livenessProbe:
            httpGet:
              path: /healthz
              port: 9090
            initialDelaySeconds: 10
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /readyz
              port: 9090
            initialDelaySeconds: 5
            periodSeconds: 5
            timeoutSeconds: 3
            failureThreshold: 2
          resources:
            requests:
              cpu: 50m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 1Gi
      volumes:
        - name: config
          configMap:
            name: envoy-authorization-config
        - name: maxmind-dbs
          emptyDir: {}
```

### Service

Expose the service within the cluster:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: envoy-authorization-service
spec:
  selector:
    app: envoy-authorization-service
  ports:
    - name: grpc
      port: 9001
      targetPort: 9001
    - name: metrics
      port: 9090
      targetPort: 9090
```

## Apply

```bash
kubectl apply -f envoy-authorization-service.yaml
```

Verify the deployment:

```bash
kubectl get pods -l app=envoy-authorization-service
kubectl logs -l app=envoy-authorization-service
```

## How It Works

1. **Init Container**: Downloads MaxMind GeoLite2 databases (ASN and City) before the main container starts
2. **Shared Volume**: An `emptyDir` volume shares the downloaded databases between init and main containers
3. **Analysis Controllers**: The service analyzes requests and adds GeoIP and ASN metadata to request headers
4. **No Authorization**: This configuration performs analysis only without enforcing any authorization policies

## Next Steps

- [Configure Match Controllers](/match-controllers/)
- [Write Policy Expressions](/policy-dsl)
- [Configuration Guide](/configuration)
- [View Configuration Examples](/examples/)
