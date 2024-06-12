#!/bin/bash

# Deploy Ingress-nginx
kubectl apply -f ../kube/ingress-nginx.yaml

# Wait until setup and running
echo "Waiting for pods to be ready"
kubectl wait --namespace ingress-nginx --for=condition=ready pod \
             --selector=app.kubernetes.io/component=controller --timeout=4m

